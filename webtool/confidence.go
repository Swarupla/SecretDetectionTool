package main

import (
	"math"
	"regexp"
	"strings"
)

// Layer 2: confidence engine. Provider-specific rules detect structured tokens
// (AWS, GitHub, Stripe, Slack, ...) and are trusted as HIGH confidence. Broad
// keyword rules (chiefly Generic-Api-Key) are the dominant false-positive source
// and must clear a series of gates; survivors are capped at MEDIUM.

// lowConfidenceRules are rule names (lowercased) treated as broad/noisy. These
// always pass through the Layer 2 value-quality gates before they can surface.
var lowConfidenceRules = map[string]struct{}{
	"generic-api-key":           {},
	"hardcoded-password":        {},
	"hashicorp-field":           {},
	"keyword-assignment-secret": {}, // aggressive-recall custom rule
	"aws-secret-access-key":     {}, // aggressive-recall custom rule
	"unquoted-keyword-secret":   {}, // aggressive-recall custom rule
}

var (
	// dotted or namespaced code identifiers, e.g. "i0.EnvironmentInjector".
	codeIdentifierRe = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+$`)
	// placeholder/example markers — applied to the matched VALUE. Includes the
	// "<...>" angle-bracket form (e.g. "<your-token>") and "xxxxx" runs.
	placeholderRe = regexp.MustCompile(`(?i)(example|sample|dummy|changeme|placeholder|redacted|fake|your[_-]?(?:key|token|secret|api)|xxxxx+|<[^>]+>|insert[_-]?your|test[_-]?(?:key|token|secret))`)
	// placeholder markers safe to scan against a whole LINE. Deliberately omits
	// the "<...>" form, which would match XML/HTML tags on every line and
	// wrongly suppress real secrets (private keys, GPP cpassword, ...).
	placeholderLineRe = regexp.MustCompile(`(?i)(example|sample|dummy|changeme|placeholder|redacted|your[_-]?(?:key|token|secret|api)|insert[_-]?your|test[_-]?(?:key|token|secret))`)
	// comment-line leaders for common languages.
	commentRe = regexp.MustCompile(`^\s*(//|#|--|/\*|\*|<!--|;)`)
	// C/C++ preprocessor directives start with "#" but are NOT comments
	// (e.g. "#define SECRET ..."); they must not be filtered as comments.
	cPreprocessorRe = regexp.MustCompile(`(?i)^\s*#\s*(define|include|ifdef|ifndef|if|elif|else|endif|pragma|undef|error|warning|line|import)\b`)
	// a long unbroken base64 run, signalling an actual key/cert body.
	base64RunRe = regexp.MustCompile(`[A-Za-z0-9+/]{40,}`)
	// semver / docker image version tags, e.g. "1.13.5-no-vault", "v2.0.1-rc1".
	versionTagRe = regexp.MustCompile(`^v?\d+\.\d+(?:\.\d+)?(?:[-.][A-Za-z0-9]+)*$`)
	// canonical UUID/GUID — an identifier, not a secret.
	uuidRe = regexp.MustCompile(`^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$`)
	// template / variable interpolation & format references that resolve at
	// deploy/render time, e.g. "${{ secrets.PASSWORD }}", "${DB_PASS}",
	// "{password}", "{{ .Values.password }}", "prefix_{}", "<%= password %>",
	// "#{password}", "%(password)s", "$DB_PASS". These are references/templates,
	// never the literal secret itself. The brace alternative is a "contains"
	// match so it also covers the "${...}" and "${{...}}" forms.
	templateRefRe = regexp.MustCompile(`\{\{?[^{}]*\}?\}|<%[-=]?[^%]*%>|#\{[^{}]*\}|%\([A-Za-z0-9_]*\)[sd]|^\$[A-Za-z_][A-Za-z0-9_]*$`)
)

// scoreFinding assigns a confidence level and, when a finding fails a gate,
// marks it suppressed with a human-readable reason.
func scoreFinding(f *Finding, minEntropy float64) {
	val := f.RawValue
	low := isLowConfidenceRule(f.RuleName)

	// Placeholders/examples are never real secrets, regardless of rule.
	if placeholderRe.MatchString(val) || placeholderLineRe.MatchString(f.LineContent) {
		suppress(f, "value looks like a placeholder/example")
		return
	}

	// Template/variable references (e.g. "${{ secrets.X }}", "${VAR}", "{{ x }}")
	// are resolved elsewhere and are not the literal secret.
	if templateRefRe.MatchString(val) {
		suppress(f, "value is a template/variable reference, not a literal secret")
		return
	}

	// Private-key/cert rules frequently match the "-----BEGIN ... KEY-----"
	// literal in source code (e.g. string replacement). Require an actual key
	// body (a long base64 run), otherwise it is code referencing the marker.
	if isPrivateKeyRule(f.RuleName) && !hasKeyBody(val) {
		suppress(f, "private-key marker without an actual key body")
		return
	}

	if !low {
		// Trust provider-specific structured detections.
		f.Confidence = ConfidenceHigh
		return
	}

	// --- gates for broad keyword rules ---
	if versionTagRe.MatchString(val) {
		suppress(f, "value looks like a version/image tag")
		return
	}
	if uuidRe.MatchString(val) {
		suppress(f, "value is a UUID/GUID (identifier, not a secret)")
		return
	}
	if codeIdentifierRe.MatchString(val) {
		suppress(f, "value looks like a code identifier")
		return
	}
	if strings.ContainsAny(val, " \t") {
		suppress(f, "value contains whitespace (likely prose, not a secret)")
		return
	}
	if isCommentLine(f.LineContent) {
		suppress(f, "match is inside a comment")
		return
	}
	if onlyWordChars(val) && !hasEncodedRun(val) {
		suppress(f, "value has no digits or symbols (likely an identifier/word)")
		return
	}
	if e := shannonEntropy(val); e < minEntropy {
		suppress(f, "entropy below threshold")
		return
	}

	// Survived all gates: a plausible homemade secret, but capped at MEDIUM.
	f.Confidence = ConfidenceMedium
}

// isCommentLine reports whether a line is a source comment, excluding C/C++
// preprocessor directives (which also start with "#").
func isCommentLine(line string) bool {
	if cPreprocessorRe.MatchString(line) {
		return false
	}
	return commentRe.MatchString(line)
}

func isLowConfidenceRule(ruleName string) bool {
	_, ok := lowConfidenceRules[strings.ToLower(ruleName)]
	return ok
}

// isPrivateKeyRule reports whether a rule detects PEM-style private keys/certs.
func isPrivateKeyRule(ruleName string) bool {
	n := strings.ToLower(ruleName)
	return strings.Contains(n, "private-key") || strings.Contains(n, "private key")
}

// hasKeyBody reports whether the value contains an actual key body (a long
// unbroken base64 run) rather than just the BEGIN/END markers.
func hasKeyBody(val string) bool {
	return base64RunRe.MatchString(val)
}

func suppress(f *Finding, reason string) {
	f.Suppressed = true
	f.Confidence = ConfidenceLow
	f.FilterReason = reason
}

// onlyWordChars reports whether the value is composed solely of letters,
// underscores, dots and hyphens (no digits, no high-entropy symbols).
func onlyWordChars(v string) bool {
	if v == "" {
		return true
	}
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r == '_', r == '.', r == '-':
		default:
			return false
		}
	}
	return true
}

// hasEncodedRun reports whether v contains a run of >= 10 consecutive letters
// with at most one vowel. Such runs are characteristic of base64/encoded or
// random tokens (e.g. "YXNkZmZmZmZm") and never of natural words/identifiers
// (e.g. "defaultPassword"), so they should survive the no-digit word gate.
func hasEncodedRun(v string) bool {
	run, vowels := 0, 0
	isLetter := func(r rune) bool { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') }
	isVowel := func(r rune) bool {
		switch r {
		case 'a', 'e', 'i', 'o', 'u', 'A', 'E', 'I', 'O', 'U':
			return true
		}
		return false
	}
	for _, r := range v {
		if isLetter(r) {
			run++
			if isVowel(r) {
				vowels++
			}
			if run >= 10 && vowels <= 1 {
				return true
			}
		} else {
			run, vowels = 0, 0
		}
	}
	return false
}

// shannonEntropy returns the Shannon entropy (bits/char) of s.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := make(map[rune]float64)
	for _, r := range s {
		counts[r]++
	}
	n := float64(len([]rune(s)))
	var e float64
	for _, c := range counts {
		p := c / n
		e -= p * math.Log2(p)
	}
	return e
}
