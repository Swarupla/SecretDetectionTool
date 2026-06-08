package main

import "github.com/checkmarx/2ms/v5/engine/rules/ruledefine"

// Aggressive-recall custom rules. These broaden detection to catch two classes
// of secret that the default 2ms rules miss:
//
//  1. Credentials assigned to keyword-bearing variables (e.g. `pg_pass`,
//     `api_token`) where the variable name lacks the exact `password`/`passwd`
//     trigger word.
//  2. Standalone AWS secret access keys (40-char base64) that have no AKIA
//     prefix to anchor on.
//
// Crucially, both rules require an actual quoted value to be present after the
// assignment -- the variable name alone never produces a match -- and both are
// classified as LOW confidence (see lowConfidenceRules) so the Layer 2 gates
// (entropy, placeholder, code-identifier, etc.) still decide whether the value
// is a believable secret before it surfaces.

// Rule names (must match the lowConfidenceRules entries, lowercased).
const (
	ruleKeywordAssignment = "Keyword-Assignment-Secret"
	ruleAWSSecretKey      = "Aws-Secret-Access-Key"
	ruleUnquotedSecret    = "Unquoted-Keyword-Secret"
)

// credential keywords that may appear inside a variable/identifier name.
const credKeywords = "(?:passwd|password|pass|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|credential|auth[_-]?token)"

// Regex notes:
//   - capture group 1 is the secret value (SecretGroup = 1)
//   - the value must be quoted (', ", or `) and at least 6 non-space chars,
//     guaranteeing a real literal value exists after the keyword variable.
const (
	// Two shapes share a single capture group (group 1 = the value):
	//   1. "#define NAME "value""  (C/C++ macro, space-separated)
	//   2. "name = "value"" / "name: "value""  (assignment in most languages)
	// where NAME/name contains a credential keyword.
	keywordAssignmentRegex = "(?i)(?:" +
		"#\\s*define\\s+[a-z0-9_.\\-]*" + credKeywords + "[a-z0-9_.\\-]*\\s+" +
		"|[a-z0-9_.\\-]*" + credKeywords + "[a-z0-9_.\\-]*\\s*[:=]\\s*" +
		")[\"'`]([^\"'`\\s]{6,150})[\"'`]"

	// a quoted, exactly-40-char base64 string (AWS secret access key shape).
	awsSecretKeyRegex = "[\"'`]([A-Za-z0-9/+]{40})[\"'`]"

	// Unquoted secret assigned with "keyword=value" and NO spaces around "=" —
	// the form used by .env files, .properties files and connection strings
	// (e.g. "DATABASE_PASSWORD=...", "API_SECRET=...", "...;Password=...;").
	// Code assignments use spaces ("password = x"), so requiring no-space "="
	// avoids matching expressions like "password = getPass()". The value stops
	// at ; " ' ` whitespace & ( ) = so code calls / quoted values are excluded.
	unquotedSecretRegex = "(?i)(?:password|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|credential|auth[_-]?token|secret[_-]?key)=([^;\"'`\\s=()]{8,150})"
)

// aggressiveRecallRules returns the opt-in custom rules.
func aggressiveRecallRules() []*ruledefine.Rule {
	return []*ruledefine.Rule{
		{
			RuleID:        "webtool-keyword-assignment",
			RuleName:      ruleKeywordAssignment,
			Description:   "Credential assigned to a keyword-bearing variable",
			Regex:         keywordAssignmentRegex,
			Keywords:      []string{"pass", "pwd", "secret", "token", "key", "cred", "auth"},
			SecretGroup:   1,
			Severity:      ruledefine.High,
			Tags:          []string{ruledefine.TagPassword},
			Category:      ruledefine.CategoryGeneralOrUnknown,
			ScoreRuleType: 4,
		},
		{
			RuleID:        "webtool-aws-secret-access-key",
			RuleName:      ruleAWSSecretKey,
			Description:   "AWS secret access key (40-char base64)",
			Regex:         awsSecretKeyRegex,
			Keywords:      []string{"aws"},
			SecretGroup:   1,
			Severity:      ruledefine.High,
			Tags:          []string{ruledefine.TagSecretKey},
			Category:      ruledefine.CategoryCloudPlatform,
			ScoreRuleType: 4,
		},
		{
			RuleID:        "webtool-unquoted-keyword-secret",
			RuleName:      ruleUnquotedSecret,
			Description:   "Unquoted secret in .env/.properties/connection string",
			Regex:         unquotedSecretRegex,
			Keywords:      []string{"password", "pwd", "secret", "token", "key", "cred", "auth"},
			SecretGroup:   1,
			Severity:      ruledefine.High,
			Tags:          []string{ruledefine.TagPassword},
			Category:      ruledefine.CategoryGeneralOrUnknown,
			ScoreRuleType: 4,
		},
	}
}
