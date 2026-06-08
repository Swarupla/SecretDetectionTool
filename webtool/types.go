package main

import (
	"time"

	"github.com/checkmarx/2ms/v5/lib/secrets"
)

// Confidence levels assigned by the Layer 2 precision engine.
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
)

// Job status values for an async scan.
const (
	StatusQueued  = "queued"
	StatusRunning = "running"
	StatusDone    = "done"
	StatusError   = "error"
)

// ScanOptions captures user-tunable knobs for a single scan request.
type ScanOptions struct {
	// Inputs (exactly one is used, in priority order: Path, GitURL, uploaded zip).
	Path   string `json:"path,omitempty"`
	GitURL string `json:"gitUrl,omitempty"`

	// Precision toggles.
	ApplyExcludes    bool    `json:"applyExcludes"`    // Layer 1 default excludes
	ApplyFilters     bool    `json:"applyFilters"`     // Layer 2 confidence gates
	ApplyFeedback    bool    `json:"applyFeedback"`    // Layer 3 learned allowlist
	AggressiveRecall bool    `json:"aggressiveRecall"` // extra custom rules for weak/keyword secrets
	WithValidation   bool    `json:"withValidation"`   // live secret validation (needs network)
	MinEntropy       float64 `json:"minEntropy"`       // entropy floor for LOW-confidence rules
}

// Finding is a single scored result returned to the UI.
type Finding struct {
	ID           string  `json:"id"`
	Source       string  `json:"source"`
	RuleID       string  `json:"ruleId"`
	RuleName     string  `json:"ruleName"`
	RuleCategory string  `json:"ruleCategory"`
	StartLine    int     `json:"startLine"`
	EndLine      int     `json:"endLine"`
	StartColumn  int     `json:"startColumn"`
	EndColumn    int     `json:"endColumn"`
	LineContent  string  `json:"lineContent"`
	Value        string  `json:"value"`    // masked for display
	RawValue     string  `json:"rawValue"` // unmasked actual value
	Severity     string  `json:"severity"`
	CvssScore    float64 `json:"cvssScore,omitempty"`
	Validation   string  `json:"validationStatus,omitempty"`

	// Precision-pipeline outputs.
	Confidence   string `json:"confidence"`
	FilterReason string `json:"filterReason,omitempty"`
	Suppressed   bool   `json:"suppressed"`        // dropped by Layer 2/3
	Learned      bool   `json:"learned,omitempty"` // suppressed by learned allowlist
}

// ScanResult is the full outcome of a scan, surfaced to the UI.
type ScanResult struct {
	TotalItemsScanned int            `json:"totalItemsScanned"`
	FilesIngested     int            `json:"filesIngested"`
	FilesExcluded     int            `json:"filesExcluded"`
	RawFindings       int            `json:"rawFindings"`
	Suppressed        int            `json:"suppressed"`
	Surfaced          int            `json:"surfaced"`
	ByConfidence      map[string]int `json:"byConfidence"`
	Findings          []*Finding     `json:"findings"`
}

// Job tracks an async scan.
type Job struct {
	ID         string      `json:"id"`
	Status     string      `json:"status"`
	Progress   int         `json:"progress"`
	Message    string      `json:"message"`
	SourceDesc string      `json:"source"`
	Error      string      `json:"error,omitempty"`
	StartedAt  time.Time   `json:"startedAt"`
	FinishedAt time.Time   `json:"finishedAt,omitempty"`
	Result     *ScanResult `json:"result,omitempty"`
}

// toFinding converts an engine secret into a UI finding (pre-scoring).
func toFinding(s *secrets.Secret) *Finding {
	return &Finding{
		ID:           s.ID,
		Source:       s.Source,
		RuleID:       s.RuleID,
		RuleName:     s.RuleName,
		RuleCategory: s.RuleCategory,
		// Engine reports 0-based lines for the custom plugin; present 1-based.
		StartLine:   s.StartLine + 1,
		EndLine:     s.EndLine + 1,
		StartColumn: s.StartColumn,
		EndColumn:   s.EndColumn,
		LineContent: s.LineContent,
		RawValue:    s.Value,
		Value:       maskSecret(s.Value),
		Severity:    s.Severity,
		CvssScore:   s.CvssScore,
		Validation:  string(s.ValidationStatus),
	}
}

// maskSecret partially hides a secret value for safe display in the UI.
func maskSecret(v string) string {
	r := []rune(v)
	n := len(r)
	if n <= 8 {
		if n <= 2 {
			return "****"
		}
		return string(r[:1]) + "****" + string(r[n-1:])
	}
	return string(r[:4]) + "…" + string(r[n-4:])
}
