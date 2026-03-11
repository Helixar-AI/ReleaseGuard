package model

// Severity levels for findings.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Category identifiers for findings.
const (
	CategorySecret     = "secret"
	CategoryMetadata   = "metadata"
	CategoryUnexpected = "unexpected"
	CategoryPolicy     = "policy"
	CategoryLicense    = "license"
)

// Finding represents a single scanner result.
type Finding struct {
	ID             string `json:"id"`
	Category       string `json:"category"`
	Severity       string `json:"severity"`
	Path           string `json:"path"`
	Line           int    `json:"line,omitempty"`
	Message        string `json:"message"`
	Evidence       string `json:"evidence,omitempty"`
	Autofixable    bool   `json:"autofixable"`
	RecommendedFix string `json:"recommended_fix,omitempty"`
	RuleID         string `json:"rule_id,omitempty"`
}
