package model

import "time"

// PolicyOutcome is the overall decision from the policy evaluator.
type PolicyOutcome string

const (
	OutcomePass  PolicyOutcome = "pass"
	OutcomeWarn  PolicyOutcome = "warn"
	OutcomeFail  PolicyOutcome = "fail"
	OutcomeWaive PolicyOutcome = "waived"
)

// GateResult is the result of a single policy rule evaluation.
type GateResult struct {
	Rule      string        `json:"rule"`
	Result    PolicyOutcome `json:"result"`
	Findings  []string      `json:"findings,omitempty"` // finding IDs
	Message   string        `json:"message,omitempty"`
}

// PolicyResult is the full output from the policy evaluator.
type PolicyResult struct {
	Result    PolicyOutcome `json:"result"`
	Gates     []GateResult  `json:"gates"`
	Waived    []string      `json:"waived"`
	Timestamp time.Time     `json:"timestamp"`
}

// ScanResult is the top-level result of a full check run.
type ScanResult struct {
	Version        string        `json:"version"`
	InputPath      string        `json:"input_path"`
	Manifest       *Manifest     `json:"manifest"`
	Findings       []Finding     `json:"findings"`
	Transforms     []Transform   `json:"transforms,omitempty"`
	PolicyResult   *PolicyResult `json:"policy_result"`
	EvidenceDir    string        `json:"evidence_dir"`
	Timestamp      string        `json:"timestamp"`
}
