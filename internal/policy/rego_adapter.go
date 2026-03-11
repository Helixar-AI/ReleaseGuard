package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/Helixar-AI/ReleaseGuard/internal/model"
)

// EvalInput is the structured input marshaled to JSON and passed to the Rego policy.
type EvalInput struct {
	Findings []model.Finding   `json:"findings"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// EvalResult holds the structured outcome from Rego evaluation.
type EvalResult struct {
	Allow bool     `json:"allow"`
	Deny  []string `json:"deny,omitempty"`
	Warn  []string `json:"warn,omitempty"`
}

// RegoEvaluator evaluates a Rego policy bundle against artifact findings.
type RegoEvaluator struct {
	BundlePath string
}

// NewRegoEvaluator returns a RegoEvaluator pointing at bundlePath.
func NewRegoEvaluator(bundlePath string) *RegoEvaluator {
	return &RegoEvaluator{BundlePath: bundlePath}
}

// Evaluate runs the Rego policy at BundlePath against the provided findings.
// If the `opa` binary is not in PATH it logs a warning and returns a passing result.
// The policy must define `data.releaseguard.deny` (set of strings) and optionally
// `data.releaseguard.warn`.
func (r *RegoEvaluator) Evaluate(input EvalInput) (*EvalResult, error) {
	opaPath, err := exec.LookPath("opa")
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [rego] opa binary not found in PATH — skipping Rego evaluation\n")
		return &EvalResult{Allow: true}, nil
	}

	inputData, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("rego: marshaling input: %w", err)
	}
	tmpFile, err := os.CreateTemp("", "rg-rego-input-*.json")
	if err != nil {
		return nil, fmt.Errorf("rego: creating temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.Write(inputData); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("rego: writing input: %w", err)
	}
	tmpFile.Close()

	result := &EvalResult{Allow: true}

	deny, err := r.evalQuery(opaPath, tmpFile.Name(), "data.releaseguard.deny")
	if err != nil {
		return nil, err
	}
	result.Deny = deny
	if len(deny) > 0 {
		result.Allow = false
	}

	// Best-effort warn query — ignore errors
	warn, _ := r.evalQuery(opaPath, tmpFile.Name(), "data.releaseguard.warn")
	result.Warn = warn

	return result, nil
}

// evalQuery runs opa eval and returns the resulting array of string messages.
func (r *RegoEvaluator) evalQuery(opaPath, inputFile, query string) ([]string, error) {
	args := []string{
		"eval",
		"--input", inputFile,
		"--data", r.BundlePath,
		"--format", "raw",
		query,
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.Command(opaPath, args...) //nolint:gosec
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// opa eval exits 1 for undefined results — treat as empty
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil, nil
		}
		return nil, fmt.Errorf("rego: opa eval %s: %w (stderr: %s)", query, err, stderr.String())
	}

	output := bytes.TrimSpace(stdout.Bytes())
	if len(output) == 0 || string(output) == "undefined" {
		return nil, nil
	}

	var raw any
	if err := json.Unmarshal(output, &raw); err != nil {
		return []string{string(output)}, nil
	}

	switch v := raw.(type) {
	case []any:
		var msgs []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				msgs = append(msgs, s)
			}
		}
		return msgs, nil
	case string:
		return []string{v}, nil
	case bool:
		if !v {
			return []string{"policy returned false"}, nil
		}
		return nil, nil
	default:
		return nil, nil
	}
}
