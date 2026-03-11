package policy

// RegoAdapter provides Open Policy Agent (Rego) integration.
// Full OPA evaluation is planned for Phase 4. This file holds the interface
// and stub so the package compiles cleanly.

// RegoEvaluator evaluates a Rego policy bundle against artifact state.
type RegoEvaluator struct {
	BundlePath string
}

// NewRegoEvaluator returns a RegoEvaluator pointing at bundlePath.
func NewRegoEvaluator(bundlePath string) *RegoEvaluator {
	return &RegoEvaluator{BundlePath: bundlePath}
}

// Evaluate runs the Rego bundle — not yet implemented.
func (r *RegoEvaluator) Evaluate() error {
	// TODO: integrate github.com/open-policy-agent/opa in Phase 4
	return nil
}
