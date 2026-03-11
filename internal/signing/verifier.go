package signing

import (
	"github.com/Helixar-AI/ReleaseGuard/internal/collect"
)

// VerifyResult holds the outcome of a verification run.
type VerifyResult struct {
	Digest          string
	SignatureValid  bool
	PolicyCompliant bool
}

// Verifier checks artifact signatures and policy compliance.
type Verifier struct{}

// NewVerifier returns a Verifier.
func NewVerifier() *Verifier {
	return &Verifier{}
}

// Verify checks the signature and policy compliance for artifactPath.
func (v *Verifier) Verify(artifactPath string) (*VerifyResult, error) {
	digest, err := collect.SHA256File(artifactPath)
	if err != nil {
		return nil, err
	}
	// TODO: Phase 13 — verify .sig file against artifact digest
	return &VerifyResult{
		Digest:          digest,
		SignatureValid:  true,  // stub until signing implemented
		PolicyCompliant: true,
	}, nil
}
