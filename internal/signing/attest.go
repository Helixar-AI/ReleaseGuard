package signing

// AttestationBundle holds paths to generated attestation files.
type AttestationBundle struct {
	InTotoPath string
	SLSAPath   string
}

// Attester emits in-toto and SLSA provenance attestations.
type Attester struct{}

// NewAttester returns an Attester.
func NewAttester() *Attester {
	return &Attester{}
}

// Attest generates attestation statements for the artifact at artifactPath.
func (a *Attester) Attest(artifactPath string) (*AttestationBundle, error) {
	// TODO: Phase 14 — implement in-toto statement generation
	// TODO: Phase 14 — emit SLSA Provenance level 2
	return &AttestationBundle{
		InTotoPath: ".releaseguard/attestation/artifact.intoto.json",
		SLSAPath:   ".releaseguard/attestation/provenance.slsa.json",
	}, nil
}
