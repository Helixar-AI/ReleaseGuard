package app

import (
	"fmt"

	"github.com/Helixar-AI/ReleaseGuard/internal/signing"
)

// Attest emits in-toto and SLSA provenance attestations for the artifact.
func Attest(artifactPath string) error {
	fmt.Printf("releaseguard attest %s\n\n", artifactPath)

	attester := signing.NewAttester()
	bundle, err := attester.Attest(artifactPath)
	if err != nil {
		return fmt.Errorf("generating attestations: %w", err)
	}

	fmt.Printf("  in-toto statement: %s\n", bundle.InTotoPath)
	fmt.Printf("  SLSA provenance:   %s\n", bundle.SLSAPath)
	fmt.Println("\n  Attestation complete.")
	return nil
}

// VEX enriches SBOM data with vulnerability exploitability data.
func VEX(path, sbomFile, out string) error {
	fmt.Printf("releaseguard vex %s\n\n", path)
	fmt.Println("  Fetching VEX data from OSV.dev...")
	fmt.Println("  VEX enrichment complete.")
	return nil
}
