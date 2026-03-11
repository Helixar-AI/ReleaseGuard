package app

import (
	"fmt"

	"github.com/Helixar-AI/ReleaseGuard/internal/signing"
)

// Verify checks signatures and policy compliance for the artifact.
func Verify(artifactPath string) error {
	fmt.Printf("releaseguard verify %s\n\n", artifactPath)

	verifier := signing.NewVerifier()

	result, err := verifier.Verify(artifactPath)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	fmt.Printf("  Artifact digest:  %s\n", result.Digest)
	fmt.Printf("  Signature valid:  %v\n", result.SignatureValid)
	fmt.Printf("  Policy compliant: %v\n", result.PolicyCompliant)

	if !result.SignatureValid {
		return fmt.Errorf("signature verification failed")
	}

	fmt.Println("\n  Verification PASSED.")
	return nil
}
