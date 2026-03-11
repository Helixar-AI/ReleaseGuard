package app

import (
	"fmt"

	"github.com/Helixar-AI/ReleaseGuard/internal/signing"
)

// Sign signs the artifact and any associated evidence bundle.
func Sign(artifactPath, mode, keyFile string) error {
	fmt.Printf("releaseguard sign %s [mode=%s]\n\n", artifactPath, mode)

	signer, err := signing.NewSigner(mode, keyFile)
	if err != nil {
		return fmt.Errorf("initializing signer: %w", err)
	}

	sig, err := signer.SignFile(artifactPath)
	if err != nil {
		return fmt.Errorf("signing artifact: %w", err)
	}

	fmt.Printf("  Artifact signed\n")
	fmt.Printf("  Signature:  %s\n", sig.Path)
	fmt.Printf("  Digest:     %s\n", sig.Digest)
	if sig.CertURL != "" {
		fmt.Printf("  Certificate: %s\n", sig.CertURL)
	}

	return nil
}
