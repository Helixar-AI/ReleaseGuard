package signing

import (
	"fmt"

	"github.com/Helixar-AI/ReleaseGuard/internal/collect"
)

// Signature holds the result of a signing operation.
type Signature struct {
	Digest  string
	Path    string // path to .sig file written
	CertURL string // Fulcio certificate URL (keyless only)
}

// Signer signs files and evidence bundles.
type Signer interface {
	SignFile(path string) (*Signature, error)
}

// NewSigner returns the appropriate Signer for the given mode.
func NewSigner(mode, keyFile string) (Signer, error) {
	switch mode {
	case "keyless":
		return &KeylessSigner{}, nil
	case "local":
		if keyFile == "" {
			return nil, fmt.Errorf("local signing mode requires --key flag")
		}
		return &LocalSigner{KeyFile: keyFile}, nil
	default:
		return nil, fmt.Errorf("unknown signing mode %q (supported: keyless, local)", mode)
	}
}

// KeylessSigner uses Sigstore / Fulcio for OIDC-based keyless signing.
type KeylessSigner struct{}

func (s *KeylessSigner) SignFile(path string) (*Signature, error) {
	digest, err := collect.SHA256File(path)
	if err != nil {
		return nil, fmt.Errorf("hashing artifact: %w", err)
	}
	// TODO: Phase 13 — integrate github.com/sigstore/cosign
	sigPath := path + ".sig"
	return &Signature{
		Digest:  digest,
		Path:    sigPath,
		CertURL: "https://fulcio.sigstore.dev (planned Phase 13)",
	}, nil
}

// LocalSigner signs using a local private key file (GPG or ECDSA).
type LocalSigner struct {
	KeyFile string
}

func (s *LocalSigner) SignFile(path string) (*Signature, error) {
	digest, err := collect.SHA256File(path)
	if err != nil {
		return nil, fmt.Errorf("hashing artifact: %w", err)
	}
	// TODO: Phase 13 — implement GPG/ECDSA local signing
	sigPath := path + ".sig"
	return &Signature{
		Digest: digest,
		Path:   sigPath,
	}, nil
}
