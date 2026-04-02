package scan

import (
	"fmt"

	"github.com/Helixar-AI/ReleaseGuard/internal/config"
	"github.com/Helixar-AI/ReleaseGuard/internal/model"
)

// SymlinksScanner detects symbolic links present in release artifacts.
// Symlinks in a distribution bundle are almost always unintentional and carry
// real risk: they may point outside the artifact root (enabling path traversal
// when the archive is unpacked) and are not portable across all filesystems.
type SymlinksScanner struct{}

func (s *SymlinksScanner) Name() string { return "symlinks" }

func (s *SymlinksScanner) Scan(root string, artifacts []model.Artifact, cfg *config.Config) ([]model.Finding, error) {
	symCfg := cfg.Scanning.Symlinks

	// Build a set of explicitly allowed symlink paths for O(1) lookup.
	allowed := make(map[string]struct{}, len(symCfg.Allow))
	for _, p := range symCfg.Allow {
		allowed[p] = struct{}{}
	}

	var findings []model.Finding

	for _, a := range artifacts {
		if a.Kind != "symlink" {
			continue
		}
		if _, ok := allowed[a.Path]; ok {
			continue
		}

		findings = append(findings, model.Finding{
			ID:             "RG-SYM-001",
			Category:       model.CategorySymlink,
			Severity:       model.SeverityMedium,
			Path:           a.Path,
			Message:        fmt.Sprintf("Symbolic link found in release artifact: %s", a.Path),
			Evidence:       "Symlinks can point outside the artifact root and cause path traversal issues when unpacked.",
			Autofixable:    false,
			RecommendedFix: "Replace the symlink with a regular file copy, or add the path to the symlinks.allow list if intentional.",
		})
	}

	return findings, nil
}
