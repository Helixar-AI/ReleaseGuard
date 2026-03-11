package scan

import (
	"fmt"
	"path/filepath"

	"github.com/Helixar-AI/ReleaseGuard/internal/config"
	"github.com/Helixar-AI/ReleaseGuard/internal/model"
)

// UnexpectedScanner detects files that should not be present in a release artifact.
type UnexpectedScanner struct{}

func (s *UnexpectedScanner) Name() string { return "unexpected" }

func (s *UnexpectedScanner) Scan(root string, artifacts []model.Artifact, cfg *config.Config) ([]model.Finding, error) {
	var findings []model.Finding
	denyPatterns := cfg.Scanning.UnexpectedFiles.Deny

	for _, a := range artifacts {
		for _, pattern := range denyPatterns {
			matched, err := filepath.Match(pattern, a.Path)
			if err != nil {
				continue
			}
			if !matched {
				// Also try matching against just the base filename
				matched, _ = filepath.Match(pattern, filepath.Base(a.Path))
			}
			if matched {
				findings = append(findings, model.Finding{
					ID:             "RG-UNEXP-001",
					Category:       model.CategoryUnexpected,
					Severity:       model.SeverityMedium,
					Path:           a.Path,
					Message:        fmt.Sprintf("Unexpected file matches deny pattern %q", pattern),
					Autofixable:    true,
					RecommendedFix: fmt.Sprintf("Add %q to your build exclusion list or enable delete_forbidden_files transform.", a.Path),
				})
				break // one finding per file
			}
		}
	}

	return findings, nil
}
