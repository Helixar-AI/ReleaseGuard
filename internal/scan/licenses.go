package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Helixar-AI/ReleaseGuard/internal/config"
	"github.com/Helixar-AI/ReleaseGuard/internal/model"
)

// LicenseScanner checks that required license and notice files are present.
type LicenseScanner struct{}

func (s *LicenseScanner) Name() string { return "licenses" }

func (s *LicenseScanner) Scan(root string, artifacts []model.Artifact, cfg *config.Config) ([]model.Finding, error) {
	var findings []model.Finding
	required := cfg.Scanning.Licenses.Require

	// Build a set of present filenames for fast lookup.
	present := make(map[string]bool)
	for _, a := range artifacts {
		present[strings.ToUpper(filepath.Base(a.Path))] = true
	}

	for _, req := range required {
		if !present[strings.ToUpper(req)] {
			// Also check if file exists directly in root (not under a subdir)
			if _, err := os.Stat(filepath.Join(root, req)); os.IsNotExist(err) {
				findings = append(findings, model.Finding{
					ID:             "RG-LIC-001",
					Category:       model.CategoryLicense,
					Severity:       model.SeverityMedium,
					Path:           req,
					Message:        fmt.Sprintf("Required file %q is missing from the artifact", req),
					Autofixable:    false,
					RecommendedFix: fmt.Sprintf("Add a %s file to your project root and ensure it is included in the release.", req),
				})
			}
		}
	}

	return findings, nil
}
