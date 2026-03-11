package scan

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Helixar-AI/ReleaseGuard/internal/config"
	"github.com/Helixar-AI/ReleaseGuard/internal/model"
)

var (
	internalURLPattern  = regexp.MustCompile(`(?i)(localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|internal\.|corp\.|\.local)`)
	buildPathPattern    = regexp.MustCompile(`(?i)(/home/[a-zA-Z0-9_]+/|/Users/[a-zA-Z0-9_]+/|C:\\Users\\[a-zA-Z0-9_]+\\|/root/)`)
)

// MetadataScanner detects leaked metadata: source maps, debug symbols, build paths, internal URLs.
type MetadataScanner struct{}

func (s *MetadataScanner) Name() string { return "metadata" }

func (s *MetadataScanner) Scan(root string, artifacts []model.Artifact, cfg *config.Config) ([]model.Finding, error) {
	var findings []model.Finding
	mcfg := cfg.Scanning.Metadata

	for _, a := range artifacts {
		// Source map detection
		if strings.HasSuffix(a.Path, ".map") || strings.HasSuffix(a.Path, ".js.map") || strings.HasSuffix(a.Path, ".css.map") {
			sev := model.SeverityMedium
			if mcfg.FailOnSourceMaps {
				sev = model.SeverityHigh
			}
			findings = append(findings, model.Finding{
				ID:             "RG-META-001",
				Category:       model.CategoryMetadata,
				Severity:       sev,
				Path:           a.Path,
				Message:        "Source map detected in release artifact",
				Autofixable:    true,
				RecommendedFix: "Enable remove_source_maps transform or exclude .map files from build.",
			})
			continue
		}

		// Debug symbol files
		ext := strings.ToLower(filepath.Ext(a.Path))
		if ext == ".pdb" || strings.HasSuffix(a.Path, ".dSYM") {
			findings = append(findings, model.Finding{
				ID:       "RG-META-002",
				Category: model.CategoryMetadata,
				Severity: model.SeverityHigh,
				Path:     a.Path,
				Message:  "Debug symbol file detected in release artifact",
				Autofixable: true,
				RecommendedFix: "Enable strip_debug_info transform.",
			})
			continue
		}

		// Scan text files for internal URLs and build paths
		if isBinaryMIME(a.MIME) {
			continue
		}

		absPath := filepath.Join(root, a.Path)
		f, err := os.Open(absPath)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(f)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()

			if mcfg.FailOnInternalURLs {
				if match := internalURLPattern.FindString(line); match != "" {
					findings = append(findings, model.Finding{
						ID:             "RG-META-003",
						Category:       model.CategoryMetadata,
						Severity:       model.SeverityMedium,
						Path:           a.Path,
						Line:           lineNum,
						Message:        fmt.Sprintf("Internal URL or hostname detected: %q", match),
						Autofixable:    false,
						RecommendedFix: "Replace internal URLs with production endpoints before release.",
					})
				}
			}

			if mcfg.FailOnBuildPaths {
				if match := buildPathPattern.FindString(line); match != "" {
					findings = append(findings, model.Finding{
						ID:             "RG-META-004",
						Category:       model.CategoryMetadata,
						Severity:       model.SeverityLow,
						Path:           a.Path,
						Line:           lineNum,
						Message:        fmt.Sprintf("Build machine path detected: %q", match),
						Autofixable:    false,
						RecommendedFix: "Use -trimpath flag when building Go binaries. Configure source map redaction for JS.",
					})
				}
			}
		}
		f.Close()
	}

	return findings, nil
}
