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

// secretPattern pairs a human-readable name with a detection regex and severity.
type secretPattern struct {
	id       string
	name     string
	pattern  *regexp.Regexp
	severity string
}

var secretPatterns = []secretPattern{
	{
		id:       "RG-SEC-001",
		name:     "AWS Access Key",
		pattern:  regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		severity: model.SeverityCritical,
	},
	{
		id:       "RG-SEC-002",
		name:     "Generic Private Key",
		pattern:  regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY`),
		severity: model.SeverityCritical,
	},
	{
		id:       "RG-SEC-003",
		name:     "GitHub Token",
		pattern:  regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}`),
		severity: model.SeverityHigh,
	},
	{
		id:       "RG-SEC-004",
		name:     "npm Token",
		pattern:  regexp.MustCompile(`npm_[0-9a-zA-Z]{36}`),
		severity: model.SeverityHigh,
	},
	{
		id:       "RG-SEC-005",
		name:     "Stripe Secret Key",
		pattern:  regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`),
		severity: model.SeverityCritical,
	},
	{
		id:       "RG-SEC-006",
		name:     "GCP Service Account Key",
		pattern:  regexp.MustCompile(`"type":\s*"service_account"`),
		severity: model.SeverityCritical,
	},
	{
		id:       "RG-SEC-007",
		name:     "Environment Variable File",
		pattern:  regexp.MustCompile(`(?i)^\.env(\..+)?$`),
		severity: model.SeverityHigh,
	},
	{
		id:       "RG-SEC-008",
		name:     "Generic API Key Assignment",
		pattern:  regexp.MustCompile(`(?i)(api_key|apikey|api-key)\s*[=:]\s*["']?[0-9a-zA-Z\-_]{20,}["']?`),
		severity: model.SeverityMedium,
	},
}

// SecretsScanner detects secrets and sensitive credentials in artifact files.
type SecretsScanner struct{}

func (s *SecretsScanner) Name() string { return "secrets" }

func (s *SecretsScanner) Scan(root string, artifacts []model.Artifact, cfg *config.Config) ([]model.Finding, error) {
	var findings []model.Finding

	for _, a := range artifacts {
		// Skip binary files that are not text-scannable
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
			for _, p := range secretPatterns {
				// Filename pattern (e.g. .env file check)
				if strings.Contains(p.pattern.String(), "^") {
					if p.pattern.MatchString(filepath.Base(a.Path)) {
						findings = append(findings, model.Finding{
							ID:             p.id,
							Category:       model.CategorySecret,
							Severity:       p.severity,
							Path:           a.Path,
							Message:        fmt.Sprintf("%s detected", p.name),
							Autofixable:    false,
							RecommendedFix: "Remove this file from the release artifact.",
						})
						break
					}
					continue
				}
				if match := p.pattern.FindString(line); match != "" {
					// Redact the actual secret value in the evidence field
					redacted := redactSecret(match)
					findings = append(findings, model.Finding{
						ID:             p.id,
						Category:       model.CategorySecret,
						Severity:       p.severity,
						Path:           a.Path,
						Line:           lineNum,
						Message:        fmt.Sprintf("%s detected", p.name),
						Evidence:       redacted,
						Autofixable:    false,
						RecommendedFix: "Remove secret before build. Use environment variable injection at runtime.",
					})
				}
			}
		}
		f.Close()
	}

	return findings, nil
}

func isBinaryMIME(mime string) bool {
	if strings.HasPrefix(mime, "text/") {
		return false
	}
	textTypes := []string{"application/json", "application/xml", "application/javascript", "application/x-sh"}
	for _, t := range textTypes {
		if strings.HasPrefix(mime, t) {
			return false
		}
	}
	return true
}

func redactSecret(s string) string {
	if len(s) <= 8 {
		return "***"
	}
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}
