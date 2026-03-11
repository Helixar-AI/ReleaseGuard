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
	// filenameOnly means the pattern is matched against the filename, not line content.
	filenameOnly bool
}

//nolint:lll
var secretPatterns = []secretPattern{
	// Cloud provider credentials
	{
		id:       "RG-SEC-001",
		name:     "AWS Access Key ID",
		pattern:  regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		severity: model.SeverityCritical,
	},
	{
		id:       "RG-SEC-002",
		name:     "AWS Secret Access Key (assignment)",
		pattern:  regexp.MustCompile(`(?i)aws.{0,10}secret.{0,10}[=:]\s*["']?[A-Za-z0-9/+]{40}["']?`),
		severity: model.SeverityCritical,
	},
	{
		id:       "RG-SEC-003",
		name:     "GCP Service Account Key",
		pattern:  regexp.MustCompile(`"type"\s*:\s*"service_account"`),
		severity: model.SeverityCritical,
	},
	{
		id:       "RG-SEC-004",
		name:     "Azure Storage Connection String",
		pattern:  regexp.MustCompile(`DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+`),
		severity: model.SeverityCritical,
	},
	// Private keys
	{
		id:       "RG-SEC-010",
		name:     "Private Key Header",
		pattern:  regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY`),
		severity: model.SeverityCritical,
	},
	// Version control tokens
	{
		id:       "RG-SEC-020",
		name:     "GitHub Token (classic)",
		pattern:  regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
		severity: model.SeverityHigh,
	},
	{
		id:       "RG-SEC-021",
		name:     "GitHub Fine-Grained Token",
		pattern:  regexp.MustCompile(`github_pat_[0-9a-zA-Z_]{82}`),
		severity: model.SeverityHigh,
	},
	{
		id:       "RG-SEC-022",
		name:     "GitHub Actions Token",
		pattern:  regexp.MustCompile(`ghs_[0-9a-zA-Z]{36}`),
		severity: model.SeverityHigh,
	},
	// Package manager tokens
	{
		id:       "RG-SEC-030",
		name:     "npm Token",
		pattern:  regexp.MustCompile(`npm_[0-9a-zA-Z]{36}`),
		severity: model.SeverityHigh,
	},
	{
		id:       "RG-SEC-031",
		name:     "PyPI API Token",
		pattern:  regexp.MustCompile(`pypi-[a-zA-Z0-9_-]{30,}`),
		severity: model.SeverityHigh,
	},
	// Payment processors
	{
		id:       "RG-SEC-040",
		name:     "Stripe Secret Key",
		pattern:  regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`),
		severity: model.SeverityCritical,
	},
	{
		id:       "RG-SEC-041",
		name:     "Stripe Restricted Key",
		pattern:  regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24,}`),
		severity: model.SeverityHigh,
	},
	{
		id:       "RG-SEC-042",
		name:     "Square Access Token",
		pattern:  regexp.MustCompile(`sq0atp-[0-9a-zA-Z\-_]{22}`),
		severity: model.SeverityHigh,
	},
	// Communication services
	{
		id:       "RG-SEC-050",
		name:     "Slack Bot Token",
		pattern:  regexp.MustCompile(`xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}`),
		severity: model.SeverityHigh,
	},
	{
		id:       "RG-SEC-051",
		name:     "Slack Webhook URL",
		pattern:  regexp.MustCompile(`hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9]{24}`),
		severity: model.SeverityHigh,
	},
	{
		id:       "RG-SEC-052",
		name:     "Twilio Account SID",
		pattern:  regexp.MustCompile(`AC[a-f0-9]{32}`),
		severity: model.SeverityHigh,
	},
	{
		id:       "RG-SEC-053",
		name:     "SendGrid API Key",
		pattern:  regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`),
		severity: model.SeverityHigh,
	},
	{
		id:       "RG-SEC-054",
		name:     "Mailgun API Key",
		pattern:  regexp.MustCompile(`key-[0-9a-z]{32}`),
		severity: model.SeverityHigh,
	},
	// Cloud platform tokens
	{
		id:       "RG-SEC-060",
		name:     "Heroku API Key",
		pattern:  regexp.MustCompile(`(?i)heroku.{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
		severity: model.SeverityHigh,
	},
	{
		id:       "RG-SEC-061",
		name:     "DigitalOcean Token",
		pattern:  regexp.MustCompile(`dop_v1_[a-zA-Z0-9]{43}`),
		severity: model.SeverityHigh,
	},
	{
		id:       "RG-SEC-062",
		name:     "Shopify Private App Token",
		pattern:  regexp.MustCompile(`shpat_[a-fA-F0-9]{32}`),
		severity: model.SeverityHigh,
	},
	// Auth tokens
	{
		id:       "RG-SEC-070",
		name:     "JSON Web Token",
		pattern:  regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}`),
		severity: model.SeverityMedium,
	},
	{
		id:       "RG-SEC-071",
		name:     "HTTP Basic Auth Header",
		pattern:  regexp.MustCompile(`(?i)Authorization\s*:\s*Basic\s+[a-zA-Z0-9+/]{20,}={0,2}`),
		severity: model.SeverityHigh,
	},
	{
		id:       "RG-SEC-072",
		name:     "HashiCorp Vault Token",
		pattern:  regexp.MustCompile(`hvs\.[a-zA-Z0-9_-]{90,}`),
		severity: model.SeverityCritical,
	},
	// Sensitive files
	{
		id:           "RG-SEC-080",
		name:         "Environment Variable File",
		pattern:      regexp.MustCompile(`(?i)^\.env(\..+)?$`),
		severity:     model.SeverityHigh,
		filenameOnly: true,
	},
	{
		id:           "RG-SEC-081",
		name:         "Kubernetes Secret Manifest",
		pattern:      regexp.MustCompile(`(?i)^.*kubeconfig.*$`),
		severity:     model.SeverityHigh,
		filenameOnly: true,
	},
	// Generic patterns (lower confidence)
	{
		id:       "RG-SEC-090",
		name:     "Generic API Key Assignment",
		pattern:  regexp.MustCompile(`(?i)(api_key|apikey|api-key)\s*[=:]\s*["']?[0-9a-zA-Z\-_]{20,}["']?`),
		severity: model.SeverityMedium,
	},
	{
		id:       "RG-SEC-091",
		name:     "Generic Secret Assignment",
		pattern:  regexp.MustCompile(`(?i)(secret|password|passwd|pwd)\s*[=:]\s*["'][^"']{8,}["']`),
		severity: model.SeverityMedium,
	},
}

// SecretsScanner detects secrets and sensitive credentials in artifact files.
type SecretsScanner struct{}

func (s *SecretsScanner) Name() string { return "secrets" }

func (s *SecretsScanner) Scan(root string, artifacts []model.Artifact, cfg *config.Config) ([]model.Finding, error) {
	var findings []model.Finding

	for _, a := range artifacts {
		// Filename-only patterns (check all artifacts regardless of MIME)
		for _, p := range secretPatterns {
			if !p.filenameOnly {
				continue
			}
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
			}
		}

		// Skip binary files for content scanning
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

			// Pattern-based detection
			for _, p := range secretPatterns {
				if p.filenameOnly {
					continue
				}
				if match := p.pattern.FindString(line); match != "" {
					findings = append(findings, model.Finding{
						ID:             p.id,
						Category:       model.CategorySecret,
						Severity:       p.severity,
						Path:           a.Path,
						Line:           lineNum,
						Message:        fmt.Sprintf("%s detected", p.name),
						Evidence:       redactSecret(match),
						Autofixable:    false,
						RecommendedFix: "Remove secret before build. Use environment variable injection at runtime.",
					})
				}
			}

			// Entropy-based detection: flag high-entropy tokens adjacent to credential keywords
			if lineHasSecretContext(line) {
				for _, tok := range extractHighEntropyTokens(line) {
					findings = append(findings, model.Finding{
						ID:             "RG-SEC-099",
						Category:       model.CategorySecret,
						Severity:       model.SeverityHigh,
						Path:           a.Path,
						Line:           lineNum,
						Message:        "High-entropy string near credential keyword",
						Evidence:       redactSecret(tok),
						Autofixable:    false,
						RecommendedFix: "Verify this is not a hardcoded secret. Use a secrets manager instead.",
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
