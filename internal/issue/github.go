package issue

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Helixar-AI/ReleaseGuard/internal/config"
	"github.com/Helixar-AI/ReleaseGuard/internal/model"
)

// GitHubCreator creates GitHub issues for critical scan findings.
type GitHubCreator struct {
	token   string
	owner   string
	repo    string
	cfg     config.GitHubIssuesConfig
	client  *http.Client
	baseURL string
}

// NewGitHubCreator returns a GitHubCreator configured from the given parameters.
// token is a GitHub API token with issues:write permission.
// repoSlug is "owner/repo" format.
func NewGitHubCreator(token, repoSlug string, cfg config.GitHubIssuesConfig) (*GitHubCreator, error) {
	parts := strings.SplitN(repoSlug, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("invalid repository slug %q: expected owner/repo", repoSlug)
	}
	return &GitHubCreator{
		token:   token,
		owner:   parts[0],
		repo:    parts[1],
		cfg:     cfg,
		client:  &http.Client{Timeout: 30 * time.Second},
		baseURL: "https://api.github.com",
	}, nil
}

// issueRequest is the GitHub API request body for creating an issue.
type issueRequest struct {
	Title     string   `json:"title"`
	Body      string   `json:"body"`
	Labels    []string `json:"labels,omitempty"`
	Assignees []string `json:"assignees,omitempty"`
}

// issueResponse is the subset of the GitHub API response we care about.
type issueResponse struct {
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
}

// CreateForFindings filters findings by configured severities and creates a
// single GitHub issue summarising all matched findings. Returns the issue URL
// or empty string if no findings matched.
func (g *GitHubCreator) CreateForFindings(findings []model.Finding, scanResult *model.ScanResult) (string, error) {
	matched := g.filterFindings(findings)
	if len(matched) == 0 {
		return "", nil
	}

	title := g.buildTitle(matched, scanResult)
	body := g.buildBody(matched, scanResult)

	req := issueRequest{
		Title:     title,
		Body:      body,
		Labels:    g.cfg.Labels,
		Assignees: g.cfg.Assignees,
	}

	resp, err := g.createIssue(req)
	if err != nil {
		return "", fmt.Errorf("creating GitHub issue: %w", err)
	}

	return resp.HTMLURL, nil
}

func (g *GitHubCreator) filterFindings(findings []model.Finding) []model.Finding {
	sevSet := make(map[string]bool, len(g.cfg.Severities))
	for _, s := range g.cfg.Severities {
		sevSet[strings.ToLower(s)] = true
	}

	var matched []model.Finding
	for _, f := range findings {
		if sevSet[strings.ToLower(f.Severity)] {
			matched = append(matched, f)
		}
	}
	return matched
}

func (g *GitHubCreator) buildTitle(findings []model.Finding, result *model.ScanResult) string {
	sevCounts := make(map[string]int)
	for _, f := range findings {
		sevCounts[strings.ToUpper(f.Severity)]++
	}

	var parts []string
	for sev, count := range sevCounts {
		parts = append(parts, fmt.Sprintf("%d %s", count, sev))
	}

	project := result.InputPath
	if project == "" {
		project = "release artifacts"
	}

	return fmt.Sprintf("[ReleaseGuard] %s vulnerability finding(s) detected in %s",
		strings.Join(parts, ", "), project)
}

func (g *GitHubCreator) buildBody(findings []model.Finding, result *model.ScanResult) string {
	var b strings.Builder

	b.WriteString("## ReleaseGuard Security Alert\n\n")
	b.WriteString(fmt.Sprintf("ReleaseGuard detected **%d** security finding(s) that blocked the release build.\n\n", len(findings)))

	// Scan metadata
	b.WriteString("### Scan Details\n\n")
	b.WriteString(fmt.Sprintf("- **Scanned path:** `%s`\n", result.InputPath))
	b.WriteString(fmt.Sprintf("- **Timestamp:** %s\n", result.Timestamp))
	if result.PolicyResult != nil {
		b.WriteString(fmt.Sprintf("- **Policy result:** `%s`\n", strings.ToUpper(string(result.PolicyResult.Result))))
	}
	if result.Manifest != nil {
		b.WriteString(fmt.Sprintf("- **Total files scanned:** %d\n", result.Manifest.TotalFiles))
	}
	b.WriteString("\n")

	// Findings table
	b.WriteString("### Findings\n\n")
	b.WriteString("| # | Severity | Category | Rule ID | Path | Message |\n")
	b.WriteString("|---|----------|----------|---------|------|---------|\n")
	for i, f := range findings {
		path := f.Path
		if len(path) > 50 {
			path = "..." + path[len(path)-47:]
		}
		b.WriteString(fmt.Sprintf("| %d | **%s** | %s | `%s` | `%s` | %s |\n",
			i+1, strings.ToUpper(f.Severity), f.Category, f.ID, path, f.Message))
	}
	b.WriteString("\n")

	// Detailed findings with evidence and recommendations
	b.WriteString("### Finding Details\n\n")
	for i, f := range findings {
		b.WriteString(fmt.Sprintf("#### %d. %s (`%s`)\n\n", i+1, f.Message, f.ID))
		b.WriteString(fmt.Sprintf("- **Severity:** %s\n", strings.ToUpper(f.Severity)))
		b.WriteString(fmt.Sprintf("- **Category:** %s\n", f.Category))
		b.WriteString(fmt.Sprintf("- **File:** `%s`", f.Path))
		if f.Line > 0 {
			b.WriteString(fmt.Sprintf(" (line %d)", f.Line))
		}
		b.WriteString("\n")

		if f.Evidence != "" {
			b.WriteString(fmt.Sprintf("- **Evidence:** `%s`\n", f.Evidence))
		}

		if f.RecommendedFix != "" {
			b.WriteString(fmt.Sprintf("\n**Recommended fix:** %s\n", f.RecommendedFix))
		}

		if f.Autofixable {
			b.WriteString("\n> This finding can be automatically fixed by running `releaseguard fix`.\n")
		}

		b.WriteString("\n")
	}

	// Remediation steps
	b.WriteString("### Recommended Actions\n\n")
	b.WriteString("1. **Review** the findings listed above and assess the impact\n")
	b.WriteString("2. **Fix** the identified issues in the source code or build configuration\n")

	hasAutofixable := false
	for _, f := range findings {
		if f.Autofixable {
			hasAutofixable = true
			break
		}
	}
	if hasAutofixable {
		b.WriteString("3. **Auto-fix** eligible findings by running:\n")
		b.WriteString("   ```bash\n   releaseguard fix <path>\n   ```\n")
	}

	b.WriteString(fmt.Sprintf("%d. **Re-run** the release pipeline after fixes are applied\n", 4))
	b.WriteString(fmt.Sprintf("%d. **Update policy** in `.releaseguard.yml` if any findings are acceptable risks\n\n", 5))

	// Category-specific guidance
	categories := make(map[string]bool)
	for _, f := range findings {
		categories[f.Category] = true
	}

	if categories[model.CategorySecret] {
		b.WriteString("### Secrets Remediation\n\n")
		b.WriteString("Leaked secrets require immediate action:\n")
		b.WriteString("- **Rotate** all exposed credentials immediately\n")
		b.WriteString("- **Revoke** any tokens or API keys found in the artifacts\n")
		b.WriteString("- **Audit** access logs for any unauthorized usage\n")
		b.WriteString("- **Add** the files to `.gitignore` and scanning exclusions if they should never be in artifacts\n\n")
	}

	if categories[model.CategoryMetadata] {
		b.WriteString("### Metadata Leak Remediation\n\n")
		b.WriteString("- Remove source maps from production builds (set `devtool: false` or `hidden-source-map` in webpack/vite)\n")
		b.WriteString("- Strip debug symbols from production binaries\n")
		b.WriteString("- Sanitize internal URLs and build paths from output\n\n")
	}

	b.WriteString("---\n")
	b.WriteString("*This issue was automatically created by [ReleaseGuard](https://github.com/Helixar-AI/ReleaseGuard). ")
	b.WriteString("To disable automatic issue creation, set `integrations.github_issues.enabled: false` in `.releaseguard.yml`.*\n")

	return b.String()
}

func (g *GitHubCreator) createIssue(req issueRequest) (*issueResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshalling request: %w", err)
	}

	url := fmt.Sprintf("%s/repos/%s/%s/issues", g.baseURL, g.owner, g.repo)
	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+g.token)
	httpReq.Header.Set("Accept", "application/vnd.github+json")
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := g.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, string(respBody))
	}

	var issueResp issueResponse
	if err := json.Unmarshal(respBody, &issueResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	return &issueResp, nil
}
