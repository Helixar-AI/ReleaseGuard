package issue

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Helixar-AI/ReleaseGuard/internal/config"
	"github.com/Helixar-AI/ReleaseGuard/internal/model"
)

func TestNewGitHubCreator(t *testing.T) {
	cfg := config.GitHubIssuesConfig{Enabled: true, Severities: []string{"critical"}}

	tests := []struct {
		name    string
		slug    string
		wantErr bool
	}{
		{"valid slug", "owner/repo", false},
		{"empty slug", "", true},
		{"no slash", "ownerrepo", true},
		{"missing repo", "owner/", true},
		{"missing owner", "/repo", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewGitHubCreator("token", tt.slug, cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewGitHubCreator() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFilterFindings(t *testing.T) {
	cfg := config.GitHubIssuesConfig{
		Enabled:    true,
		Severities: []string{"critical", "high"},
	}

	creator, err := NewGitHubCreator("token", "owner/repo", cfg)
	if err != nil {
		t.Fatal(err)
	}

	findings := []model.Finding{
		{ID: "RG-SEC-001", Severity: model.SeverityCritical, Message: "AWS key"},
		{ID: "RG-SEC-020", Severity: model.SeverityHigh, Message: "GitHub token"},
		{ID: "RG-SEC-070", Severity: model.SeverityMedium, Message: "JWT token"},
		{ID: "RG-META-001", Severity: model.SeverityLow, Message: "source map"},
	}

	matched := creator.filterFindings(findings)
	if len(matched) != 2 {
		t.Fatalf("expected 2 matched findings, got %d", len(matched))
	}
	if matched[0].ID != "RG-SEC-001" {
		t.Errorf("expected first match RG-SEC-001, got %s", matched[0].ID)
	}
	if matched[1].ID != "RG-SEC-020" {
		t.Errorf("expected second match RG-SEC-020, got %s", matched[1].ID)
	}
}

func TestFilterFindingsNoneMatch(t *testing.T) {
	cfg := config.GitHubIssuesConfig{
		Enabled:    true,
		Severities: []string{"critical"},
	}

	creator, _ := NewGitHubCreator("token", "owner/repo", cfg)

	findings := []model.Finding{
		{ID: "RG-SEC-070", Severity: model.SeverityMedium, Message: "JWT token"},
	}

	matched := creator.filterFindings(findings)
	if len(matched) != 0 {
		t.Fatalf("expected 0 matched findings, got %d", len(matched))
	}
}

func TestBuildTitle(t *testing.T) {
	cfg := config.GitHubIssuesConfig{Severities: []string{"critical"}}
	creator, _ := NewGitHubCreator("token", "owner/repo", cfg)

	findings := []model.Finding{
		{ID: "RG-SEC-001", Severity: model.SeverityCritical},
		{ID: "RG-SEC-002", Severity: model.SeverityCritical},
	}
	result := &model.ScanResult{InputPath: "./dist"}

	title := creator.buildTitle(findings, result)
	if !strings.Contains(title, "[ReleaseGuard]") {
		t.Error("title should contain [ReleaseGuard] prefix")
	}
	if !strings.Contains(title, "2 CRITICAL") {
		t.Error("title should contain finding count and severity")
	}
	if !strings.Contains(title, "./dist") {
		t.Error("title should contain scan path")
	}
}

func TestBuildBody(t *testing.T) {
	cfg := config.GitHubIssuesConfig{Severities: []string{"critical"}}
	creator, _ := NewGitHubCreator("token", "owner/repo", cfg)

	findings := []model.Finding{
		{
			ID:             "RG-SEC-001",
			Category:       model.CategorySecret,
			Severity:       model.SeverityCritical,
			Path:           "config/secrets.json",
			Line:           42,
			Message:        "AWS Access Key ID detected",
			Evidence:       "AKIA***REDACTED",
			Autofixable:    false,
			RecommendedFix: "Remove the AWS key and rotate credentials",
		},
	}
	result := &model.ScanResult{
		InputPath: "./dist",
		Timestamp: "2025-01-01T00:00:00Z",
		PolicyResult: &model.PolicyResult{
			Result: model.OutcomeFail,
		},
		Manifest: &model.Manifest{
			TotalFiles: 150,
		},
	}

	body := creator.buildBody(findings, result)

	checks := []string{
		"## ReleaseGuard Security Alert",
		"**1** security finding(s)",
		"`./dist`",
		"2025-01-01T00:00:00Z",
		"`FAIL`",
		"150",
		"RG-SEC-001",
		"AWS Access Key ID detected",
		"AKIA***REDACTED",
		"Remove the AWS key and rotate credentials",
		"Secrets Remediation",
		"Rotate",
		"integrations.github_issues.enabled: false",
	}

	for _, check := range checks {
		if !strings.Contains(body, check) {
			t.Errorf("body should contain %q", check)
		}
	}
}

func TestBuildBodyMetadataGuidance(t *testing.T) {
	cfg := config.GitHubIssuesConfig{Severities: []string{"critical"}}
	creator, _ := NewGitHubCreator("token", "owner/repo", cfg)

	findings := []model.Finding{
		{
			ID:       "RG-META-002",
			Category: model.CategoryMetadata,
			Severity: model.SeverityCritical,
			Path:     "app.pdb",
			Message:  "Debug symbols in release",
		},
	}
	result := &model.ScanResult{InputPath: "./dist", Timestamp: "now"}

	body := creator.buildBody(findings, result)
	if !strings.Contains(body, "Metadata Leak Remediation") {
		t.Error("body should contain metadata remediation guidance")
	}
}

func TestBuildBodyAutofixable(t *testing.T) {
	cfg := config.GitHubIssuesConfig{Severities: []string{"critical"}}
	creator, _ := NewGitHubCreator("token", "owner/repo", cfg)

	findings := []model.Finding{
		{
			ID:          "RG-UNEXP-001",
			Category:    model.CategoryUnexpected,
			Severity:    model.SeverityCritical,
			Path:        ".env",
			Message:     "Forbidden file",
			Autofixable: true,
		},
	}
	result := &model.ScanResult{InputPath: "./dist", Timestamp: "now"}

	body := creator.buildBody(findings, result)
	if !strings.Contains(body, "releaseguard fix") {
		t.Error("body should mention releaseguard fix for autofixable findings")
	}
}

func TestCreateForFindings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/repos/owner/repo/issues") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unexpected auth header: %s", r.Header.Get("Authorization"))
		}

		var req issueRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		if !strings.Contains(req.Title, "[ReleaseGuard]") {
			t.Error("issue title should contain [ReleaseGuard]")
		}
		if len(req.Labels) != 2 {
			t.Errorf("expected 2 labels, got %d", len(req.Labels))
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(issueResponse{
			Number:  42,
			HTMLURL: "https://github.com/owner/repo/issues/42",
		})
	}))
	defer server.Close()

	cfg := config.GitHubIssuesConfig{
		Enabled:    true,
		Severities: []string{"critical"},
		Labels:     []string{"security", "critical"},
	}

	creator, _ := NewGitHubCreator("test-token", "owner/repo", cfg)
	creator.baseURL = server.URL

	findings := []model.Finding{
		{ID: "RG-SEC-001", Severity: model.SeverityCritical, Message: "AWS key"},
	}
	result := &model.ScanResult{InputPath: "./dist", Timestamp: "now"}

	url, err := creator.CreateForFindings(findings, result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if url != "https://github.com/owner/repo/issues/42" {
		t.Errorf("unexpected URL: %s", url)
	}
}

func TestCreateForFindingsNoMatch(t *testing.T) {
	cfg := config.GitHubIssuesConfig{
		Enabled:    true,
		Severities: []string{"critical"},
	}
	creator, _ := NewGitHubCreator("token", "owner/repo", cfg)

	findings := []model.Finding{
		{ID: "RG-SEC-070", Severity: model.SeverityMedium, Message: "JWT"},
	}
	result := &model.ScanResult{InputPath: "./dist", Timestamp: "now"}

	url, err := creator.CreateForFindings(findings, result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if url != "" {
		t.Errorf("expected empty URL for no matches, got %s", url)
	}
}

func TestCreateForFindingsAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	defer server.Close()

	cfg := config.GitHubIssuesConfig{
		Enabled:    true,
		Severities: []string{"critical"},
	}
	creator, _ := NewGitHubCreator("bad-token", "owner/repo", cfg)
	creator.baseURL = server.URL

	findings := []model.Finding{
		{ID: "RG-SEC-001", Severity: model.SeverityCritical, Message: "AWS key"},
	}
	result := &model.ScanResult{InputPath: "./dist", Timestamp: "now"}

	_, err := creator.CreateForFindings(findings, result)
	if err == nil {
		t.Fatal("expected error for API failure")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error should mention status code: %v", err)
	}
}
