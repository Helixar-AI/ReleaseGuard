package app

import (
	"fmt"
	"os"
	"time"

	"github.com/Helixar-AI/ReleaseGuard/internal/collect"
	"github.com/Helixar-AI/ReleaseGuard/internal/config"
	"github.com/Helixar-AI/ReleaseGuard/internal/issue"
	"github.com/Helixar-AI/ReleaseGuard/internal/model"
	"github.com/Helixar-AI/ReleaseGuard/internal/policy"
	"github.com/Helixar-AI/ReleaseGuard/internal/report"
	"github.com/Helixar-AI/ReleaseGuard/internal/scan"
)

// Check runs the full scanner pipeline and policy evaluation against path.
func Check(path, format, out, configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if err := config.EnsureEvidenceDir(cfg.Output.Directory); err != nil {
		return err
	}

	fmt.Printf("releaseguard check %s\n\n", path)

	// Collect
	fmt.Println("  Collecting artifacts...")
	walker := collect.NewWalker()
	walker.ExcludeGlobs = cfg.Scanning.ExcludePaths
	artifacts, err := walker.Walk(path)
	if err != nil {
		return fmt.Errorf("collecting artifacts: %w", err)
	}
	fmt.Printf("  Found %d files\n", len(artifacts))

	manifest := &model.Manifest{
		Version:     "1",
		GeneratedAt: time.Now().UTC(),
		InputPath:   path,
		TotalFiles:  len(artifacts),
		Artifacts:   artifacts,
	}
	for _, a := range artifacts {
		manifest.TotalBytes += a.Size
	}

	// Scan
	fmt.Println("  Running scanners...")
	pipeline := scan.NewPipeline(cfg)
	findings, err := pipeline.Run(path, artifacts, cfg)
	if err != nil {
		return fmt.Errorf("scanning: %w", err)
	}
	fmt.Printf("  Found %d findings\n", len(findings))

	// Policy
	fmt.Println("  Evaluating policy...")
	evaluator := policy.NewEvaluator(cfg)
	result := evaluator.Evaluate(findings)

	scanResult := &model.ScanResult{
		Version:      "1",
		InputPath:    path,
		Manifest:     manifest,
		Findings:     findings,
		PolicyResult: result,
		EvidenceDir:  cfg.Output.Directory,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
	}

	// Report
	reporter := report.NewReporter(format, out)
	if err := reporter.Write(scanResult); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}

	// Create GitHub issue for critical findings if enabled
	if result.Result == model.OutcomeFail && cfg.Integrations.GitHubIssues.Enabled {
		createGitHubIssue(cfg, findings, scanResult)
	}

	// Exit code
	if result.Result == model.OutcomeFail {
		fmt.Fprintln(os.Stderr, "\nPolicy FAILED. Fix findings or update policy before releasing.")
		os.Exit(1)
	}
	if result.Result == model.OutcomeWarn {
		fmt.Println("\nPolicy PASSED with warnings.")
	} else {
		fmt.Println("\nPolicy PASSED.")
	}

	return nil
}

// createGitHubIssue attempts to create a GitHub issue for critical findings.
// It reads GITHUB_TOKEN and GITHUB_REPOSITORY from the environment (standard
// in GitHub Actions). Errors are logged but do not fail the build — the policy
// failure exit code is the primary signal.
func createGitHubIssue(cfg *config.Config, findings []model.Finding, scanResult *model.ScanResult) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "  [issue] GITHUB_TOKEN not set, skipping issue creation")
		return
	}
	repo := os.Getenv("GITHUB_REPOSITORY")
	if repo == "" {
		fmt.Fprintln(os.Stderr, "  [issue] GITHUB_REPOSITORY not set, skipping issue creation")
		return
	}

	creator, err := issue.NewGitHubCreator(token, repo, cfg.Integrations.GitHubIssues)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [issue] failed to initialise issue creator: %v\n", err)
		return
	}

	url, err := creator.CreateForFindings(findings, scanResult)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [issue] failed to create GitHub issue: %v\n", err)
		return
	}
	if url != "" {
		fmt.Printf("  Created GitHub issue: %s\n", url)
	}
}
