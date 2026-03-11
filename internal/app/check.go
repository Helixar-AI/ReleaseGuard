package app

import (
	"fmt"
	"os"
	"time"

	"github.com/Helixar-AI/ReleaseGuard/internal/collect"
	"github.com/Helixar-AI/ReleaseGuard/internal/config"
	"github.com/Helixar-AI/ReleaseGuard/internal/model"
	"github.com/Helixar-AI/ReleaseGuard/internal/policy"
	"github.com/Helixar-AI/ReleaseGuard/internal/report"
	"github.com/Helixar-AI/ReleaseGuard/internal/scan"
)

// Check runs the full scanner pipeline and policy evaluation against path.
func Check(path, format, out string) error {
	cfg, err := config.Load("")
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
