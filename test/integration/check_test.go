package integration_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Helixar-AI/ReleaseGuard/internal/collect"
	"github.com/Helixar-AI/ReleaseGuard/internal/config"
	"github.com/Helixar-AI/ReleaseGuard/internal/model"
	"github.com/Helixar-AI/ReleaseGuard/internal/scan"
)

// fixturesDir returns the absolute path to test/fixtures.
func fixturesDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine test file path")
	}
	return filepath.Join(filepath.Dir(file), "..", "fixtures")
}

func TestCheck_ReactDist_FindsAWSKey(t *testing.T) {
	root := filepath.Join(fixturesDir(t), "react-dist")
	cfg := config.DefaultConfig()

	walker := collect.NewWalker()
	artifacts, err := walker.Walk(root)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(artifacts) == 0 {
		t.Fatal("expected at least one artifact")
	}

	pipeline := scan.NewPipeline(cfg)
	findings, err := pipeline.Run(root, artifacts, cfg)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	var secretFindings []model.Finding
	for _, f := range findings {
		if f.Category == model.CategorySecret {
			secretFindings = append(secretFindings, f)
		}
	}

	if len(secretFindings) == 0 {
		t.Error("expected at least one secret finding in react-dist, got none")
	}

	// Verify the AWS key is specifically detected
	var foundAWSKey bool
	for _, f := range secretFindings {
		if f.ID == "RG-SEC-001" {
			foundAWSKey = true
			break
		}
	}
	if !foundAWSKey {
		t.Errorf("expected AWS Access Key finding (RG-SEC-001), got findings: %v", secretFindings)
	}
}

func TestCheck_ReactDist_FindsDotEnvFile(t *testing.T) {
	root := filepath.Join(fixturesDir(t), "react-dist")
	cfg := config.DefaultConfig()

	walker := collect.NewWalker()
	artifacts, err := walker.Walk(root)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	pipeline := scan.NewPipeline(cfg)
	findings, err := pipeline.Run(root, artifacts, cfg)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	var foundEnv bool
	for _, f := range findings {
		if f.ID == "RG-SEC-080" {
			foundEnv = true
			break
		}
	}
	if !foundEnv {
		t.Error("expected .env file finding (RG-SEC-080), got none")
	}
}

func TestCheck_ReactDist_FindsSourceMap(t *testing.T) {
	root := filepath.Join(fixturesDir(t), "react-dist")
	cfg := config.DefaultConfig()

	walker := collect.NewWalker()
	artifacts, err := walker.Walk(root)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	pipeline := scan.NewPipeline(cfg)
	findings, err := pipeline.Run(root, artifacts, cfg)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	var foundSourceMap bool
	for _, f := range findings {
		if f.Category == model.CategoryMetadata {
			foundSourceMap = true
			break
		}
	}
	if !foundSourceMap {
		t.Error("expected source map metadata finding in react-dist, got none")
	}
}

func TestCheck_CleanDist_NoSecretFindings(t *testing.T) {
	root := filepath.Join(fixturesDir(t), "clean-dist")
	cfg := config.DefaultConfig()
	// Disable license check for clean-dist (it has a LICENSE file but no NOTICE)
	cfg.Scanning.Licenses.Require = []string{"LICENSE"}

	walker := collect.NewWalker()
	artifacts, err := walker.Walk(root)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	pipeline := scan.NewPipeline(cfg)
	findings, err := pipeline.Run(root, artifacts, cfg)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	for _, f := range findings {
		if f.Category == model.CategorySecret {
			t.Errorf("unexpected secret finding in clean-dist: %+v", f)
		}
	}
}

func TestCheck_EntropyDetection(t *testing.T) {
	root := filepath.Join(fixturesDir(t), "react-dist")
	cfg := config.DefaultConfig()

	walker := collect.NewWalker()
	artifacts, err := walker.Walk(root)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	pipeline := scan.NewPipeline(cfg)
	findings, err := pipeline.Run(root, artifacts, cfg)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	// The .env file contains secrets that should be detected
	if len(findings) == 0 {
		t.Error("expected findings from react-dist scan, got none")
	}
}
