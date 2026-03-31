package scan

import (
	"testing"

	"github.com/Helixar-AI/ReleaseGuard/internal/config"
	"github.com/Helixar-AI/ReleaseGuard/internal/model"
)

func TestSymlinksScanner_Name(t *testing.T) {
	s := &SymlinksScanner{}
	if s.Name() != "symlinks" {
		t.Errorf("Name() = %q, want %q", s.Name(), "symlinks")
	}
}

func TestSymlinksScanner_Scan(t *testing.T) {
	makeCfg := func(allow ...string) *config.Config {
		cfg := config.DefaultConfig()
		cfg.Scanning.Symlinks = config.SymlinksConfig{
			Enabled: true,
			Allow:   allow,
		}
		return cfg
	}

	t.Run("no symlinks produces no findings", func(t *testing.T) {
		arts := []model.Artifact{
			{Path: "index.js", Kind: "file"},
			{Path: "style.css", Kind: "file"},
		}
		s := &SymlinksScanner{}
		findings, err := s.Scan(".", arts, makeCfg())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(findings))
		}
	})

	t.Run("single symlink produces RG-SYM-001", func(t *testing.T) {
		arts := []model.Artifact{
			{Path: "latest", Kind: "symlink"},
		}
		s := &SymlinksScanner{}
		findings, err := s.Scan(".", arts, makeCfg())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		f := findings[0]
		if f.ID != "RG-SYM-001" {
			t.Errorf("expected ID RG-SYM-001, got %q", f.ID)
		}
		if f.Category != model.CategorySymlink {
			t.Errorf("expected category %q, got %q", model.CategorySymlink, f.Category)
		}
		if f.Severity != model.SeverityMedium {
			t.Errorf("expected severity %q, got %q", model.SeverityMedium, f.Severity)
		}
	})

	t.Run("multiple symlinks produce multiple findings", func(t *testing.T) {
		arts := []model.Artifact{
			{Path: "latest", Kind: "symlink"},
			{Path: "current", Kind: "symlink"},
		}
		s := &SymlinksScanner{}
		findings, err := s.Scan(".", arts, makeCfg())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 2 {
			t.Errorf("expected 2 findings, got %d", len(findings))
		}
	})

	t.Run("allowed symlink path is skipped", func(t *testing.T) {
		arts := []model.Artifact{
			{Path: "latest", Kind: "symlink"},
		}
		s := &SymlinksScanner{}
		findings, err := s.Scan(".", arts, makeCfg("latest"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 0 {
			t.Errorf("expected allowed symlink to be skipped, got %d findings", len(findings))
		}
	})

	t.Run("allowed symlink skipped, others still flagged", func(t *testing.T) {
		arts := []model.Artifact{
			{Path: "latest", Kind: "symlink"},
			{Path: "unexpected-link", Kind: "symlink"},
		}
		s := &SymlinksScanner{}
		findings, err := s.Scan(".", arts, makeCfg("latest"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding for non-allowed symlink, got %d", len(findings))
		}
		if findings[0].Path != "unexpected-link" {
			t.Errorf("expected finding for unexpected-link, got %q", findings[0].Path)
		}
	})

	t.Run("regular files are not flagged", func(t *testing.T) {
		arts := []model.Artifact{
			{Path: "main.js", Kind: "file"},
		}
		s := &SymlinksScanner{}
		findings, err := s.Scan(".", arts, makeCfg())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 0 {
			t.Errorf("expected regular files to be ignored, got %d findings", len(findings))
		}
	})

	t.Run("directories are not flagged", func(t *testing.T) {
		arts := []model.Artifact{
			{Path: "static", Kind: "dir"},
		}
		s := &SymlinksScanner{}
		findings, err := s.Scan(".", arts, makeCfg())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 0 {
			t.Errorf("expected directories to be ignored, got %d findings", len(findings))
		}
	})
}
