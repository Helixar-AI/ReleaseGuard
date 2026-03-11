package integration_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Helixar-AI/ReleaseGuard/internal/collect"
	"github.com/Helixar-AI/ReleaseGuard/internal/config"
	"github.com/Helixar-AI/ReleaseGuard/internal/model"
	"github.com/Helixar-AI/ReleaseGuard/internal/transform"
)

// copyFixture copies the source fixture directory into dst (which must not already exist).
func copyFixture(t *testing.T, src, dst string) {
	t.Helper()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("copyFixture ReadDir %s: %v", src, err)
	}
	if err := os.MkdirAll(dst, 0755); err != nil {
		t.Fatalf("copyFixture MkdirAll %s: %v", dst, err)
	}
	for _, e := range entries {
		srcPath := filepath.Join(src, e.Name())
		dstPath := filepath.Join(dst, e.Name())
		if e.IsDir() {
			copyFixture(t, srcPath, dstPath)
			continue
		}
		data, err := os.ReadFile(srcPath)
		if err != nil {
			t.Fatalf("copyFixture ReadFile %s: %v", srcPath, err)
		}
		if err := os.WriteFile(dstPath, data, 0644); err != nil {
			t.Fatalf("copyFixture WriteFile %s: %v", dstPath, err)
		}
	}
}

func TestTransform_RemovesSourceMaps(t *testing.T) {
	src := filepath.Join(fixturesDir(t), "react-dist")
	dst := t.TempDir()
	copyFixture(t, src, dst)

	cfg := config.DefaultConfig()
	cfg.Transforms.RemoveSourceMaps = true
	cfg.Transforms.AddChecksums = false
	cfg.Transforms.AddManifest = false
	cfg.Transforms.DeleteForbiddenFiles = false

	walker := collect.NewWalker()
	artifacts, err := walker.Walk(dst)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	engine := transform.NewEngine(cfg, false)
	transforms, err := engine.Run(dst, artifacts)
	if err != nil {
		t.Fatalf("transform: %v", err)
	}

	// Should have at least one delete for the .js.map file
	var deletedMaps int
	for _, tx := range transforms {
		if tx.Action == model.ActionDelete {
			deletedMaps++
		}
	}
	if deletedMaps == 0 {
		t.Error("expected source map to be deleted, got no deletions")
	}

	// Verify the .js.map file is gone
	mapPath := filepath.Join(dst, "static", "js", "main.abc123.js.map")
	if _, err := os.Stat(mapPath); !os.IsNotExist(err) {
		t.Error("expected .js.map to be removed, but it still exists")
	}
}

func TestTransform_AddChecksums(t *testing.T) {
	src := filepath.Join(fixturesDir(t), "clean-dist")
	dst := t.TempDir()
	copyFixture(t, src, dst)

	cfg := config.DefaultConfig()
	cfg.Transforms.RemoveSourceMaps = false
	cfg.Transforms.DeleteForbiddenFiles = false
	cfg.Transforms.AddChecksums = true
	cfg.Transforms.AddManifest = false

	walker := collect.NewWalker()
	artifacts, err := walker.Walk(dst)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	engine := transform.NewEngine(cfg, false)
	_, err = engine.Run(dst, artifacts)
	if err != nil {
		t.Fatalf("transform: %v", err)
	}

	// checksums.sha256 must now exist
	checksumPath := filepath.Join(dst, "checksums.sha256")
	data, err := os.ReadFile(checksumPath)
	if err != nil {
		t.Fatalf("checksums.sha256 not created: %v", err)
	}
	if len(data) == 0 {
		t.Error("checksums.sha256 is empty")
	}
}

func TestTransform_AddManifest(t *testing.T) {
	src := filepath.Join(fixturesDir(t), "clean-dist")
	dst := t.TempDir()
	copyFixture(t, src, dst)

	cfg := config.DefaultConfig()
	cfg.Transforms.RemoveSourceMaps = false
	cfg.Transforms.DeleteForbiddenFiles = false
	cfg.Transforms.AddChecksums = false
	cfg.Transforms.AddManifest = true

	walker := collect.NewWalker()
	artifacts, err := walker.Walk(dst)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	engine := transform.NewEngine(cfg, false)
	_, err = engine.Run(dst, artifacts)
	if err != nil {
		t.Fatalf("transform: %v", err)
	}

	// manifest.json must now exist
	manifestPath := filepath.Join(dst, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("manifest.json not created: %v", err)
	}
	if len(data) == 0 {
		t.Error("manifest.json is empty")
	}
}

func TestTransform_DryRun_NoChanges(t *testing.T) {
	src := filepath.Join(fixturesDir(t), "react-dist")
	dst := t.TempDir()
	copyFixture(t, src, dst)

	cfg := config.DefaultConfig()

	walker := collect.NewWalker()
	artifacts, err := walker.Walk(dst)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	engine := transform.NewEngine(cfg, true) // dryRun = true
	transforms, err := engine.Run(dst, artifacts)
	if err != nil {
		t.Fatalf("transform: %v", err)
	}

	// In dry run, transforms are reported but not applied
	if len(transforms) == 0 {
		t.Error("expected dry-run to report transforms, got none")
	}

	// Source map should still exist
	mapPath := filepath.Join(dst, "static", "js", "main.abc123.js.map")
	if _, err := os.Stat(mapPath); os.IsNotExist(err) {
		t.Error("dry-run should not remove files, but .js.map is gone")
	}
}
