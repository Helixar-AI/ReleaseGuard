package integration_test

import (
	"path/filepath"
	"testing"

	"github.com/Helixar-AI/ReleaseGuard/internal/config"
	"github.com/Helixar-AI/ReleaseGuard/internal/sbom"
)

func TestSBOM_NodePackageLock(t *testing.T) {
	root := filepath.Join(fixturesDir(t), "react-dist")
	cfg := config.DefaultConfig()
	cfg.SBOM.Ecosystems = []string{"node"}

	engine := sbom.NewEngine(cfg)
	bill, err := engine.Generate(root)
	if err != nil {
		t.Fatalf("SBOM generate: %v", err)
	}

	if bill.Total == 0 {
		t.Fatal("expected SBOM components from package-lock.json, got 0")
	}

	// Verify react is in the component list
	var foundReact bool
	for _, c := range bill.Components {
		if c.Name == "react" {
			foundReact = true
			if c.Version == "" {
				t.Error("react component has empty version")
			}
			if c.PackageURL == "" {
				t.Error("react component has empty PackageURL")
			}
			if c.Ecosystem != "node" {
				t.Errorf("react component ecosystem = %q, want %q", c.Ecosystem, "node")
			}
			break
		}
	}
	if !foundReact {
		t.Errorf("react not found in SBOM components: %v", bill.Components)
	}
}

func TestSBOM_CleanDist_NoComponents(t *testing.T) {
	root := filepath.Join(fixturesDir(t), "clean-dist")
	cfg := config.DefaultConfig()
	cfg.SBOM.Ecosystems = []string{"node", "python", "go", "rust"}

	engine := sbom.NewEngine(cfg)
	bill, err := engine.Generate(root)
	if err != nil {
		t.Fatalf("SBOM generate: %v", err)
	}

	// clean-dist has no lock files so total should be 0
	if bill.Total != 0 {
		t.Errorf("expected 0 SBOM components for clean-dist, got %d", bill.Total)
	}
}

func TestSBOM_ComponentFields(t *testing.T) {
	root := filepath.Join(fixturesDir(t), "react-dist")
	cfg := config.DefaultConfig()
	cfg.SBOM.Ecosystems = []string{"node"}

	engine := sbom.NewEngine(cfg)
	bill, err := engine.Generate(root)
	if err != nil {
		t.Fatalf("SBOM generate: %v", err)
	}

	for _, c := range bill.Components {
		if c.Name == "" {
			t.Error("component has empty name")
		}
		if c.Ecosystem == "" {
			t.Error("component has empty ecosystem")
		}
		if c.PackageURL == "" {
			t.Errorf("component %q has empty PackageURL", c.Name)
		}
	}
}
