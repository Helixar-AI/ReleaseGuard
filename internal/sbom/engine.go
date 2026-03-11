package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Helixar-AI/ReleaseGuard/internal/config"
	"github.com/Helixar-AI/ReleaseGuard/internal/model"
)

// Engine drives SBOM generation across multiple ecosystems.
type Engine struct {
	cfg *config.Config
}

// NewEngine returns an Engine configured from cfg.
func NewEngine(cfg *config.Config) *Engine {
	return &Engine{cfg: cfg}
}

// Generate produces a combined SBOM for all detected ecosystems under root.
func (e *Engine) Generate(root string) (*model.SBOM, error) {
	bill := &model.SBOM{
		Format:      model.SBOMFormatCycloneDX,
		Version:     "1",
		GeneratedAt: time.Now().UTC(),
		InputPath:   root,
	}

	ecosystems := e.cfg.SBOM.Ecosystems
	if len(ecosystems) == 0 {
		ecosystems = []string{"node", "python", "go", "rust", "java", "dotnet", "ruby", "php"}
	}

	for _, eco := range ecosystems {
		components, err := detectEcosystem(root, eco)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  warning: %s ecosystem detection: %v\n", eco, err)
			continue
		}
		bill.Components = append(bill.Components, components...)
	}

	bill.Total = len(bill.Components)
	return bill, nil
}

// EnrichCVE annotates SBOM components with CVE data from OSV.dev.
func (e *Engine) EnrichCVE(bill *model.SBOM) error {
	// TODO: Phase 5 — call OSV.dev batch query API
	// https://osv.dev/docs/
	fmt.Println("  CVE enrichment via OSV.dev: planned for Phase 5")
	return nil
}

// Write serialises bill to the target format and path.
func (e *Engine) Write(bill *model.SBOM, format, out string) error {
	if err := os.MkdirAll(filepath.Dir(out), 0755); err != nil {
		return err
	}

	switch format {
	case "spdx":
		bill.Format = model.SBOMFormatSPDX
		return writeSPDX(bill, out)
	default:
		return writeCycloneDX(bill, out)
	}
}

func writeCycloneDX(bill *model.SBOM, out string) error {
	data, err := json.MarshalIndent(bill, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(out, data, 0644)
}

func writeSPDX(bill *model.SBOM, out string) error {
	data, err := json.MarshalIndent(bill, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(out, data, 0644)
}

// detectEcosystem scans root for ecosystem-specific manifest files.
func detectEcosystem(root, eco string) ([]model.SBOMComponent, error) {
	switch eco {
	case "node":
		return detectNode(root)
	case "python":
		return detectPython(root)
	case "go":
		return detectGo(root)
	case "rust":
		return detectRust(root)
	default:
		// Other ecosystems: planned for Phase 5
		return nil, nil
	}
}

func detectNode(root string) ([]model.SBOMComponent, error) {
	lockFile := filepath.Join(root, "package-lock.json")
	if _, err := os.Stat(lockFile); os.IsNotExist(err) {
		return nil, nil // no Node.js project here
	}
	// TODO: parse package-lock.json and build component list
	return []model.SBOMComponent{}, nil
}

func detectPython(root string) ([]model.SBOMComponent, error) {
	for _, candidate := range []string{"requirements.txt", "Pipfile.lock", "poetry.lock"} {
		if _, err := os.Stat(filepath.Join(root, candidate)); err == nil {
			// TODO: parse candidate and build component list
			return []model.SBOMComponent{}, nil
		}
	}
	return nil, nil
}

func detectGo(root string) ([]model.SBOMComponent, error) {
	if _, err := os.Stat(filepath.Join(root, "go.mod")); os.IsNotExist(err) {
		return nil, nil
	}
	// TODO: run `go list -m -json all` and parse output
	return []model.SBOMComponent{}, nil
}

func detectRust(root string) ([]model.SBOMComponent, error) {
	if _, err := os.Stat(filepath.Join(root, "Cargo.lock")); os.IsNotExist(err) {
		return nil, nil
	}
	// TODO: parse Cargo.lock
	return []model.SBOMComponent{}, nil
}
