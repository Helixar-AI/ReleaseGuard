package app

import (
	"fmt"

	"github.com/Helixar-AI/ReleaseGuard/internal/config"
	"github.com/Helixar-AI/ReleaseGuard/internal/sbom"
)

// SBOM generates a Software Bill of Materials for path.
func SBOM(path, format, out string, enrichCVE bool) error {
	cfg, err := config.Load("")
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if out == "" {
		switch format {
		case "spdx":
			out = cfg.Output.Directory + "/sbom.spdx.json"
		default:
			out = cfg.Output.Directory + "/sbom.cdx.json"
		}
	}

	if err := config.EnsureEvidenceDir(cfg.Output.Directory); err != nil {
		return err
	}

	fmt.Printf("releaseguard sbom %s [format=%s]\n\n", path, format)

	engine := sbom.NewEngine(cfg)
	bill, err := engine.Generate(path)
	if err != nil {
		return fmt.Errorf("generating SBOM: %w", err)
	}

	if enrichCVE {
		fmt.Println("  Enriching with VEX data from OSV.dev...")
		if err := engine.EnrichCVE(bill); err != nil {
			fmt.Printf("  Warning: CVE enrichment failed: %v\n", err)
		}
	}

	if err := engine.Write(bill, format, out); err != nil {
		return fmt.Errorf("writing SBOM: %w", err)
	}

	fmt.Printf("  %d components found\n", bill.Total)
	fmt.Printf("  SBOM written to %s\n", out)
	return nil
}
