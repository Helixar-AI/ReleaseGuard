package app

import (
	"fmt"

	"github.com/Helixar-AI/ReleaseGuard/internal/collect"
	"github.com/Helixar-AI/ReleaseGuard/internal/config"
	"github.com/Helixar-AI/ReleaseGuard/internal/transform"
)

// Fix applies safe deterministic hardening transforms to path.
func Fix(path string, dryRun bool) error {
	cfg, err := config.Load("")
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if err := config.EnsureEvidenceDir(cfg.Output.Directory); err != nil {
		return err
	}

	mode := "apply"
	if dryRun {
		mode = "dry-run"
	}
	fmt.Printf("releaseguard fix %s [%s]\n\n", path, mode)

	walker := collect.NewWalker()
	artifacts, err := walker.Walk(path)
	if err != nil {
		return fmt.Errorf("collecting artifacts: %w", err)
	}

	engine := transform.NewEngine(cfg, dryRun)
	transforms, err := engine.Run(path, artifacts)
	if err != nil {
		return fmt.Errorf("applying transforms: %w", err)
	}

	for _, t := range transforms {
		action := string(t.Action)
		if dryRun {
			action = "[dry-run] " + action
		}
		fmt.Printf("  %-12s %s\n", action, t.Path)
	}

	fmt.Printf("\n  %d transforms applied\n", len(transforms))
	return nil
}
