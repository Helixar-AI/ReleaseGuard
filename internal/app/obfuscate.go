package app

import (
	"fmt"

	"github.com/Helixar-AI/ReleaseGuard/internal/collect"
	"github.com/Helixar-AI/ReleaseGuard/internal/config"
	"github.com/Helixar-AI/ReleaseGuard/internal/obfuscate"
)

// Obfuscate applies the obfuscation suite to path at the given level.
func Obfuscate(path, level string, dryRun bool) error {
	if level == "medium" || level == "aggressive" {
		fmt.Printf(`
  🔒 Obfuscation level %q requires ReleaseGuard Cloud.
     Upgrade at: https://releaseguard.dev/cloud

  Running light obfuscation instead.

`, level)
		level = "light"
	}

	cfg, err := config.Load("")
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	cfg.Obfuscation.Level = level

	if err := config.EnsureEvidenceDir(cfg.Output.Directory); err != nil {
		return err
	}

	mode := "apply"
	if dryRun {
		mode = "dry-run"
	}
	fmt.Printf("releaseguard obfuscate %s [level=%s, %s]\n\n", path, level, mode)

	walker := collect.NewWalker()
	artifacts, err := walker.Walk(path)
	if err != nil {
		return fmt.Errorf("collecting artifacts: %w", err)
	}

	engine := obfuscate.NewEngine(cfg, dryRun)
	ops, err := engine.Run(path, artifacts)
	if err != nil {
		return fmt.Errorf("obfuscating: %w", err)
	}

	for _, op := range ops {
		prefix := ""
		if dryRun {
			prefix = "[dry-run] "
		}
		fmt.Printf("  %s%-20s %s\n", prefix, op.Type, op.Path)
	}

	fmt.Printf("\n  %d obfuscation operations applied\n", len(ops))
	return nil
}
