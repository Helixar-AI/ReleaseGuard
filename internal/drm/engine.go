package drm

import (
	"fmt"
	"time"

	"github.com/Helixar-AI/ReleaseGuard/internal/config"
	"github.com/Helixar-AI/ReleaseGuard/internal/model"
)

// Engine injects DRM runtime stubs into release artifacts.
type Engine struct {
	cfg    *config.Config
	dryRun bool
}

// NewEngine returns an Engine configured from cfg.
func NewEngine(cfg *config.Config, dryRun bool) *Engine {
	return &Engine{cfg: cfg, dryRun: dryRun}
}

// Run injects configured stubs and returns the DRM manifest.
func (e *Engine) Run(root string, artifacts []model.Artifact) (*model.DRMManifest, error) {
	manifest := &model.DRMManifest{
		GeneratedAt: time.Now().UTC(),
		InputPath:   root,
	}

	if !e.cfg.DRM.Enabled {
		return manifest, nil
	}

	if e.cfg.DRM.IntegrityCheck.Enabled {
		stubs, err := e.injectIntegrityStubs(root, artifacts)
		if err != nil {
			return manifest, fmt.Errorf("integrity stub injection: %w", err)
		}
		manifest.Stubs = append(manifest.Stubs, stubs...)
	}

	if e.cfg.DRM.AntiDebug.Enabled {
		stubs, err := e.injectAntiDebugStubs(root, artifacts)
		if err != nil {
			return manifest, fmt.Errorf("anti-debug stub injection: %w", err)
		}
		manifest.Stubs = append(manifest.Stubs, stubs...)
	}

	return manifest, nil
}

func (e *Engine) injectIntegrityStubs(root string, artifacts []model.Artifact) ([]model.DRMStub, error) {
	var stubs []model.DRMStub
	// TODO: Phase 10 — detect JS entry points and inject integrity-check.js stub
	// TODO: Phase 10 — detect Go binaries and inject go/integrity.go.tmpl
	fmt.Printf("  Integrity check stub injection: planned for Phase 10\n")
	return stubs, nil
}

func (e *Engine) injectAntiDebugStubs(root string, artifacts []model.Artifact) ([]model.DRMStub, error) {
	var stubs []model.DRMStub
	// TODO: Phase 11
	return stubs, nil
}
