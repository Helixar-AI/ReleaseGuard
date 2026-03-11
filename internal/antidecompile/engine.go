package antidecompile

import (
	"github.com/Helixar-AI/ReleaseGuard/internal/config"
	"github.com/Helixar-AI/ReleaseGuard/internal/model"
)

// Engine applies decompilation resistance transforms to release artifacts.
type Engine struct {
	cfg    *config.Config
	dryRun bool
}

// Op describes a single decompilation-resistance operation.
type Op struct {
	Language string
	Type     string
	Path     string
}

// NewEngine returns an Engine configured from cfg.
func NewEngine(cfg *config.Config, dryRun bool) *Engine {
	return &Engine{cfg: cfg, dryRun: dryRun}
}

// Run applies decompilation resistance based on the obfuscation level in cfg.
// Light level is available in OSS. Medium/aggressive require Cloud.
func (e *Engine) Run(root string, artifacts []model.Artifact) ([]Op, error) {
	// TODO: Phase 12 — implement per-language decompilation resistance
	// JS: control flow flattening, opaque predicates (medium+)
	// Python: pyc-only release, PyArmor (basic)
	// JVM: reflection dispatch (light)
	// Native: section rename, padding
	return nil, nil
}
