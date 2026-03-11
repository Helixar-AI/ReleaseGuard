package obfuscate

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Helixar-AI/ReleaseGuard/internal/config"
	"github.com/Helixar-AI/ReleaseGuard/internal/model"
)

// Op describes a single obfuscation operation applied to a file.
type Op struct {
	Type string // e.g. js_string_encrypt, go_strip_symbols
	Path string
	Note string
}

// Engine drives the obfuscation pipeline.
type Engine struct {
	cfg    *config.Config
	dryRun bool
}

// NewEngine returns an Engine configured from cfg.
func NewEngine(cfg *config.Config, dryRun bool) *Engine {
	return &Engine{cfg: cfg, dryRun: dryRun}
}

// Run applies obfuscation operations to the artifact tree and returns the op log.
func (e *Engine) Run(root string, artifacts []model.Artifact) ([]Op, error) {
	level := e.cfg.Obfuscation.Level
	if level == "none" {
		return nil, nil
	}

	var ops []Op

	for _, a := range artifacts {
		absPath := filepath.Join(root, a.Path)
		ext := strings.ToLower(filepath.Ext(a.Path))

		switch ext {
		case ".js", ".mjs":
			newOps, err := e.obfuscateJS(absPath, a.Path, level)
			if err != nil {
				fmt.Printf("  warning: JS obfuscation skipped for %s: %v\n", a.Path, err)
				continue
			}
			ops = append(ops, newOps...)
		}
	}

	return ops, nil
}

func (e *Engine) obfuscateJS(absPath, relPath, level string) ([]Op, error) {
	var ops []Op
	targets := e.cfg.Obfuscation.Targets.JS

	if targets.StringEncrypt {
		ops = append(ops, Op{Type: "js_string_encrypt", Path: relPath})
		if !e.dryRun {
			// TODO: Phase 7 — call terser/acorn via subprocess
		}
	}

	if targets.PropertyMangle {
		ops = append(ops, Op{Type: "js_property_mangle", Path: relPath})
		if !e.dryRun {
			// TODO: Phase 7
		}
	}

	if targets.ControlFlowFlatten && (level == "medium" || level == "aggressive") {
		ops = append(ops, Op{
			Type: "js_control_flow_flatten",
			Path: relPath,
			Note: "medium+ level — Cloud only",
		})
	}

	return ops, nil
}
