package transform

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Helixar-AI/ReleaseGuard/internal/collect"
	"github.com/Helixar-AI/ReleaseGuard/internal/config"
	"github.com/Helixar-AI/ReleaseGuard/internal/model"
)

// Engine applies deterministic hardening transforms to an artifact tree.
type Engine struct {
	cfg    *config.Config
	dryRun bool
	seq    int
}

// NewEngine returns an Engine configured from cfg.
func NewEngine(cfg *config.Config, dryRun bool) *Engine {
	return &Engine{cfg: cfg, dryRun: dryRun}
}

// Run applies all configured transforms and returns the transform log.
func (e *Engine) Run(root string, artifacts []model.Artifact) ([]model.Transform, error) {
	var transforms []model.Transform
	tcfg := e.cfg.Transforms

	for _, a := range artifacts {
		absPath := filepath.Join(root, a.Path)

		// Remove source maps
		if tcfg.RemoveSourceMaps && isSourceMap(a.Path) {
			t, err := e.deleteFile(absPath, a.Path, a.SHA256, "remove_source_maps")
			if err != nil {
				return transforms, err
			}
			transforms = append(transforms, t)
			continue
		}

		// Delete forbidden files
		if tcfg.DeleteForbiddenFiles && isForbidden(a.Path, e.cfg.Scanning.UnexpectedFiles.Deny) {
			t, err := e.deleteFile(absPath, a.Path, a.SHA256, "delete_forbidden_files")
			if err != nil {
				return transforms, err
			}
			transforms = append(transforms, t)
			continue
		}
	}

	// Add checksums file
	if tcfg.AddChecksums {
		if err := e.writeChecksums(root, artifacts); err != nil {
			return transforms, fmt.Errorf("writing checksums: %w", err)
		}
		transforms = append(transforms, model.Transform{
			ID:     e.nextID(),
			Action: model.ActionAdd,
			Path:   "checksums.sha256",
			Reason: "add_checksums",
		})
	}

	return transforms, nil
}

func (e *Engine) deleteFile(absPath, relPath, beforeSHA, reason string) (model.Transform, error) {
	e.seq++
	t := model.Transform{
		ID:        e.nextID(),
		Action:    model.ActionDelete,
		Path:      relPath,
		Reason:    reason,
		BeforeSHA: beforeSHA,
		AfterSHA:  nil,
		Staged:    e.dryRun,
	}
	if !e.dryRun {
		if err := os.Remove(absPath); err != nil && !os.IsNotExist(err) {
			return t, fmt.Errorf("deleting %s: %w", absPath, err)
		}
	}
	return t, nil
}

func (e *Engine) writeChecksums(root string, artifacts []model.Artifact) error {
	if e.dryRun {
		return nil
	}
	out := filepath.Join(root, "checksums.sha256")
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, a := range artifacts {
		fmt.Fprintf(f, "%s  %s\n", a.SHA256, a.Path)
	}
	return nil
}

func (e *Engine) nextID() string {
	e.seq++
	return fmt.Sprintf("RG-FIX-%03d", e.seq)
}

func isSourceMap(path string) bool {
	return strings.HasSuffix(path, ".map") ||
		strings.HasSuffix(path, ".js.map") ||
		strings.HasSuffix(path, ".css.map")
}

func isForbidden(path string, denyPatterns []string) bool {
	base := filepath.Base(path)
	for _, pattern := range denyPatterns {
		if matched, _ := filepath.Match(pattern, base); matched {
			return true
		}
		if matched, _ := filepath.Match(pattern, path); matched {
			return true
		}
	}
	return false
}

// Ensure collect is used indirectly via walker; import kept for hash reuse.
var _ = collect.SHA256Bytes
