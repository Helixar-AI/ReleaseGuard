package transform

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

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

	// Generate manifest.json inventory
	if tcfg.AddManifest {
		if err := e.writeManifest(root, artifacts); err != nil {
			return transforms, fmt.Errorf("writing manifest: %w", err)
		}
		transforms = append(transforms, model.Transform{
			ID:     e.nextID(),
			Action: model.ActionAdd,
			Path:   "manifest.json",
			Reason: "add_manifest",
		})
	}

	return transforms, nil
}

// manifestEntry is a single file record in manifest.json.
type manifestEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	MIME   string `json:"mime"`
}

// manifestFile is the top-level structure for manifest.json.
type manifestFile struct {
	Version     string          `json:"version"`
	GeneratedAt string          `json:"generated_at"`
	TotalFiles  int             `json:"total_files"`
	TotalBytes  int64           `json:"total_bytes"`
	Files       []manifestEntry `json:"files"`
}

func (e *Engine) writeManifest(root string, artifacts []model.Artifact) error {
	if e.dryRun {
		return nil
	}
	mf := manifestFile{
		Version:     "1",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		TotalFiles:  len(artifacts),
	}
	for _, a := range artifacts {
		mf.TotalBytes += a.Size
		mf.Files = append(mf.Files, manifestEntry{
			Path:   a.Path,
			SHA256: a.SHA256,
			Size:   a.Size,
			MIME:   a.MIME,
		})
	}
	data, err := json.MarshalIndent(mf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "manifest.json"), data, 0644)
}

func (e *Engine) deleteFile(absPath, relPath, beforeSHA, reason string) (model.Transform, error) {
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
