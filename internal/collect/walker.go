package collect

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Helixar-AI/ReleaseGuard/internal/model"
)

const defaultMaxArchiveDepth = 3

// Walker walks a directory tree and builds an artifact inventory.
type Walker struct {
	MaxArchiveDepth int
	// ExcludeGlobs contains path prefixes (relative to root) that should be
	// skipped entirely. Trailing /** is stripped; prefix matching is used.
	ExcludeGlobs []string
}

// NewWalker returns a Walker with default settings.
func NewWalker() *Walker {
	return &Walker{MaxArchiveDepth: defaultMaxArchiveDepth}
}

// Walk traverses root and returns a slice of Artifact records.
func (w *Walker) Walk(root string) ([]model.Artifact, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("accessing path %q: %w", root, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("path %q is not a directory", root)
	}

	var artifacts []model.Artifact

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		// Normalise to forward slashes for consistent glob matching.
		rel = filepath.ToSlash(rel)

		if d.IsDir() {
			if rel != "." && w.isExcluded(rel) {
				return filepath.SkipDir
			}
			return nil
		}

		if w.isExcluded(rel) {
			return nil
		}

		artifact, err := w.buildArtifact(path, rel, 0)
		if err != nil {
			// Log and continue rather than aborting the whole walk.
			fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", path, err)
			return nil
		}

		artifacts = append(artifacts, artifact)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking %q: %w", root, err)
	}

	return artifacts, nil
}

// isExcluded returns true when rel matches any configured exclude glob.
func (w *Walker) isExcluded(rel string) bool {
	// Always skip VCS metadata directories — they are never part of a release artifact.
	if rel == ".git" || strings.HasPrefix(rel, ".git/") ||
		rel == ".hg" || strings.HasPrefix(rel, ".hg/") ||
		rel == ".svn" || strings.HasPrefix(rel, ".svn/") {
		return true
	}
	for _, ex := range w.ExcludeGlobs {
		// Normalise: strip trailing /** or /
		ex = strings.TrimSuffix(ex, "/**")
		ex = strings.TrimSuffix(ex, "/")
		ex = filepath.ToSlash(ex)
		if rel == ex || strings.HasPrefix(rel, ex+"/") {
			return true
		}
		if matched, _ := filepath.Match(ex, rel); matched {
			return true
		}
	}
	return false
}

func (w *Walker) buildArtifact(absPath, relPath string, depth int) (model.Artifact, error) {
	info, err := os.Stat(absPath)
	if err != nil {
		return model.Artifact{}, err
	}

	sha256, err := SHA256File(absPath)
	if err != nil {
		return model.Artifact{}, err
	}

	mime := DetectMIME(absPath)
	tags := Classify(relPath, mime, info)

	artifact := model.Artifact{
		Path:         relPath,
		SHA256:       sha256,
		Size:         info.Size(),
		MIME:         mime,
		Executable:   isExecutable(info),
		Kind:         "file",
		Tags:         tags,
		ArchiveDepth: depth,
		Timestamps: model.ArtifactTimestamp{
			Modified: info.ModTime(),
		},
	}

	return artifact, nil
}

func isExecutable(info fs.FileInfo) bool {
	return info.Mode()&0111 != 0
}
