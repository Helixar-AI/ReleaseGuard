package collect

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Helixar-AI/ReleaseGuard/internal/model"
)

const defaultMaxArchiveDepth = 3

// Walker walks a directory tree and builds an artifact inventory.
type Walker struct {
	MaxArchiveDepth int
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
		if d.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
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
