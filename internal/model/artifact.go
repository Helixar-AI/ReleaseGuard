package model

import "time"

// Artifact represents a single file within the scanned artifact tree.
type Artifact struct {
	Path         string            `json:"path"`
	SHA256       string            `json:"sha256"`
	Blake3       string            `json:"blake3,omitempty"`
	Size         int64             `json:"size"`
	MIME         string            `json:"mime"`
	Executable   bool              `json:"executable"`
	Kind         string            `json:"kind"` // file, symlink, dir
	Tags         []string          `json:"tags"` // frontend, binary, archive, script, config, debug, test, vendor
	ArchiveDepth int               `json:"archive_depth"`
	Timestamps   ArtifactTimestamp `json:"timestamps"`
}

// ArtifactTimestamp holds filesystem time metadata.
type ArtifactTimestamp struct {
	Modified time.Time `json:"modified"`
}
