package model

import "time"

// Manifest is the canonical inventory of an artifact tree produced by the collector.
type Manifest struct {
	Version     string     `json:"version"`
	GeneratedAt time.Time  `json:"generated_at"`
	InputPath   string     `json:"input_path"`
	TotalFiles  int        `json:"total_files"`
	TotalBytes  int64      `json:"total_bytes"`
	Artifacts   []Artifact `json:"artifacts"`
}
