package scan

import (
	"fmt"
	"path/filepath"

	"github.com/Helixar-AI/ReleaseGuard/internal/config"
	"github.com/Helixar-AI/ReleaseGuard/internal/model"
)

// FileSizeScanner detects individual files and total artifact bundles that exceed
// configurable size thresholds.
type FileSizeScanner struct{}

func (s *FileSizeScanner) Name() string { return "filesize" }

func (s *FileSizeScanner) Scan(root string, artifacts []model.Artifact, cfg *config.Config) ([]model.Finding, error) {
	fsCfg := cfg.Scanning.FileSize
	var findings []model.Finding
	var totalBytes int64

	for _, a := range artifacts {
		if a.Kind != "file" {
			continue
		}

		totalBytes += a.Size

		limit := fsCfg.MaxFileBytes
		if override, ok := fsCfg.PerExtension[filepath.Ext(a.Path)]; ok {
			limit = override
		}

		if a.Size > limit {
			findings = append(findings, model.Finding{
				ID:             "RG-SIZE-001",
				Category:       model.CategoryFileSize,
				Severity:       model.SeverityMedium,
				Path:           a.Path,
				Message:        fmt.Sprintf("File exceeds size limit: %s > %s", humanBytes(a.Size), humanBytes(limit)),
				Evidence:       fmt.Sprintf("size=%d bytes, limit=%d bytes", a.Size, limit),
				Autofixable:    false,
				RecommendedFix: "Exclude this file from the release artifact or reduce its size.",
			})
		}
	}

	if totalBytes > fsCfg.MaxTotalBytes {
		findings = append(findings, model.Finding{
			ID:             "RG-SIZE-002",
			Category:       model.CategoryFileSize,
			Severity:       model.SeverityHigh,
			Path:           ".",
			Message:        fmt.Sprintf("Total artifact bundle exceeds size limit: %s > %s", humanBytes(totalBytes), humanBytes(fsCfg.MaxTotalBytes)),
			Evidence:       fmt.Sprintf("total=%d bytes, limit=%d bytes", totalBytes, fsCfg.MaxTotalBytes),
			Autofixable:    false,
			RecommendedFix: "Review and remove large or unnecessary files from the release bundle.",
		})
	}

	return findings, nil
}

// humanBytes returns a human-readable representation of a byte count.
func humanBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
