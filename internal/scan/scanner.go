package scan

import (
	"github.com/Helixar-AI/ReleaseGuard/internal/config"
	"github.com/Helixar-AI/ReleaseGuard/internal/model"
)

// Scanner is the interface that all scanners must implement.
type Scanner interface {
	Name() string
	Scan(root string, artifacts []model.Artifact, cfg *config.Config) ([]model.Finding, error)
}

// Pipeline runs multiple scanners and aggregates their findings.
type Pipeline struct {
	scanners []Scanner
}

// NewPipeline returns a Pipeline configured from cfg.
func NewPipeline(cfg *config.Config) *Pipeline {
	p := &Pipeline{}

	if cfg.Scanning.Secrets.Enabled {
		p.scanners = append(p.scanners, &SecretsScanner{})
	}
	if cfg.Scanning.Metadata.Enabled {
		p.scanners = append(p.scanners, &MetadataScanner{})
	}
	if cfg.Scanning.UnexpectedFiles.Enabled {
		p.scanners = append(p.scanners, &UnexpectedScanner{})
	}
	if cfg.Scanning.Licenses.Enabled {
		p.scanners = append(p.scanners, &LicenseScanner{})
	}

	return p
}

// Run executes all scanners and returns the combined finding set.
func (p *Pipeline) Run(root string, artifacts []model.Artifact, cfg *config.Config) ([]model.Finding, error) {
	var all []model.Finding
	for _, s := range p.scanners {
		findings, err := s.Scan(root, artifacts, cfg)
		if err != nil {
			return all, err
		}
		all = append(all, findings...)
	}
	return all, nil
}
