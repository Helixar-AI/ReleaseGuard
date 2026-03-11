package model

import "time"

// SBOMFormat defines the output format for SBOM generation.
type SBOMFormat string

const (
	SBOMFormatCycloneDX SBOMFormat = "cyclonedx"
	SBOMFormatSPDX      SBOMFormat = "spdx"
)

// SBOMComponent represents a single dependency in the SBOM.
type SBOMComponent struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	PackageURL  string   `json:"purl"`
	Licenses    []string `json:"licenses"`
	Ecosystem   string   `json:"ecosystem"` // node, python, go, rust, java, dotnet, ruby, php, system
	Hashes      []Hash   `json:"hashes,omitempty"`
	Description string   `json:"description,omitempty"`
	CVEs        []CVE    `json:"cves,omitempty"`
}

// Hash represents a cryptographic hash of a component.
type Hash struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// CVE represents a known vulnerability annotated on a component.
type CVE struct {
	ID          string  `json:"id"`
	CVSS        float64 `json:"cvss"`
	Description string  `json:"description"`
	Exploitable *bool   `json:"exploitable,omitempty"` // VEX: nil = unknown
	FixedIn     string  `json:"fixed_in,omitempty"`
}

// SBOM is the top-level Software Bill of Materials output.
type SBOM struct {
	Format      SBOMFormat      `json:"format"`
	Version     string          `json:"version"`
	GeneratedAt time.Time       `json:"generated_at"`
	InputPath   string          `json:"input_path"`
	Components  []SBOMComponent `json:"components"`
	Total       int             `json:"total"`
}
