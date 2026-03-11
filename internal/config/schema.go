package config

// Config is the top-level structure for .releaseguard.yml.
type Config struct {
	Version   int            `mapstructure:"version"   yaml:"version"`
	Project   ProjectConfig  `mapstructure:"project"   yaml:"project"`
	Inputs    []InputConfig  `mapstructure:"inputs"    yaml:"inputs"`
	SBOM      SBOMConfig     `mapstructure:"sbom"      yaml:"sbom"`
	Scanning  ScanConfig     `mapstructure:"scanning"  yaml:"scanning"`
	Transforms TransformConfig `mapstructure:"transforms" yaml:"transforms"`
	Obfuscation ObfuscationConfig `mapstructure:"obfuscation" yaml:"obfuscation"`
	DRM       DRMConfig      `mapstructure:"drm"       yaml:"drm"`
	Signing   SigningConfig  `mapstructure:"signing"   yaml:"signing"`
	Attestations AttestConfig `mapstructure:"attestations" yaml:"attestations"`
	Policy    PolicyConfig   `mapstructure:"policy"    yaml:"policy"`
	Packaging PackagingConfig `mapstructure:"packaging" yaml:"packaging"`
	Output    OutputConfig   `mapstructure:"output"    yaml:"output"`
}

type ProjectConfig struct {
	Name string `mapstructure:"name" yaml:"name"`
	Mode string `mapstructure:"mode" yaml:"mode"` // release, staging
}

type InputConfig struct {
	Path string `mapstructure:"path" yaml:"path"`
	Type string `mapstructure:"type" yaml:"type"` // directory, archive
}

type SBOMConfig struct {
	Enabled          bool     `mapstructure:"enabled"             yaml:"enabled"`
	Ecosystems       []string `mapstructure:"ecosystems"          yaml:"ecosystems"`
	Formats          []string `mapstructure:"formats"             yaml:"formats"`
	EnrichCVE        bool     `mapstructure:"enrich_cve"          yaml:"enrich_cve"`
	FailOnCVSSAbove  float64  `mapstructure:"fail_on_cvss_above"  yaml:"fail_on_cvss_above"`
	AllowedLicenses  []string `mapstructure:"allowed_licenses"    yaml:"allowed_licenses"`
}

type ScanConfig struct {
	// ExcludePaths lists path prefixes (relative to scan root) to skip entirely.
	// Trailing /** is accepted but not required. Example: ["test/fixtures", "vendor"]
	ExcludePaths    []string         `mapstructure:"exclude_paths"    yaml:"exclude_paths,omitempty"`
	Secrets         SecretsConfig    `mapstructure:"secrets"          yaml:"secrets"`
	Metadata        MetadataConfig   `mapstructure:"metadata"         yaml:"metadata"`
	UnexpectedFiles UnexpectedConfig `mapstructure:"unexpected_files" yaml:"unexpected_files"`
	Licenses        LicenseConfig    `mapstructure:"licenses"         yaml:"licenses"`
}

type SecretsConfig struct {
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
}

type MetadataConfig struct {
	Enabled             bool `mapstructure:"enabled"               yaml:"enabled"`
	FailOnSourceMaps    bool `mapstructure:"fail_on_source_maps"   yaml:"fail_on_source_maps"`
	FailOnInternalURLs  bool `mapstructure:"fail_on_internal_urls" yaml:"fail_on_internal_urls"`
	FailOnBuildPaths    bool `mapstructure:"fail_on_build_paths"   yaml:"fail_on_build_paths"`
}

type UnexpectedConfig struct {
	Enabled bool     `mapstructure:"enabled" yaml:"enabled"`
	Deny    []string `mapstructure:"deny"    yaml:"deny"`
}

type LicenseConfig struct {
	Enabled bool     `mapstructure:"enabled" yaml:"enabled"`
	Require []string `mapstructure:"require" yaml:"require"`
}

type TransformConfig struct {
	RemoveSourceMaps     bool `mapstructure:"remove_source_maps"     yaml:"remove_source_maps"`
	DeleteForbiddenFiles bool `mapstructure:"delete_forbidden_files" yaml:"delete_forbidden_files"`
	StripDebugInfo       bool `mapstructure:"strip_debug_info"       yaml:"strip_debug_info"`
	AddChecksums         bool `mapstructure:"add_checksums"          yaml:"add_checksums"`
	AddManifest          bool `mapstructure:"add_manifest"           yaml:"add_manifest"`
	NormalizeTimestamps  bool `mapstructure:"normalize_timestamps"   yaml:"normalize_timestamps"`
}

type ObfuscationConfig struct {
	Enabled bool               `mapstructure:"enabled" yaml:"enabled"`
	Level   string             `mapstructure:"level"   yaml:"level"` // none, light, medium, aggressive
	Targets ObfuscationTargets `mapstructure:"targets" yaml:"targets"`
}

type ObfuscationTargets struct {
	JS     JSObfuscation     `mapstructure:"js"     yaml:"js"`
	Go     GoObfuscation     `mapstructure:"go"     yaml:"go"`
	Python PythonObfuscation `mapstructure:"python" yaml:"python"`
	JVM    JVMObfuscation    `mapstructure:"jvm"    yaml:"jvm"`
	DotNet DotNetObfuscation `mapstructure:"dotnet" yaml:"dotnet"`
	Native NativeObfuscation `mapstructure:"native" yaml:"native"`
}

type JSObfuscation struct {
	StringEncrypt       bool `mapstructure:"string_encrypt"        yaml:"string_encrypt"`
	PropertyMangle      bool `mapstructure:"property_mangle"       yaml:"property_mangle"`
	ControlFlowFlatten  bool `mapstructure:"control_flow_flatten"  yaml:"control_flow_flatten"`
}

type GoObfuscation struct {
	StripSymbols bool `mapstructure:"strip_symbols" yaml:"strip_symbols"`
	RedactPaths  bool `mapstructure:"redact_paths"  yaml:"redact_paths"`
	UseGarble    bool `mapstructure:"use_garble"    yaml:"use_garble"`
}

type PythonObfuscation struct {
	StripSource  bool `mapstructure:"strip_source"  yaml:"strip_source"`
	UsePyArmor   bool `mapstructure:"use_pyarmor"   yaml:"use_pyarmor"`
}

type JVMObfuscation struct {
	RenameSymbols bool `mapstructure:"rename_symbols" yaml:"rename_symbols"`
	ControlFlow   bool `mapstructure:"control_flow"   yaml:"control_flow"`
}

type DotNetObfuscation struct {
	StripPDBRefs bool `mapstructure:"strip_pdb_refs" yaml:"strip_pdb_refs"`
}

type NativeObfuscation struct {
	StripDebug   bool `mapstructure:"strip_debug"   yaml:"strip_debug"`
	StripSymbols bool `mapstructure:"strip_symbols" yaml:"strip_symbols"`
}

type DRMConfig struct {
	Enabled        bool            `mapstructure:"enabled"         yaml:"enabled"`
	IntegrityCheck IntegrityConfig `mapstructure:"integrity_check" yaml:"integrity_check"`
	AntiDebug      AntiDebugConfig `mapstructure:"anti_debug"      yaml:"anti_debug"`
}

type IntegrityConfig struct {
	Enabled  bool   `mapstructure:"enabled"   yaml:"enabled"`
	OnTamper string `mapstructure:"on_tamper" yaml:"on_tamper"` // exit, log
}

type AntiDebugConfig struct {
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
}

type SigningConfig struct {
	Enabled bool   `mapstructure:"enabled" yaml:"enabled"`
	Mode    string `mapstructure:"mode"    yaml:"mode"` // keyless, local
	Subject string `mapstructure:"subject" yaml:"subject"`
	KeyFile string `mapstructure:"key_file" yaml:"key_file"`
}

type AttestConfig struct {
	Enabled    bool `mapstructure:"enabled"    yaml:"enabled"`
	Provenance bool `mapstructure:"provenance" yaml:"provenance"`
	Evidence   bool `mapstructure:"evidence"   yaml:"evidence"`
	SBOM       bool `mapstructure:"sbom"       yaml:"sbom"`
}

type PolicyConfig struct {
	FailOn                []PolicyGate `mapstructure:"fail_on"                  yaml:"fail_on"`
	WarnOn                []PolicyGate `mapstructure:"warn_on"                  yaml:"warn_on"`
	RequireSBOM           bool         `mapstructure:"require_sbom"             yaml:"require_sbom"`
	RequireObfuscation    string       `mapstructure:"require_obfuscation"      yaml:"require_obfuscation"`
	RequireIntegrityCheck bool         `mapstructure:"require_integrity_check"  yaml:"require_integrity_check"`
	// RegoBundle is an optional path to a directory or .rego file evaluated via the OPA CLI subprocess.
	RegoBundle string `mapstructure:"rego_bundle" yaml:"rego_bundle,omitempty"`
}

type PolicyGate struct {
	Severity string `mapstructure:"severity" yaml:"severity,omitempty"`
	Category string `mapstructure:"category" yaml:"category,omitempty"`
}

type PackagingConfig struct {
	Enabled             bool   `mapstructure:"enabled"              yaml:"enabled"`
	Format              string `mapstructure:"format"               yaml:"format"` // tar.gz, zip
	Output              string `mapstructure:"output"               yaml:"output"`
	NormalizeTimestamps bool   `mapstructure:"normalize_timestamps" yaml:"normalize_timestamps"`
}

type OutputConfig struct {
	Reports   []string `mapstructure:"reports"   yaml:"reports"`
	Directory string   `mapstructure:"directory" yaml:"directory"`
}
