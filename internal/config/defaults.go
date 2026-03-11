package config

// DefaultConfig returns a Config populated with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Version: 2,
		Project: ProjectConfig{
			Name: "my-app",
			Mode: "release",
		},
		Inputs: []InputConfig{
			{Path: "./dist", Type: "directory"},
		},
		SBOM: SBOMConfig{
			Enabled:         true,
			Ecosystems:      []string{"node", "python", "go", "rust", "java", "dotnet"},
			Formats:         []string{"cyclonedx"},
			EnrichCVE:       false,
			FailOnCVSSAbove: 9.0,
			AllowedLicenses: []string{"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"},
		},
		Scanning: ScanConfig{
			Secrets: SecretsConfig{Enabled: true},
			Metadata: MetadataConfig{
				Enabled:            true,
				FailOnSourceMaps:   true,
				FailOnInternalURLs: true,
				FailOnBuildPaths:   false,
			},
			UnexpectedFiles: UnexpectedConfig{
				Enabled: true,
				Deny: []string{
					".env", ".env.*", "*.map", ".git/**",
					"*.bak", "*.swp", "*.tmp", "node_modules/**",
				},
			},
			Licenses: LicenseConfig{
				Enabled: true,
				Require: []string{"LICENSE"},
			},
		},
		Transforms: TransformConfig{
			RemoveSourceMaps:     true,
			DeleteForbiddenFiles: true,
			StripDebugInfo:       false,
			AddChecksums:         true,
			AddManifest:          true,
			NormalizeTimestamps:  true,
		},
		Obfuscation: ObfuscationConfig{
			Enabled: false,
			Level:   "light",
			Targets: ObfuscationTargets{
				JS:     JSObfuscation{StringEncrypt: true, PropertyMangle: true, ControlFlowFlatten: false},
				Go:     GoObfuscation{StripSymbols: true, RedactPaths: true, UseGarble: false},
				Python: PythonObfuscation{StripSource: true, UsePyArmor: false},
				JVM:    JVMObfuscation{RenameSymbols: false, ControlFlow: false},
				DotNet: DotNetObfuscation{StripPDBRefs: true},
				Native: NativeObfuscation{StripDebug: true, StripSymbols: true},
			},
		},
		DRM: DRMConfig{
			Enabled: false,
			IntegrityCheck: IntegrityConfig{
				Enabled:  false,
				OnTamper: "exit",
			},
			AntiDebug: AntiDebugConfig{Enabled: false},
		},
		Signing: SigningConfig{
			Enabled: false,
			Mode:    "keyless",
			Subject: "releaseguard-ci",
		},
		Attestations: AttestConfig{
			Enabled:    false,
			Provenance: true,
			Evidence:   true,
			SBOM:       true,
		},
		Policy: PolicyConfig{
			FailOn: []PolicyGate{
				{Severity: "critical"},
				{Severity: "high"},
				{Category: "secret"},
			},
			WarnOn: []PolicyGate{
				{Category: "missing_notice"},
			},
			RequireSBOM:           false,
			RequireObfuscation:    "none",
			RequireIntegrityCheck: false,
		},
		Packaging: PackagingConfig{
			Enabled:             false,
			Format:              "tar.gz",
			NormalizeTimestamps: true,
		},
		Output: OutputConfig{
			Reports:   []string{"cli", "json"},
			Directory: "./.releaseguard",
		},
	}
}
