package policy

// BuiltinRules lists the names of all built-in policy rules.
// These are applied by the Evaluator via the config-driven gate system.
// For Rego-based built-ins, see rego_adapter.go.
var BuiltinRules = []string{
	"no_secrets",
	"no_source_maps",
	"no_unexpected_files",
	"require_license",
	"require_sbom",
	"require_signing",
	"require_obfuscation",
	"require_integrity_check",
}
