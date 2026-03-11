package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/Helixar-AI/ReleaseGuard/internal/app"
)

var (
	cfgFile string
	version = "dev"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "releaseguard",
		Short: "The artifact policy engine for dist/ and release/ outputs",
		Long: `ReleaseGuard is an open-source artifact policy engine that hardens dist/ and
release/ artifacts before they ship. It scans build outputs, applies deterministic
hardening rules, signs and attests the final artifacts, and validates them against
release policies locally or in CI/CD.

Learn more: https://github.com/Helixar-AI/ReleaseGuard`,
		Version: version,
	}

	root.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: .releaseguard.yml)")
	root.PersistentFlags().Bool("verbose", false, "enable verbose output")
	root.PersistentFlags().Bool("no-color", false, "disable color output")

	cobra.OnInitialize(func() { initConfig(cfgFile) })

	root.AddCommand(
		newInitCmd(),
		newCheckCmd(),
		newFixCmd(),
		newSBOMCmd(),
		newObfuscateCmd(),
		newHardenCmd(),
		newPackCmd(),
		newSignCmd(),
		newAttestCmd(),
		newVerifyCmd(),
		newReportCmd(),
		newVexCmd(),
	)

	return root
}

func initConfig(cfgFile string) {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath(".")
		viper.SetConfigName(".releaseguard")
		viper.SetConfigType("yml")
	}
	viper.AutomaticEnv()
	_ = viper.ReadInConfig()
}

// releaseguard init
func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Bootstrap a .releaseguard.yml config in the current directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.Init()
		},
	}
}

// releaseguard check <path>
func newCheckCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check <path>",
		Short: "Scan artifact path and evaluate release policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, _ := cmd.Flags().GetString("format")
			out, _ := cmd.Flags().GetString("out")
			return app.Check(args[0], format, out)
		},
	}
	cmd.Flags().String("format", "cli", "output format: cli, json, sarif, markdown, html")
	cmd.Flags().String("out", "", "write output to file instead of stdout")
	return cmd
}

// releaseguard fix <path>
func newFixCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fix <path>",
		Short: "Apply safe deterministic hardening transforms to artifact path",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dryRun, _ := cmd.Flags().GetBool("dry-run")
			return app.Fix(args[0], dryRun)
		},
	}
	cmd.Flags().Bool("dry-run", false, "preview transforms without applying them")
	return cmd
}

// releaseguard sbom <path>
func newSBOMCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sbom <path>",
		Short: "Generate a Software Bill of Materials for the artifact",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, _ := cmd.Flags().GetString("format")
			out, _ := cmd.Flags().GetString("out")
			enrichCVE, _ := cmd.Flags().GetBool("enrich-cve")
			return app.SBOM(args[0], format, out, enrichCVE)
		},
	}
	cmd.Flags().String("format", "cyclonedx", "output format: cyclonedx, spdx")
	cmd.Flags().String("out", "", "write SBOM to file (default: .releaseguard/sbom.cdx.json)")
	cmd.Flags().Bool("enrich-cve", false, "enrich SBOM with VEX data from OSV.dev")
	return cmd
}

// releaseguard obfuscate <path>
func newObfuscateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "obfuscate <path>",
		Short: "Apply obfuscation suite to artifact path",
		Long: `Apply obfuscation to release artifacts.

Available levels:
  none    - no obfuscation applied
  light   - symbol strip, string encrypt, basic mangling (OSS)
  medium  - + control flow flatten, bytecode transform (Cloud)
  aggressive - + opaque predicates, LLVM passes (Cloud)

Upgrade to ReleaseGuard Cloud for medium and aggressive levels.
https://releaseguard.dev/cloud`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			level, _ := cmd.Flags().GetString("level")
			dryRun, _ := cmd.Flags().GetBool("dry-run")
			return app.Obfuscate(args[0], level, dryRun)
		},
	}
	cmd.Flags().String("level", "light", "obfuscation level: none, light, medium, aggressive")
	cmd.Flags().Bool("dry-run", false, "preview without applying")
	return cmd
}

// releaseguard harden <path>
func newHardenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "harden <path>",
		Short: "Full hardening: fix + obfuscate + DRM injection",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			level, _ := cmd.Flags().GetString("obfuscation")
			dryRun, _ := cmd.Flags().GetBool("dry-run")
			return app.Harden(args[0], level, dryRun)
		},
	}
	cmd.Flags().String("obfuscation", "light", "obfuscation level: none, light, medium, aggressive")
	cmd.Flags().Bool("dry-run", false, "preview without applying")
	return cmd
}

// releaseguard pack <path>
func newPackCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pack <path>",
		Short: "Package artifact into a canonical archive",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out, _ := cmd.Flags().GetString("out")
			format, _ := cmd.Flags().GetString("format")
			return app.Pack(args[0], out, format)
		},
	}
	cmd.Flags().String("out", "", "output archive path (required)")
	cmd.Flags().String("format", "tar.gz", "archive format: tar.gz, zip")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

// releaseguard sign <artifact>
func newSignCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign <artifact>",
		Short: "Sign artifact and evidence bundle",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			mode, _ := cmd.Flags().GetString("mode")
			keyFile, _ := cmd.Flags().GetString("key")
			return app.Sign(args[0], mode, keyFile)
		},
	}
	cmd.Flags().String("mode", "keyless", "signing mode: keyless, local")
	cmd.Flags().String("key", "", "path to private key file (local mode only)")
	return cmd
}

// releaseguard attest <artifact>
func newAttestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attest <artifact>",
		Short: "Emit in-toto and SLSA provenance attestations",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.Attest(args[0])
		},
	}
	return cmd
}

// releaseguard verify <artifact>
func newVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify <artifact>",
		Short: "Verify artifact signatures and policy compliance",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.Verify(args[0])
		},
	}
	return cmd
}

// releaseguard report <path>
func newReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report <path>",
		Short: "Export scan report in specified format",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, _ := cmd.Flags().GetString("format")
			out, _ := cmd.Flags().GetString("out")
			return app.Report(args[0], format, out)
		},
	}
	cmd.Flags().String("format", "json", "output format: cli, json, sarif, markdown, html")
	cmd.Flags().String("out", "", "write report to file instead of stdout")
	return cmd
}

// releaseguard vex <path>
func newVexCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vex <path>",
		Short: "Enrich SBOM with VEX vulnerability exploitability data",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sbomFile, _ := cmd.Flags().GetString("sbom")
			out, _ := cmd.Flags().GetString("out")
			return app.VEX(args[0], sbomFile, out)
		},
	}
	cmd.Flags().String("sbom", "", "path to existing SBOM file to enrich")
	cmd.Flags().String("out", "", "output path for enriched VEX data")
	return cmd
}

// Ensure unused import doesn't fail build during scaffold phase.
var _ = fmt.Sprintf
