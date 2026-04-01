# ReleaseGuard

> **The artifact policy engine for `dist/` and `release/` outputs.**

![ReleaseGuard — The Artifact Security Engine](docs/release-guard-banner.png)

ReleaseGuard is an open-source artifact security engine. It scans build outputs for risky content, applies deterministic hardening transforms, generates full SBOMs, signs and attests the final artifacts, and validates them against release policies — locally or in any CI/CD pipeline.

[![CI](https://github.com/Helixar-AI/ReleaseGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/Helixar-AI/ReleaseGuard/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/Helixar-AI/ReleaseGuard)](https://goreportcard.com/report/github.com/Helixar-AI/ReleaseGuard)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Why ReleaseGuard?

Most supply-chain security tools focus on source code, dependencies, containers, or runtime admission. ReleaseGuard focuses on the **final distributable** — the exact artifact that leaves your build system.

That means catching things that slip through everything else:
- Secret keys and API tokens embedded in `dist/` bundles
- Source maps accidentally shipped to production
- Debug symbols inside release binaries
- `.env` files and internal hostnames baked into builds
- Unsigned executables in packaged releases

---

## Quick Start

```bash
# Install (macOS / Linux)
curl -sSfL https://raw.githubusercontent.com/Helixar-AI/ReleaseGuard/main/scripts/install.sh | sh

# Or build from source
git clone https://github.com/Helixar-AI/ReleaseGuard
cd ReleaseGuard && make install

# Bootstrap config
releaseguard init

# Scan your dist folder
releaseguard check ./dist

# Apply safe hardening transforms
releaseguard fix ./dist

# Generate SBOM
releaseguard sbom ./dist

# Full hardening pipeline
releaseguard harden ./dist
```

---

## Core Commands

| Command | Description |
|---|---|
| `releaseguard init` | Bootstrap `.releaseguard.yml` |
| `releaseguard check <path>` | Scan artifact and evaluate policy |
| `releaseguard fix <path>` | Apply safe deterministic transforms |
| `releaseguard sbom <path>` | Generate Software Bill of Materials |
| `releaseguard obfuscate <path>` | Apply obfuscation suite |
| `releaseguard harden <path>` | Full: fix + obfuscate + DRM injection |
| `releaseguard pack <path>` | Package into canonical archive |
| `releaseguard sign <artifact>` | Sign artifact and evidence bundle |
| `releaseguard attest <artifact>` | Emit in-toto / SLSA attestations |
| `releaseguard verify <artifact>` | Verify signatures and policy |
| `releaseguard report <path>` | Export report (JSON, SARIF, HTML) |
| `releaseguard vex <path>` | Enrich SBOM with VEX data |

---

## What's Included (Free & Open Source)

### Scanning
- Secrets detection (API keys, private keys, tokens, `.env` files)
- Metadata leaks (source maps, debug symbols, build paths, internal URLs)
- Unexpected content (test files, `.git` remnants, CI configs)
- License and notice presence checker
- **File size limits** — per-file and total bundle thresholds to catch accidental large binaries or bloated bundles

### SBOM Generation
- **All major ecosystems**: Node.js, Python, Go, Rust, Java, .NET, Ruby, PHP, Container, System packages
- **Formats**: CycloneDX (JSON + XML), SPDX (JSON + tag-value)
- VEX enrichment via OSV.dev

### Hardening Transforms
- Remove source maps, strip debug info, delete forbidden files
- Normalize archive timestamps for reproducibility
- Add checksums and manifest

### Obfuscation (`light` level — free)
- JS: string encryption, property mangling
- Go: symbol stripping, build path redaction, garble integration
- Python: `.py` source removal, PyArmor integration
- JVM / .NET: symbol renaming, PDB stripping
- Native (ELF / Mach-O / PE): debug section and symbol stripping

### DRM and Anti-Tamper (free)
- Runtime integrity check stub injection (JS, Go, .NET, Python)
- Tamper detection with configurable `exit` or `log` action
- Anti-debug stubs (opt-in)

### Signing and Attestation
- Keyless signing via Sigstore / Fulcio
- Local key signing (GPG, ECDSA)
- in-toto attestation statements
- SLSA Provenance level 2

### Policy Engine
- Built-in YAML rules (severity gates, category gates, license checks)
- Open Policy Agent (Rego) adapter
- Policy bundle loading from local path or OCI registry

### Reporting
- CLI table, JSON, SARIF (GitHub Security tab), Markdown, HTML

---

## What's in ReleaseGuard Cloud

> 🔒 Advanced capabilities available in [ReleaseGuard Cloud](https://releaseguard.dev/cloud).

- **Obfuscation `medium` / `aggressive`** — control flow flattening, opaque predicates, LLVM passes
- **License enforcement server** — online, offline, time-bound, machine-fingerprinted
- **Managed DRM profiles** per language and ecosystem
- **Managed decompilation resistance** profiles
- **SLSA Provenance level 3** (hosted builder)
- **KMS signing** (AWS, GCP, Azure, HashiCorp Vault)
- **Org-wide policy registry** with inheritance
- **Waiver and release approval workflows**
- **Historical evidence store** and cross-repo dashboards
- **SBOM registry** with diff, CVE search, and vendor submission
- **SSO** (SAML / OIDC), compliance reports (SOC 2, ISO 27001, NTIA)

---

## Add to Your README

Show that your release is clean:

```markdown
[\![ReleaseGuard](https://img.shields.io/badge/releaseguard-passing-brightgreen?logo=shield&logoColor=white)](https://github.com/Helixar-AI/ReleaseGuard)
```

Renders as: [\![ReleaseGuard](https://img.shields.io/badge/releaseguard-passing-brightgreen?logo=shield&logoColor=white)](https://github.com/Helixar-AI/ReleaseGuard)

---

## GitHub Action

> **Always pin to a commit SHA** — mutable tags can be moved. Replace `<SHA>` with
> the SHA of the release you want, e.g. `229a90dff5a31d7805e5df43bb9230f9fe5ec75c` for v0.1.2.

```yaml
- uses: Helixar-AI/ReleaseGuard@<SHA>  # vX.Y.Z
  with:
    path: ./dist
    sbom: true
    fix: true
    sign: keyless
    format: sarif
```

**CLI flags reference** (for direct use of the `releaseguard` binary):

| Command | Key flags |
|---|---|
| `releaseguard check <path>` | `--format <cli\|json\|sarif\|markdown\|html>`, `--out <file>`, `--config <file>` |
| `releaseguard sbom <path>` | `--format <cyclonedx\|spdx>`, `--out <file>`, `--enrich-cve` |
| `releaseguard fix <path>` | `--dry-run` |
| `releaseguard obfuscate <path>` | `--level <none\|light\|medium\|aggressive>` |
| `releaseguard sign <artifact>` | `--mode <keyless\|local>`, `--key <file>` |

> **Note:** `--fail-on` is **not** a CLI flag. Severity gating (which findings
> fail the build) is configured in `.releaseguard.yml` under `policy.fail-on`.
> The `fail-on` input on the GitHub Action is documentation-only and does not
> pass any flag to the CLI.

---

## Use with OpenClaw

Install the ReleaseGuard skill from [ClawHub](https://github.com/openclaw/clawhub):

```bash
clawhub install releaseguard
```

Then just ask your agent in plain English:

> *"Scan my ./dist folder for secrets and misconfigs"*
> *"Generate an SBOM for this release"*
> *"Sign the artifact and attest provenance"*
> *"Run the full hardening pipeline on ./dist"*

The skill maps natural language to the full `releaseguard` CLI — check, fix, sbom, sign, attest, verify, report, and vex — and installs the binary automatically if it isn't present.

**Publish your own skill** — the source is at [`skills/releaseguard/SKILL.md`](skills/releaseguard/SKILL.md).

---

## Configuration

```yaml
# .releaseguard.yml
version: 2
project:
  name: my-app
scanning:
  secrets:
    enabled: true
  metadata:
    enabled: true
    fail_on_source_maps: true
  file_size:
    enabled: true
    max_file_bytes: 10485760    # 10 MiB per file
    max_total_bytes: 104857600  # 100 MiB total bundle
    per_extension:
      ".wasm": 52428800         # 50 MiB override for WebAssembly
transforms:
  remove_source_maps: true
  add_checksums: true
policy:
  fail_on:
    - severity: critical
    - category: secret
```

See [docs/config-schema.md](docs/config-schema.md) for the full schema reference.

---

## GitHub Issue Integration

ReleaseGuard can automatically create a GitHub issue when critical vulnerabilities are detected during a scan. This gives your team immediate visibility into what blocked the release and actionable remediation steps — without leaving GitHub.

### How It Works

1. ReleaseGuard scans your release artifacts as part of CI
2. A critical (or configured severity) vulnerability is found
3. The release build **fails**
4. ReleaseGuard automatically creates a GitHub issue with:
   - Full finding details (severity, category, file path, line number)
   - Evidence snippets for each finding
   - Recommended fixes and remediation guidance
   - Category-specific playbooks (e.g. secret rotation steps)
   - Whether the finding can be auto-fixed with `releaseguard fix`
5. Artifacts are dropped and CI reports failure

### Configuration

Add the `integrations.github_issues` section to your `.releaseguard.yml`:

```yaml
# .releaseguard.yml
version: 2
project:
  name: my-app

policy:
  fail_on:
    - severity: critical

integrations:
  github_issues:
    enabled: true
    severities:
      - critical       # Create issues for critical findings
      - high           # Optionally include high severity too
    labels:
      - security
      - releaseguard
    assignees:
      - your-github-username
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `enabled` | `bool` | Yes | Set to `true` to enable automatic issue creation |
| `severities` | `string[]` | Yes | Severity levels that trigger issue creation (e.g. `critical`, `high`, `medium`, `low`) |
| `labels` | `string[]` | No | Labels to apply to created issues |
| `assignees` | `string[]` | No | GitHub usernames to assign to created issues |

### Authentication

ReleaseGuard needs a GitHub token with `issues:write` permission on the target repository.

**In CI (GitHub Actions):**

```yaml
- uses: Helixar-AI/ReleaseGuard@<SHA>
  with:
    path: ./dist
  env:
    RELEASEGUARD_GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    RELEASEGUARD_REPO: ${{ github.repository }}
```

The built-in `GITHUB_TOKEN` works for creating issues in the same repository. For cross-repo issue creation, use a personal access token or GitHub App token with the appropriate permissions.

**Locally:**

```bash
export RELEASEGUARD_GITHUB_TOKEN="ghp_..."
export RELEASEGUARD_REPO="owner/repo"
releaseguard check ./dist
```

### Disabling Issue Creation

Set `enabled: false` in your config, or simply omit the `integrations.github_issues` section entirely:

```yaml
integrations:
  github_issues:
    enabled: false
```

> **Future roadmap:** Issue creation will be extensible to other systems (Jira, Linear, etc.) via the `integrations` config block.

---

## Documentation

- [Architecture](docs/architecture.md)
- [Policy Model](docs/policy-model.md)
- [Config Schema](docs/config-schema.md)
- [SBOM](docs/sbom.md)
- [Signing](docs/signing.md)
- [Obfuscation](docs/obfuscation.md)
- [DRM](docs/drm.md)

---

## Contributing

```bash
git clone https://github.com/Helixar-AI/ReleaseGuard
cd ReleaseGuard
make dev-setup
make test
make build
```

Issues and PRs are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT — see [LICENSE](LICENSE).

---

> Built by [Helixar AI](https://helixar.ai) · [ReleaseGuard Cloud →](https://releaseguard.dev/cloud)
