# ReleaseGuard

> **The artifact policy engine for `dist/` and `release/` outputs.**

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
curl -sSfL https://github.com/Helixar-AI/ReleaseGuard/releases/latest/download/install.sh | sh

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

## GitHub Action

```yaml
- uses: Helixar-AI/ReleaseGuard@v1
  with:
    path: ./dist
    sbom: true
    fix: true
    sign: keyless
    format: sarif
```

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
