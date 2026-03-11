# ReleaseGuard — Open Source Project Plan

> **The artifact policy engine that hardens `dist/` and `release/` outputs before they ship.**
>
> ReleaseGuard is free and open-source. It scans build artifacts for risky content, applies deterministic hardening transforms, generates full SBOMs, and verifies release policy in CI — locally or in any pipeline.
>
> Some advanced capabilities (managed policy registry, org dashboards, license enforcement server, waiver workflows) are available in **ReleaseGuard Cloud** — the commercial SaaS offering.

---

## Table of Contents

1. [Positioning](#1-positioning)
2. [What's Free vs Commercial](#2-whats-free-vs-commercial)
3. [Architecture](#3-architecture)
4. [Component Deep-Dives](#4-component-deep-dives)
5. [CLI Design](#5-cli-design)
6. [Config Schema](#6-config-schema)
7. [Internal Data Model](#7-internal-data-model)
8. [Repo Structure](#8-repo-structure)
9. [Tech Stack](#9-tech-stack)
10. [Implementation Phases](#10-implementation-phases)
11. [MVP Definition](#11-mvp-definition)
12. [Security and Ethics Notes](#12-security-and-ethics-notes)
13. [Contributing](#13-contributing)

---

## 1. Positioning

Most supply-chain tools focus on source code, dependencies, containers, or runtime admission. **ReleaseGuard focuses on the final distributable** — the exact artifact that leaves the build system.

That means:
- Desktop app bundles
- Tarballs and zip archives
- Compiled binaries
- Frontend `dist/` folders
- Install packages (`.deb`, `.rpm`, `.nupkg`, `.whl`)
- Signed release bundles

ReleaseGuard acts as the **last policy gate before launch**.

### Product Principles

| Principle | Description |
|---|---|
| **Artifact-first** | The artifact is the subject, not just the source repo |
| **Deterministic** | Transforms are repeatable and fully auditable |
| **Policy-driven** | Decisions are codified, testable, and reviewable |
| **Portable** | Works locally, in GitHub Actions, and in any CI/CD runner |
| **Verifiable** | Output includes evidence, attestations, and signatures |

---

## 2. What's Free vs Commercial

### Feature Matrix

> **Legend:** ✅ Free & open source | 🔒 ReleaseGuard Cloud (paid SaaS)

#### Scanning

| Feature | Free OSS | Cloud |
|---|---|---|
| Secrets scanner (API keys, tokens, private keys) | ✅ | ✅ |
| Metadata scanner (source maps, build paths, internal URLs) | ✅ | ✅ |
| Unexpected file scanner (.env, .git remnants, test files) | ✅ | ✅ |
| Policy-sensitive file scanner (unsigned exes, oversized files) | ✅ | ✅ |
| License and notice presence scanner | ✅ | ✅ |
| Custom scanner plugins | ✅ | ✅ |
| Centrally managed scan policies across repos | 🔒 | ✅ |
| Scan history and trend dashboards | 🔒 | ✅ |

#### SBOM Generation

| Feature | Free OSS | Cloud |
|---|---|---|
| Node.js / npm / yarn / pnpm | ✅ | ✅ |
| Python / pip / poetry / pipenv | ✅ | ✅ |
| Go modules | ✅ | ✅ |
| Rust / Cargo | ✅ | ✅ |
| Java / Maven / Gradle | ✅ | ✅ |
| .NET / NuGet | ✅ | ✅ |
| Ruby / Bundler | ✅ | ✅ |
| PHP / Composer | ✅ | ✅ |
| Container layers | ✅ | ✅ |
| System packages (.deb, .rpm) | ✅ | ✅ |
| CycloneDX output (JSON + XML) | ✅ | ✅ |
| SPDX output (JSON + tag-value) | ✅ | ✅ |
| VEX enrichment via OSV.dev | ✅ | ✅ |
| SBOM stored and queryable in central registry | 🔒 | ✅ |
| SBOM diff between releases | 🔒 | ✅ |
| Org-wide license compliance reporting | 🔒 | ✅ |
| Procurement-ready SBOM submission workflows | 🔒 | ✅ |

#### Hardening Transforms

| Feature | Free OSS | Cloud |
|---|---|---|
| Remove source maps | ✅ | ✅ |
| Delete forbidden files | ✅ | ✅ |
| Strip debug info | ✅ | ✅ |
| Normalize archive timestamps | ✅ | ✅ |
| Add manifest and checksums | ✅ | ✅ |
| Repackage into canonical archive | ✅ | ✅ |

#### Obfuscation Suite

| Feature | Free OSS | Cloud |
|---|---|---|
| JS string encryption | ✅ (light) | ✅ (all levels) |
| JS property mangling | ✅ (light) | ✅ (all levels) |
| JS control flow flattening | ✅ (light) | ✅ (medium / aggressive) |
| JS opaque predicates + dead code injection | 🔒 | ✅ |
| Go symbol stripping | ✅ | ✅ |
| Go build path redaction | ✅ | ✅ |
| Go garble integration | ✅ | ✅ |
| Python `.pyc` strip + path redact | ✅ | ✅ |
| Python PyArmor / Nuitka integration | ✅ (basic) | ✅ (managed profiles) |
| JVM bytecode rename + control flow | ✅ (light) | ✅ (all levels) |
| .NET assembly obfuscation | ✅ (light) | ✅ (all levels) |
| Native ELF / Mach-O / PE strip | ✅ | ✅ |
| Managed obfuscation profiles per ecosystem | 🔒 | ✅ |
| Obfuscation level: `none` / `light` | ✅ | ✅ |
| Obfuscation level: `medium` / `aggressive` | 🔒 | ✅ |

> **Note:** Obfuscation in the OSS tier is real and production-useful at `light` level. For teams that need heavier protection, Cloud unlocks `medium` and `aggressive` profiles with managed configuration.

#### DRM and Anti-Tamper

| Feature | Free OSS | Cloud |
|---|---|---|
| Runtime integrity check stub injection | ✅ | ✅ |
| Tamper detection (exit / log on tamper) | ✅ | ✅ |
| Anti-debug stubs (opt-in) | ✅ | ✅ |
| License enforcement stub injection | ✅ (basic) | ✅ |
| Online license validation server | 🔒 | ✅ |
| Offline license key validation | 🔒 | ✅ |
| Time-bound license enforcement | 🔒 | ✅ |
| Machine fingerprinting integration | 🔒 | ✅ |
| Tamper callback webhook management | 🔒 | ✅ |

#### Decompilation Resistance

| Feature | Free OSS | Cloud |
|---|---|---|
| JS control flow flattening | ✅ (light) | ✅ (aggressive) |
| JS dispatcher pattern | ✅ | ✅ |
| Python bytecode-only release (remove .py source) | ✅ | ✅ |
| JVM / .NET reflection dispatch injection | ✅ (light) | ✅ |
| Native section renaming + padding | ✅ | ✅ |
| LLVM obfuscation pass integration | 🔒 | ✅ |
| Managed per-language decompile-resistance profiles | 🔒 | ✅ |

#### Policy Engine

| Feature | Free OSS | Cloud |
|---|---|---|
| Built-in YAML policy rules | ✅ | ✅ |
| Pass / warn / fail / waive decisions | ✅ | ✅ |
| Open Policy Agent (Rego) adapter | ✅ | ✅ |
| Local policy bundle loading | ✅ | ✅ |
| Policy bundle from OCI registry | ✅ | ✅ |
| Managed policy registry (org-wide) | 🔒 | ✅ |
| Policy-as-code review workflows (PRs for policy changes) | 🔒 | ✅ |
| Waiver management and approval workflows | 🔒 | ✅ |
| Policy inheritance across repos | 🔒 | ✅ |

#### Signing and Attestation

| Feature | Free OSS | Cloud |
|---|---|---|
| Local key signing (GPG, ECDSA) | ✅ | ✅ |
| Keyless signing via Sigstore / Fulcio | ✅ | ✅ |
| Rekor transparency log integration | ✅ | ✅ |
| in-toto attestation statements | ✅ | ✅ |
| SLSA Provenance (level 2) | ✅ | ✅ |
| SLSA Provenance (level 3, hosted builder) | 🔒 | ✅ |
| AWS KMS / GCP KMS / HashiCorp Vault signing | 🔒 | ✅ |
| Org-wide key management and rotation | 🔒 | ✅ |

#### Reporting

| Feature | Free OSS | Cloud |
|---|---|---|
| CLI table output | ✅ | ✅ |
| JSON report | ✅ | ✅ |
| SARIF (GitHub Security tab) | ✅ | ✅ |
| Markdown summary | ✅ | ✅ |
| HTML report (self-contained) | ✅ | ✅ |
| Historical report storage and querying | 🔒 | ✅ |
| Cross-repo release health dashboard | 🔒 | ✅ |
| Executive compliance reports | 🔒 | ✅ |

#### CI/CD Integration

| Feature | Free OSS | Cloud |
|---|---|---|
| GitHub Action | ✅ | ✅ |
| GitLab CI template | ✅ | ✅ |
| Generic CI shell script | ✅ | ✅ |
| CI result reporting to Cloud dashboard | 🔒 | ✅ |
| Release approval gates via Cloud | 🔒 | ✅ |
| Org-wide CI policy enforcement | 🔒 | ✅ |

---

## 3. Architecture

```text
                  +-------------------------+
                  |   dist/ or release/     |
                  +----------+--------------+
                             |
                             v
                  +-------------------------+
                  |    Collector Engine     |
                  |  walk, hash, classify,  |
                  |  SBOM seed extraction   |
                  +----------+--------------+
                             |
        +--------------------+--------------------+
        |                    |                    |
        v                    v                    v
+---------------+   +----------------+   +------------------+
| Scanner       |   | SBOM Engine    |   | Hardening        |
| Pipeline      |   | (full multi-   |   | Pipeline         |
| secrets/meta/ |   |  ecosystem)    |   | obfuscate/DRM/   |
| unexpected/   |   |                |   | strip/transform  |
| licenses/     |   |                |   | anti-decompile   |
| policy-files  |   |                |   |                  |
+-------+-------+   +-------+--------+   +--------+---------+
        |                   |                     |
        +-------------------+---------------------+
                            |
                            v
                 +----------------------+
                 |   Evidence Builder   |
                 | manifest / findings  |
                 | SBOM / transform log |
                 | before/after digests |
                 +-----------+----------+
                             |
                             v
                 +----------------------+
                 |   Policy Evaluator   |
                 | YAML rules / Rego    |
                 | pass/warn/fail/waive |
                 +-----------+----------+
                             |
              +--------------+--------------+
              |                             |
              v                             v
  +----------------------+      +------------------------+
  |  Sign / Attest       |      |  Fail / Report         |
  |  artifact + evidence |      |  JSON/SARIF/MD/HTML    |
  |  SBOM + provenance   |      +------------------------+
  +-----------+----------+
              |
              v
  +--------------------------------+
  |   Verified Release Bundle      |
  |   artifact + manifest + sigs   |
  |   SBOM + attestations + report |
  +--------------------------------+
```

---

## 4. Component Deep-Dives

### 4.1 Collector Engine

Responsible for building a complete, normalized inventory of every file in the artifact.

**Capabilities:**
- Recursive directory walk
- Nested archive traversal (zip-in-tar, jar-in-war, etc.) with configurable depth limit
- Dual hashing: SHA-256 + Blake3
- MIME type detection via magic bytes (not file extension)
- File classification tagging: `frontend`, `binary`, `archive`, `script`, `config`, `debug`, `test`, `vendor`
- Executable bit detection
- Archive boundary detection (`.tar.gz`, `.zip`, `.jar`, `.whl`, `.nupkg`, `.deb`, `.rpm`, `.dmg`, `.AppImage`)

**Artifact record output:**
```json
{
  "path": "dist/assets/app.js",
  "sha256": "e3b0c44298fc...",
  "blake3": "af1349b9f5f9...",
  "size": 912331,
  "mime": "application/javascript",
  "executable": false,
  "kind": "file",
  "tags": ["frontend", "bundle"],
  "archive_depth": 0,
  "timestamps": {
    "modified": "2026-03-11T10:00:00Z"
  }
}
```

---

### 4.2 Scanner Pipeline

Modular scanners run against the collected artifact inventory.

#### Secrets Scanner
- Pattern library: AWS keys, GCP service accounts, GitHub tokens, npm tokens, private keys (RSA / EC / PGP), `.env` files, connection strings, JWT secrets, Stripe keys, Twilio SIDs
- Entropy-based detection for high-entropy string candidates
- Context-aware: ignores test fixtures when `test_mode: ignore` configured
- Severity: `critical` (private keys), `high` (API tokens), `medium` (env references)

#### Metadata Scanner
- Source maps (`.js.map`, `.css.map`)
- Debug symbols (`.pdb`, `.dSYM`, DWARF sections in ELF / Mach-O)
- Build machine paths embedded in binaries
- Internal hostnames, `localhost`, RFC1918 addresses in text and binary content
- Username / home directory strings from compilation
- Compiler version strings (policy-configurable)

#### Unexpected Content Scanner
- Test files, spec files, CI configs shipped accidentally
- `.git/` remnants
- Backup files (`.bak`, `.swp`, `~` suffixes), editor swap files
- `node_modules` inside a `dist/`
- Configurable deny glob list in `.releaseguard.yml`

#### Policy-Sensitive File Scanner
- Forbidden extensions per policy
- Oversized file detection (configurable threshold)
- Unsigned executables: PE (Authenticode), Mach-O (codesign), ELF (GPG detached sig)
- File count anomaly detection

#### License and Notice Scanner
- Presence / absence of `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES`
- Optional OSI-approved license text verification
- Cross-references SBOM license data for consistency

**Finding record output:**
```json
{
  "id": "RG-SEC-001",
  "category": "secret",
  "severity": "critical",
  "path": "dist/config.js",
  "message": "AWS access key detected",
  "evidence": "AKIA...",
  "autofixable": false,
  "recommended_fix": "Remove secret before build. Use environment variable injection at runtime."
}
```

---

### 4.3 SBOM Engine

Full Software Bill of Materials generation across all supported packaging ecosystems.

#### Supported Ecosystems

| Ecosystem | Manifest / lock files | Extraction method |
|---|---|---|
| Node.js | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | Parse lock file + `node_modules` traversal |
| Python | `requirements.txt`, `Pipfile.lock`, `pyproject.toml`, `poetry.lock` | Parse + wheel metadata inspection |
| Go | `go.mod`, `go.sum` | `go list -m -json all` + go.sum verification |
| Rust | `Cargo.toml`, `Cargo.lock` | Lock file parse + crate metadata |
| Java/JVM | `pom.xml`, `build.gradle`, `*.jar` manifest | JAR manifest + nested JAR walk |
| .NET | `*.csproj`, `packages.lock.json`, `*.nupkg` | NuGet metadata extraction |
| Ruby | `Gemfile.lock` | Gemfile parse |
| PHP | `composer.lock` | Composer parse |
| Container | `Dockerfile`, layer tarballs | Layer analysis |
| System packages | `.deb`, `.rpm` | Control/spec file extraction |

#### SBOM Output Formats
- **CycloneDX** (JSON + XML) — primary, recommended for supply-chain tooling
- **SPDX** (JSON + tag-value) — for regulatory compliance and NTIA submission

#### VEX Enrichment
- Calls OSV.dev API to annotate known CVEs against SBOM components
- Policy gate: `fail_on_cvss_above: 7.0`
- VEX statement output included in evidence bundle

---

### 4.4 Hardening Pipeline

#### Standard Transforms
- Remove source maps (`.js.map`, `.css.map`)
- Delete forbidden files (configurable glob list)
- Strip debug info from text artifacts
- Normalize archive timestamps for reproducibility
- Add `manifest.json` and `checksums.sha256` / `checksums.blake3`
- Repackage into canonical archive format

**Transform record:**
```json
{
  "id": "RG-FIX-004",
  "action": "delete",
  "path": "dist/assets/app.js.map",
  "reason": "remove_source_maps",
  "before_sha256": "e3b0c44298fc...",
  "after_sha256": null
}
```

#### Obfuscation Suite (OSS: `light` level)

**JavaScript / TypeScript**
- String literal encryption (XOR / AES with runtime key derivation)
- Property mangling via Terser integration
- Control flow flattening (basic dispatcher pattern)
- Identifier scrambling

**Go binaries**
- Symbol stripping (`-ldflags="-s -w"` or `objcopy` post-process)
- Build path redaction (replace absolute paths with `_/`)
- Garble integration (full source-level obfuscation, opt-in)

**Python**
- `.pyc` bytecode path hints stripped
- Source `.py` files excluded from release output
- PyArmor / Nuitka subprocess integration (when available in environment)

**JVM**
- Strip source attributes from class files
- Symbol renaming via ASM bytecode manipulation
- ProGuard / R8 subprocess integration

**.NET**
- PDB reference stripping
- ConfuserEx integration via subprocess

**Native (ELF / Mach-O / PE)**
- Debug section stripping (`.debug_*`, DWARF)
- Symbol table reduction
- UPX packing (opt-in, policy flag — note: some AV scanners flag this)

> 🔒 **`medium` and `aggressive` obfuscation levels — available in ReleaseGuard Cloud.**
> These unlock full control flow flattening, opaque predicates, dead code injection, advanced bytecode transforms, and LLVM-based native obfuscation passes. [Learn more →](https://releaseguard.dev/cloud)

#### DRM and Anti-Tamper (OSS: integrity + tamper detection)

**Runtime integrity check (free)**
- JS bundles: self-hash check injected at load time comparing computed hash vs embedded expected hash
- Go binaries: compile-time key section hash embedded via `go:embed`, verified at startup
- .NET assemblies: assembly hash verification injected at startup
- Python frozen apps: `.pyc` checksum verification at bootstrap

**Tamper detection (free)**
- Expected binary hash embedded in a signed metadata section
- On tamper detected: configurable `exit` or `log` action

**Anti-debug stubs (free, opt-in)**
- Debugger detection for supported platforms
- JS: disable DevTools hooks via standard patterns
- Native: ptrace and timing checks

> 🔒 **License enforcement server, machine fingerprinting, time-bound licenses, tamper webhook callbacks — available in ReleaseGuard Cloud.**

#### Decompilation Resistance (OSS: `light` level)

**JavaScript**
- Control flow flattening (dispatcher pattern)
- String encryption with runtime decoder
- Function inline / split manipulation

**Python**
- Compile to `.pyc` only — remove `.py` source from release artifact
- Bytecode obfuscation via PyArmor (subprocess integration)

**JVM / .NET**
- Rename symbols to short identifiers
- Basic control flow obfuscation

**Native**
- Section renaming and padding
- Fake import table entries (PE)

> 🔒 **Aggressive decompilation resistance (opaque predicates, LLVM passes, reflection dispatch, managed profiles) — available in ReleaseGuard Cloud.**

---

### 4.5 Evidence Builder

Produces the machine-readable release dossier written to `.releaseguard/`.

```
.releaseguard/
├── manifest.json            # full file inventory with dual hashes
├── findings.json            # all scanner findings with severity
├── sbom.cdx.json            # CycloneDX SBOM
├── sbom.spdx.json           # SPDX SBOM
├── vex.json                 # VEX vulnerability exploitability data
├── transform-log.json       # all mutations with before/after hashes
├── obfuscation-log.json     # obfuscation operations applied
├── drm-manifest.json        # DRM stubs injected and configuration
├── checksums.sha256
├── checksums.blake3
├── policy-report.json       # policy evaluation result
└── attestation/
    ├── artifact.intoto.json
    ├── sbom.intoto.json
    └── evidence.intoto.json
```

---

### 4.6 Policy Evaluator

**Built-in YAML rules:**
- Severity threshold gates (`fail_on: [critical, high]`)
- Category gates (`fail_on: [secret, unsigned_executable]`)
- SBOM completeness requirement (`require_sbom: true`)
- Obfuscation level gate (`require_obfuscation: light`)
- Integrity check gate (`require_integrity_check: true`)
- License allowlist (`allowed_licenses: [MIT, Apache-2.0]`)
- CVE threshold (`fail_on_cvss_above: 7.0`)

**Rego (Open Policy Agent) adapter:**
- Full OPA integration for advanced policy logic
- Policy bundle loading from local path or OCI registry
- Decision trace output for audit logs

**Policy result:**
```json
{
  "result": "fail",
  "gates": [
    { "rule": "no_secrets",          "result": "fail", "findings": ["RG-SEC-001"] },
    { "rule": "sbom_complete",       "result": "pass" },
    { "rule": "obfuscation_applied", "result": "warn" }
  ],
  "waived": [],
  "timestamp": "2026-03-11T10:00:00Z"
}
```

> 🔒 **Centrally managed policy registry, waiver approval workflows, policy inheritance across repos — available in ReleaseGuard Cloud.**

---

### 4.7 Signing and Attestation

**Signing modes:**
- Local key — GPG detached signature or raw ECDSA P-256
- Keyless — Sigstore / Fulcio OIDC identity-based, recorded to Rekor transparency log
- No-sign — dry run mode

**Attestation format:**
- in-toto attestation statements
- SLSA Provenance level 2 by default

**Verification:**
- `releaseguard verify ./release.tar.gz` checks artifact sig, evidence bundle sig, SBOM sig, provenance chain, and policy compliance at time of signing

> 🔒 **SLSA Provenance level 3 (hosted builder), AWS KMS / GCP KMS / HashiCorp Vault signing backends, org-wide key management — available in ReleaseGuard Cloud.**

---

### 4.8 Reporting Layer

| Format | Use case |
|---|---|
| CLI table | Developer local feedback loop |
| JSON | Machine consumption, CI artifact storage |
| SARIF | GitHub Security tab, IDE integration |
| Markdown | PR comments, release notes |
| HTML | Self-contained release compliance report |
| CycloneDX / SPDX | SBOM submission to NTIA, procurement |

> 🔒 **Historical report storage, cross-repo dashboards, executive compliance reports — available in ReleaseGuard Cloud.**

---

## 5. CLI Design

```bash
# Bootstrap
releaseguard init                                    # scaffold .releaseguard.yml

# Scanning
releaseguard check ./dist                            # scan + policy eval
releaseguard check ./dist --format sarif             # output as SARIF

# SBOM
releaseguard sbom ./dist                             # generate SBOM (CycloneDX by default)
releaseguard sbom ./dist --format spdx               # SPDX output
releaseguard sbom ./dist --enrich-cve                # enrich with VEX data from OSV.dev

# Transforms and hardening
releaseguard fix ./dist                              # apply safe standard transforms
releaseguard obfuscate ./dist --level light          # apply obfuscation (light)
releaseguard harden ./dist                           # full: fix + obfuscate + DRM

# Packaging
releaseguard pack ./dist --out release.tar.gz        # canonical packaging

# Signing and attestation
releaseguard sign ./release.tar.gz                   # sign artifact + evidence bundle
releaseguard attest ./release.tar.gz                 # emit in-toto / SLSA attestations

# Verification
releaseguard verify ./release.tar.gz                 # verify signatures + policy compliance

# Reporting
releaseguard report ./dist --format json             # export report
releaseguard report ./dist --format html             # self-contained HTML report
```

---

## 6. Config Schema

```yaml
# .releaseguard.yml
version: 2

project:
  name: my-app
  mode: release

inputs:
  - path: ./dist
    type: directory

sbom:
  enabled: true
  ecosystems: [node, python, go, rust, java, dotnet, ruby, php]
  formats: [cyclonedx, spdx]
  enrich_cve: true
  fail_on_cvss_above: 7.0
  allowed_licenses:
    - MIT
    - Apache-2.0
    - BSD-2-Clause
    - BSD-3-Clause

scanning:
  secrets:
    enabled: true
  metadata:
    enabled: true
    fail_on_source_maps: true
    fail_on_internal_urls: true
    fail_on_build_paths: true
  unexpected_files:
    enabled: true
    deny:
      - ".env"
      - "*.map"
      - ".git/**"
      - "*.bak"
      - "*.tmp"
      - "*.swp"
      - "node_modules/**"
  licenses:
    enabled: true
    require:
      - LICENSE

transforms:
  remove_source_maps: true
  delete_forbidden_files: true
  strip_debug_info: true
  add_checksums: true
  add_manifest: true
  normalize_timestamps: true

obfuscation:
  enabled: true
  level: light                   # none | light  (medium/aggressive: Cloud only)
  targets:
    js:
      string_encrypt: true
      property_mangle: true
      control_flow_flatten: true
    go:
      strip_symbols: true
      redact_paths: true
      use_garble: false
    python:
      strip_source: true
      use_pyarmor: false
    jvm:
      rename_symbols: true
    dotnet:
      strip_pdb_refs: true
    native:
      strip_debug: true
      strip_symbols: true

drm:
  enabled: true
  integrity_check:
    enabled: true
    on_tamper: exit              # exit | log
  anti_debug:
    enabled: false               # opt-in only
  # license_enforcement: Cloud only

signing:
  enabled: true
  mode: keyless                  # keyless | local  (kms: Cloud only)
  subject: "releaseguard-ci"

attestations:
  enabled: true
  provenance: true
  evidence: true
  sbom: true

policy:
  fail_on:
    - severity: critical
    - severity: high
    - category: secret
    - category: unsigned_executable
  warn_on:
    - category: missing_notice
  require_sbom: true
  require_obfuscation: light
  require_integrity_check: true

packaging:
  enabled: true
  format: tar.gz
  output: ./out/my-app.tar.gz
  normalize_timestamps: true

output:
  reports:
    - cli
    - json
    - sarif
    - html
  directory: ./.releaseguard
```

---

## 7. Internal Data Model

### Artifact

```go
type Artifact struct {
    Path         string            `json:"path"`
    SHA256       string            `json:"sha256"`
    Blake3       string            `json:"blake3"`
    Size         int64             `json:"size"`
    MIME         string            `json:"mime"`
    Executable   bool              `json:"executable"`
    Kind         string            `json:"kind"`
    Tags         []string          `json:"tags"`
    ArchiveDepth int               `json:"archive_depth"`
    Timestamps   ArtifactTimestamp `json:"timestamps"`
}
```

### Finding

```go
type Finding struct {
    ID              string `json:"id"`
    Category        string `json:"category"`
    Severity        string `json:"severity"`
    Path            string `json:"path"`
    Message         string `json:"message"`
    Evidence        string `json:"evidence,omitempty"`
    Autofixable     bool   `json:"autofixable"`
    RecommendedFix  string `json:"recommended_fix,omitempty"`
}
```

### Transform

```go
type Transform struct {
    ID          string  `json:"id"`
    Action      string  `json:"action"`
    Path        string  `json:"path"`
    Reason      string  `json:"reason"`
    BeforeSHA   string  `json:"before_sha256"`
    AfterSHA    *string `json:"after_sha256"`
}
```

### PolicyResult

```go
type PolicyResult struct {
    Result    string      `json:"result"`
    Gates     []GateResult `json:"gates"`
    Waived    []string    `json:"waived"`
    Timestamp time.Time   `json:"timestamp"`
}
```

---

## 8. Repo Structure

```text
releaseguard/
├── cmd/
│   └── releaseguard/
│       └── main.go
├── internal/
│   ├── app/
│   │   ├── check.go
│   │   ├── fix.go
│   │   ├── harden.go
│   │   ├── obfuscate.go
│   │   ├── sbom.go
│   │   ├── sign.go
│   │   ├── verify.go
│   │   └── report.go
│   ├── collect/
│   │   ├── walker.go
│   │   ├── hash.go
│   │   └── classify.go
│   ├── scan/
│   │   ├── scanner.go
│   │   ├── secrets.go
│   │   ├── metadata.go
│   │   ├── unexpected.go
│   │   └── licenses.go
│   ├── sbom/
│   │   ├── engine.go
│   │   ├── node.go
│   │   ├── python.go
│   │   ├── go.go
│   │   ├── rust.go
│   │   ├── java.go
│   │   ├── dotnet.go
│   │   ├── ruby.go
│   │   ├── php.go
│   │   ├── container.go
│   │   ├── system.go
│   │   ├── cyclonedx.go
│   │   ├── spdx.go
│   │   └── vex.go
│   ├── transform/
│   │   ├── engine.go
│   │   ├── remove_sourcemaps.go
│   │   ├── delete_forbidden.go
│   │   ├── checksums.go
│   │   └── manifest.go
│   ├── obfuscate/
│   │   ├── engine.go
│   │   ├── js.go
│   │   ├── go_binary.go
│   │   ├── python.go
│   │   ├── dotnet.go
│   │   ├── jvm.go
│   │   ├── native.go
│   │   └── levels.go
│   ├── drm/
│   │   ├── engine.go
│   │   ├── integrity.go
│   │   ├── antidebug.go
│   │   └── tamper.go
│   ├── antidecompile/
│   │   ├── engine.go
│   │   ├── js.go
│   │   ├── python.go
│   │   ├── jvm.go
│   │   ├── dotnet.go
│   │   └── native.go
│   ├── policy/
│   │   ├── engine.go
│   │   ├── builtin.go
│   │   └── rego_adapter.go
│   ├── signing/
│   │   ├── signer.go
│   │   ├── verifier.go
│   │   ├── attest.go
│   │   └── keyless.go
│   ├── report/
│   │   ├── cli.go
│   │   ├── json.go
│   │   ├── sarif.go
│   │   ├── markdown.go
│   │   └── html.go
│   ├── pack/
│   │   ├── tar.go
│   │   └── zip.go
│   ├── config/
│   │   ├── load.go
│   │   ├── schema.go
│   │   └── defaults.go
│   └── model/
│       ├── artifact.go
│       ├── finding.go
│       ├── transform.go
│       ├── manifest.go
│       ├── sbom.go
│       ├── drm.go
│       └── result.go
├── stubs/
│   ├── js/
│   │   ├── integrity-check.js
│   │   └── antidebug.js
│   ├── go/
│   │   └── integrity.go.tmpl
│   └── dotnet/
│       └── TamperCheck.cs.tmpl
├── policies/
│   ├── builtin/
│   │   ├── no_secrets.rego
│   │   ├── no_sourcemaps.rego
│   │   ├── require_signing.rego
│   │   ├── require_sbom.rego
│   │   └── require_obfuscation.rego
│   └── examples/
│       ├── frontend-release.rego
│       ├── electron-app.rego
│       └── oss-library.rego
├── examples/
│   ├── react-dist/
│   ├── go-binary/
│   ├── electron-app/
│   └── python-wheel/
├── .github/
│   ├── actions/
│   │   └── releaseguard/
│   │       └── action.yml
│   └── workflows/
│       ├── ci.yml
│       └── release.yml
├── docs/
│   ├── architecture.md
│   ├── policy-model.md
│   ├── config-schema.md
│   ├── signing.md
│   ├── sbom.md
│   ├── obfuscation.md
│   ├── drm.md
│   └── examples.md
├── test/
│   ├── fixtures/
│   ├── integration/
│   └── e2e/
├── scripts/
│   ├── install.sh
│   └── demo.sh
├── go.mod
├── go.sum
├── .releaseguard.yml
├── README.md
├── LICENSE
└── Makefile
```

---

## 9. Tech Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Go | Single binary, fast, great archive/FS support, ideal for DevOps tooling |
| CLI framework | Cobra | Standard Go CLI framework |
| Config | YAML + viper | Human-friendly, widely understood |
| Policy (advanced) | Open Policy Agent / Rego | Industry standard, composable |
| SBOM | cyclonedx-go + spdx-go | Official Go SDKs for both formats |
| Signing | Sigstore Go SDK + cosign | Keyless CI signing, industry momentum |
| Attestation | in-toto Go | SLSA provenance standard |
| JS transforms | esbuild / acorn via subprocess | Mature AST tooling |
| Go obfuscation | garble via subprocess | Best-in-class Go obfuscation |
| JVM bytecode | ASM via subprocess | Industry standard bytecode manipulation |
| .NET | ConfuserEx / dnlib via subprocess | Standard .NET obfuscation tooling |
| Python | PyArmor / Nuitka via subprocess | Best available Python protection |
| CVE enrichment | OSV.dev API | Free, comprehensive, open |
| Hashing | crypto/sha256 + zeebo/blake3 | Dual hash for robustness |
| Archive handling | archive/tar + archive/zip stdlib | Zero external dependencies |

---

## 10. Implementation Phases

| Phase | Deliverable | Exit Criteria |
|---|---|---|
| **1** | CLI skeleton, collector engine, file inventory, dual hashing, JSON output | `releaseguard check ./dist` produces artifact inventory |
| **2** | Secrets + metadata + unexpected file scanners | Findings output with correct severity |
| **3** | License scanner + built-in YAML policy evaluator | `pass / warn / fail` on a real dist folder |
| **4** | SBOM engine — Node.js + Go + Python first | CycloneDX output with VEX enrichment |
| **5** | SBOM — remaining ecosystems + SPDX output | Full SBOM coverage across all supported ecosystems |
| **6** | Transform pipeline (source maps, forbidden files, checksums, manifest) | `releaseguard fix` mutates artifact safely with full log |
| **7** | JS obfuscation (Terser + control flow + string encrypt, `light` level) | Obfuscated JS bundle is functionally equivalent |
| **8** | Go + native binary obfuscation (symbol strip, path redact, garble) | Binary obfuscated and working |
| **9** | JVM + .NET + Python obfuscation (`light` level) | All language targets covered |
| **10** | DRM stubs — integrity check injection (JS + Go first) | Runtime self-check passes for valid artifact |
| **11** | DRM — tamper detection + anti-debug stubs (opt-in) | Configurable via config |
| **12** | Decompilation resistance (`light` level, cross-language) | Passes decompiler smoke tests |
| **13** | Signing: local key + Sigstore keyless | `releaseguard sign` + `verify` round-trips cleanly |
| **14** | Attestation: in-toto + SLSA Provenance level 2 | Full evidence bundle signed and verifiable |
| **15** | Rego policy adapter | Custom OPA policies loadable from file and OCI registry |
| **16** | HTML report + SARIF export | GitHub Security tab integration |
| **17** | GitHub Action + GitLab CI template | Drop-in CI gate |
| **18** | Docs, examples, polish | Public launch |

---

## 11. MVP Definition

A V1 is shippable when it can:

1. `releaseguard check ./dist` — scan a frontend `dist/` folder and report findings with severity
2. `releaseguard sbom ./dist` — produce a CycloneDX SBOM for Node.js, Go, and Python projects
3. `releaseguard fix ./dist` — remove source maps, forbidden files, and add checksums
4. `releaseguard obfuscate ./dist --level light` — apply safe JS string encryption + Go symbol strip
5. `releaseguard harden ./dist` — inject runtime integrity check stub
6. `releaseguard sign` + `releaseguard verify` — round-trip verified with keyless signing
7. Drop-in GitHub Action that fails CI when policy is violated
8. Complete, machine-readable evidence bundle in `.releaseguard/`

---

## 12. Security and Ethics Notes

- **Obfuscation is defense, not malware.** All transforms are documented in the evidence bundle. Transforms are reproducible and auditable.
- **DRM stubs are disclosed.** The `drm-manifest.json` lists every stub injected. Consumers can inspect it.
- **No analysis evasion for malicious purposes.** Anti-debug stubs are opt-in, require explicit policy consent, and are documented as increasing reverse engineering cost — not preventing security research.
- **SBOM is the counterbalance.** Even obfuscated releases carry a complete, signed dependency graph for security researchers and procurement teams.
- **No destructive transforms without opt-in.** Every mutation requires explicit policy configuration.

---

## 13. Contributing

```bash
git clone https://github.com/releaseguard/releaseguard
cd releaseguard
make dev-setup
make test
make build
```

See `docs/architecture.md` for component design and `docs/policy-model.md` for extending the policy engine.

Issues and PRs welcome. See `CONTRIBUTING.md`.

---

> **Want org-wide dashboards, managed policy registry, license enforcement server, waiver workflows, and enterprise KMS signing?**
>
> → **[ReleaseGuard Cloud](https://releaseguard.dev/cloud)** — the commercial SaaS offering built on this open-source core.
