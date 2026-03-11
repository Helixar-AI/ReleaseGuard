# ReleaseGuard Cloud — Commercial SaaS Plan

> **Managed release security, compliance, and artifact hardening — for teams and enterprises.**
>
> ReleaseGuard Cloud is the commercial SaaS platform built on the open-source ReleaseGuard engine. It adds centralized policy management, org-wide dashboards, managed license enforcement, waiver workflows, enterprise key management, and a release approval control plane — everything needed to operate artifact security at scale.

---

## Table of Contents

1. [Product Positioning](#1-product-positioning)
2. [Pricing Tiers](#2-pricing-tiers)
3. [Feature Breakdown by Tier](#3-feature-breakdown-by-tier)
4. [Platform Architecture](#4-platform-architecture)
5. [Core SaaS Services](#5-core-saas-services)
6. [License Enforcement Server](#6-license-enforcement-server)
7. [Policy Registry and Control Plane](#7-policy-registry-and-control-plane)
8. [Managed Obfuscation and Hardening Profiles](#8-managed-obfuscation-and-hardening-profiles)
9. [Enterprise Key Management](#9-enterprise-key-management)
10. [Org Dashboard and Reporting](#10-org-dashboard-and-reporting)
11. [Waiver and Release Approval Workflows](#11-waiver-and-release-approval-workflows)
12. [SBOM Registry](#12-sbom-registry)
13. [Audit and Compliance](#13-audit-and-compliance)
14. [CI/CD Integration](#14-cicd-integration)
15. [API Design](#15-api-design)
16. [Data Model Extensions](#16-data-model-extensions)
17. [Repo Structure](#17-repo-structure)
18. [Tech Stack](#18-tech-stack)
19. [Implementation Phases](#19-implementation-phases)
20. [Security and Trust Architecture](#20-security-and-trust-architecture)
21. [Go-to-Market Strategy](#21-go-to-market-strategy)

---

## 1. Product Positioning

The open-source CLI is the hook. ReleaseGuard Cloud is the platform that makes the CLI useful at scale — across tens of repos, multiple teams, and enterprise compliance requirements.

### Core value proposition by buyer

| Buyer | Pain | ReleaseGuard Cloud solves |
|---|---|---|
| **Platform / DevSecOps team** | Can't enforce release policy consistently across all repos | Central policy registry that every team's CI inherits automatically |
| **Security team** | No visibility into what artifacts shipped and what was in them | Historical evidence store, SBOM registry, cross-repo audit trail |
| **Release manager** | Releases blocked by policy failures they can't waive quickly | Waiver request and approval workflow with full audit log |
| **Compliance / GRC team** | Need evidence of artifact signing, SBOM, and provenance for audits | One-click compliance report export (SOC 2, ISO 27001, NTIA SBOM) |
| **ISV / software vendor** | Need to protect commercial software from reverse engineering | Managed obfuscation and DRM profiles, license server |
| **Enterprise procurement** | Need SBOM and signed provenance from suppliers | SBOM submission portal and signed attestation bundles |

---

## 2. Pricing Tiers

### Free — Open Source CLI

- Local CLI, all OSS features
- Self-managed signing, local policy files
- No Cloud connectivity required
- Community support only

### Starter — $49 / month (up to 5 seats)

- Everything in OSS
- Cloud dashboard (up to 10 repos)
- SBOM registry (up to 1 year retention)
- Managed policy templates
- Email support

### Team — $199 / month (up to 25 seats)

- Everything in Starter
- Unlimited repos
- Waiver request and approval workflow
- Release approval gates
- Medium obfuscation profiles
- Managed DRM: license enforcement (basic online check)
- SLSA Provenance level 3
- KMS signing (AWS, GCP)
- Slack / GitHub notifications
- Priority support

### Business — $799 / month (up to 100 seats)

- Everything in Team
- Aggressive obfuscation profiles + managed decompilation resistance
- Full license server (online, offline, time-bound, machine fingerprinting)
- Managed obfuscation profiles per ecosystem
- Policy inheritance and org-wide policy push
- Org-wide compliance dashboard
- SSO (SAML / OIDC)
- HashiCorp Vault KMS integration
- Executive compliance reports (SOC 2, ISO 27001, NTIA)
- SLA: 99.9% uptime
- Dedicated Slack support channel

### Enterprise — Custom pricing

- Everything in Business
- Private cloud deployment (your VPC)
- Custom policy development
- Dedicated onboarding engineer
- Custom SLA
- Air-gapped deployment option
- Volume licensing for software distribution
- Procurement-ready SBOM submission workflows
- Contract and MSA

---

## 3. Feature Breakdown by Tier

| Feature | OSS | Starter | Team | Business | Enterprise |
|---|---|---|---|---|---|
| **Scanner Pipeline** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SBOM (all ecosystems)** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Standard transforms** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Obfuscation: none/light** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Obfuscation: medium** | — | — | ✅ | ✅ | ✅ |
| **Obfuscation: aggressive** | — | — | — | ✅ | ✅ |
| **DRM: integrity check** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **DRM: license enforcement** | — | — | ✅ (basic) | ✅ (full) | ✅ (full) |
| **DRM: machine fingerprinting** | — | — | — | ✅ | ✅ |
| **Decompilation resistance: light** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Decompilation resistance: aggressive** | — | — | — | ✅ | ✅ |
| **Keyless signing (Sigstore)** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **KMS signing (AWS/GCP)** | — | — | ✅ | ✅ | ✅ |
| **KMS signing (Vault)** | — | — | — | ✅ | ✅ |
| **SLSA Provenance L2** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SLSA Provenance L3** | — | — | ✅ | ✅ | ✅ |
| **Cloud dashboard** | — | ✅ (10 repos) | ✅ | ✅ | ✅ |
| **SBOM registry** | — | ✅ (1 yr) | ✅ (3 yr) | ✅ (7 yr) | ✅ (custom) |
| **Policy registry** | — | Templates only | ✅ | ✅ | ✅ |
| **Policy inheritance** | — | — | — | ✅ | ✅ |
| **Waiver workflows** | — | — | ✅ | ✅ | ✅ |
| **Release approval gates** | — | — | ✅ | ✅ | ✅ |
| **Historical evidence store** | — | 30 days | 1 yr | 7 yr | Custom |
| **Org compliance dashboard** | — | — | — | ✅ | ✅ |
| **Executive reports (SOC 2, NTIA)** | — | — | — | ✅ | ✅ |
| **SSO (SAML/OIDC)** | — | — | — | ✅ | ✅ |
| **Private cloud / VPC deployment** | — | — | — | — | ✅ |
| **Air-gapped deployment** | — | — | — | — | ✅ |
| **Dedicated onboarding** | — | — | — | — | ✅ |

---

## 4. Platform Architecture

```text
                      +----------------------------------+
                      |   ReleaseGuard Cloud Platform    |
                      +----------------------------------+
                                     |
          +--------------------------+---------------------------+
          |                          |                           |
          v                          v                           v
+------------------+    +---------------------+    +-------------------+
|   API Gateway    |    |   Web Dashboard     |    |  CLI Agent        |
|   REST + GraphQL |    |   Next.js / React   |    |  (OSS CLI +       |
|   + WebSockets   |    |   app.releaseguard  |    |   Cloud plugin)   |
|   + Webhooks     |    |                     |    |                   |
+--------+---------+    +----------+----------+    +---------+---------+
         |                         |                         |
         +-------------------------+-------------------------+
                                   |
              +--------------------+--------------------+
              |                    |                    |
              v                    v                    v
   +------------------+  +------------------+  +------------------+
   |  Policy Service  |  |  Evidence Store  |  |  SBOM Registry   |
   |  rule engine /   |  |  findings /      |  |  CycloneDX /     |
   |  waiver mgmt /   |  |  manifests /     |  |  SPDX / VEX /    |
   |  policy registry |  |  audit logs /    |  |  diff / search   |
   |                  |  |  report history  |  |                  |
   +--------+---------+  +--------+---------+  +--------+---------+
            |                     |                     |
            +---------------------+---------------------+
                                  |
              +-------------------+-------------------+
              |                   |                   |
              v                   v                   v
   +------------------+  +----------------+  +------------------+
   |  License Server  |  |  Key Mgmt      |  |  Notification    |
   |  online / offline|  |  KMS adapter / |  |  Slack / GH /    |
   |  time-bound /    |  |  key rotation /|  |  email / webhook |
   |  machine finger  |  |  org key store |  |                  |
   +------------------+  +----------------+  +------------------+
```

---

## 5. Core SaaS Services

### API Gateway
- REST API (v1) for all Cloud integrations
- GraphQL for dashboard queries
- WebSocket for real-time CI event streaming to dashboard
- Webhook dispatch for CI events (release passed, policy failed, waiver requested)
- Rate limiting, tenant isolation, API key auth + JWT session auth

### Identity and Auth
- Email + password (hashed with Argon2id)
- SSO: SAML 2.0 and OIDC (Business and above)
- GitHub OAuth (quick signup / CI identity linking)
- API keys per-org with scoped permissions
- RBAC: `owner`, `admin`, `release-manager`, `developer`, `viewer`

### Tenant Model
- Full tenant isolation at the database and storage layer
- Org → Teams → Repos → Releases hierarchy
- Seats tracked at org level
- Usage metering: scans / month, SBOM storage GB, evidence bundle storage GB

---

## 6. License Enforcement Server

The license server is the commercial moat for ISVs using ReleaseGuard to protect their own software products.

### How it works

1. At build time, `releaseguard harden` injects a license validation stub into the artifact (JS, Go, .NET, Python, JVM).
2. The stub calls the ReleaseGuard License API (or validates an offline key) at startup.
3. If validation fails, the stub executes the configured action: `exit`, `degrade`, or `callback`.

### License validation modes

| Mode | Description | Connectivity |
|---|---|---|
| **Online** | Stub calls License API on every startup (or every N hours) | Requires outbound HTTPS |
| **Offline** | Stub validates a cryptographically signed license file embedded or installed locally | No connectivity required |
| **Time-bound** | License has an expiry date enforced at runtime | Offline-capable |
| **Machine-fingerprinted** | License is bound to hardware identifiers (CPU ID, MAC address, hostname hash) | Offline-capable |
| **Seat-limited** | License tracks concurrent activations against the API | Requires outbound HTTPS |

### License API endpoints

```
POST   /api/v1/license/validate           # runtime validation call from stub
POST   /api/v1/license/activate           # seat activation
POST   /api/v1/license/deactivate         # seat deactivation
GET    /api/v1/license/issue              # issue new license key (vendor-side)
GET    /api/v1/license/list               # list issued licenses (vendor-side)
POST   /api/v1/license/revoke             # revoke a license key (vendor-side)
```

### License record model

```json
{
  "license_id": "lic_abc123",
  "product_id": "my-app",
  "customer_id": "cust_xyz",
  "mode": "online",
  "expiry": "2027-01-01T00:00:00Z",
  "seat_limit": 5,
  "machine_fingerprint": null,
  "issued_at": "2026-03-11T10:00:00Z",
  "status": "active"
}
```

### Stub injection

ReleaseGuard Cloud provides pre-built, cryptographically bound stubs for:
- JavaScript (injected at bundle head — IIFE that must resolve before main execution)
- Go (injected via `go:generate` + `go:embed` pattern, verified at `init()`)
- .NET (injected as a static constructor in the entry assembly)
- Python (injected into the frozen app bootstrap)
- JVM (injected as a static initializer in the main class)

Stubs are signed with the vendor's org key so they cannot be swapped.

---

## 7. Policy Registry and Control Plane

### Policy Registry

Centrally managed policies that push down to every repo in the org.

```
Org
└── Policy Groups
    ├── frontend-release       → applied to all repos tagged frontend
    ├── backend-service        → applied to all repos tagged service
    ├── oss-library            → applied to all repos tagged oss
    └── electron-desktop-app   → applied to all repos tagged desktop
```

#### Policy inheritance model
- Org-level policies: inherited by all repos, cannot be overridden downward
- Team-level policies: inherited by repos in the team, can tighten but not loosen org policy
- Repo-level policy: can add stricter rules on top of inherited policies

#### Policy-as-code workflow
- Policies stored as versioned Rego files in a dedicated `policy-registry` repo
- Changes submitted as PRs with mandatory review by security team
- Policy diff computed and shown in PR (which rules tighten, which loosen)
- Approved policies pushed to all connected repos on merge

#### Policy bundle serving
- CLI fetches active policy bundle from Cloud on each `releaseguard check` run
- Bundles are signed with the org's key — CLI verifies signature before applying
- Bundle served as OCI artifact for portability

---

## 8. Managed Obfuscation and Hardening Profiles

### Obfuscation level definitions (Cloud)

| Level | What it does | Languages |
|---|---|---|
| `none` | No obfuscation | All |
| `light` | Symbol strip, string encrypt, basic mangling | All (OSS) |
| `medium` | + control flow flatten, identifier scramble, bytecode transform | JS, Go, Python, JVM, .NET |
| `aggressive` | + opaque predicates, dead code injection, reflection dispatch, LLVM passes, advanced bytecode | All |

### Managed profiles

Cloud provides pre-built, ecosystem-specific profiles that select the right combination of tools and flags:

| Profile | Target | Tools used |
|---|---|---|
| `web-production` | React/Vue/Angular dist | Terser + custom AST transforms |
| `electron-desktop` | Electron app bundle | Terser + garble + PE symbol strip |
| `go-service-binary` | Go single binary | garble + objcopy + build path redact |
| `python-desktop-app` | PyInstaller / Nuitka frozen app | PyArmor + Nuitka compilation |
| `jvm-commercial` | Fat JAR / Spring Boot | ProGuard + custom ASM transforms |
| `dotnet-commercial` | .NET self-contained | ConfuserEx + PDB strip |
| `native-cross-platform` | C/C++/Rust binary | LLVM pass + strip + section rename |

### Custom profile builder (Business+)

Dashboard UI for building custom profiles:
- Choose base profile
- Select individual transform operations (checkboxes per operation)
- Set thresholds (max obfuscation time, max size delta %)
- Test profile against a sample artifact
- Save and assign to repos or teams

---

## 9. Enterprise Key Management

### Supported backends

| Backend | Tier |
|---|---|
| Sigstore / Fulcio (keyless) | All Cloud tiers |
| AWS KMS | Team + |
| GCP Cloud KMS | Team + |
| Azure Key Vault | Business + |
| HashiCorp Vault | Business + |
| Custom HSM (PKCS#11) | Enterprise |

### Org key store

- Each org has a dedicated signing key hierarchy
- Root key → org key → per-project signing keys
- Key rotation policy: configurable, automated (quarterly default)
- Key usage audit log: every signing operation recorded

### Key lifecycle

```
keygen → activate → in-use → scheduled-rotation → rotated → archived → revoked
```

### Air-gapped signing (Enterprise)

- Local signing proxy deployed in customer environment
- Cloud provides policy evaluation only — no artifact data leaves customer network
- Signing key never leaves the customer's HSM

---

## 10. Org Dashboard and Reporting

### Dashboard views

#### Release Health Overview
- All repos, their last release result, policy status
- Trend: findings over time, severity distribution
- Release cadence vs policy pass rate
- SBOM coverage across org

#### Per-Repo Detail
- Release history with policy result for each
- Finding breakdown by scanner category
- Obfuscation and DRM status
- SBOM diff between last two releases
- Active waivers

#### SBOM Explorer
- Search across all SBOMs in the org by package name, license, or CVE
- "Which releases ship lodash@4.17.15?" → instant answer
- License compliance heatmap across all repos
- CVE exposure by repo

#### Evidence Browser
- Browse any historical evidence bundle
- Download signed evidence for audit
- Verify signatures directly in the browser

#### Compliance View
- SOC 2 Type II artifact evidence mapping
- ISO 27001 Annex A control mapping
- NTIA SBOM minimum elements completeness check
- Executive PDF export

### Real-time CI event feed
- Live stream of scan events from all connected repos
- Filter by repo, severity, team
- Alert configuration: notify on any `critical` finding

---

## 11. Waiver and Release Approval Workflows

### Waiver workflow

When a policy gate fails, developers can request a waiver instead of being blocked indefinitely.

```
Developer runs releaseguard check
  → Policy fails (e.g. missing NOTICE file)
  → Developer submits waiver request via CLI or dashboard
  → Security team reviews: context, risk, expiry date
  → Approve (with expiry) or Deny
  → If approved: next releaseguard check passes the specific rule for the waiver period
  → Waiver expires → rule re-enforces automatically
  → Full audit log of request, reviewer, decision, justification
```

#### Waiver record model
```json
{
  "waiver_id": "wvr_abc123",
  "org_id": "org_xyz",
  "repo": "my-app",
  "rule": "require_notice_file",
  "finding_id": "RG-LIC-001",
  "requester": "dev@company.com",
  "justification": "NOTICE file will be added in next sprint. Unblocking release for hotfix.",
  "reviewer": "sec@company.com",
  "decision": "approved",
  "expires_at": "2026-04-01T00:00:00Z",
  "created_at": "2026-03-11T10:00:00Z"
}
```

### Release approval workflow

For high-risk releases, require explicit human sign-off before an artifact can be published.

```
releaseguard sign → generates release candidate
  → Cloud creates approval request
  → Assigned approvers notified (Slack, email)
  → Approver reviews: policy report, evidence bundle, SBOM, findings
  → Approve or Reject with comment
  → If approved: signing token issued, artifact can be published
  → If rejected: block with reason, developer notified
```

#### Approval gates configurable by:
- Branch pattern (`main`, `release/*`)
- Repo tag (`critical`, `customer-facing`)
- Finding severity (require approval if any `high` findings are waived)
- SBOM changes (require approval if new dependencies added)

---

## 12. SBOM Registry

A queryable, versioned store of all SBOMs produced across the org.

### Capabilities

- **Version tracking**: SBOM for every release, indexed by artifact + version + timestamp
- **SBOM diff**: show which packages were added, removed, or updated between two releases
- **Package search**: "find all releases that ship package X at version Y"
- **License search**: "find all releases that include GPL-licensed code"
- **CVE sweep**: "find all releases that ship a package with a known CVE above CVSS 7.0"
- **VEX management**: update exploitability statements for known CVEs across all affected releases

### SBOM submission portal (Enterprise)

- Accept SBOM submissions from third-party vendors
- Validate format (CycloneDX / SPDX), completeness, and signature
- Store in org SBOM registry alongside first-party SBOMs
- Procurement team view: all supplier SBOMs in one place

### SBOM API

```
GET    /api/v1/sbom/{org}/{repo}/{version}         # retrieve SBOM
GET    /api/v1/sbom/{org}/{repo}/diff?from=v1&to=v2  # SBOM diff
POST   /api/v1/sbom/search                          # search across all SBOMs
GET    /api/v1/sbom/{org}/cve-exposure              # org-wide CVE sweep
POST   /api/v1/sbom/submit                          # vendor SBOM submission
```

---

## 13. Audit and Compliance

### Audit log

Every action in the Cloud platform is recorded:
- Who performed the action (user or API key)
- What resource was affected
- What changed
- Timestamp (immutable, append-only)

Covered events: policy changes, waiver requests, waiver approvals, release approvals, key operations, SBOM submissions, user permission changes, SSO configurations.

### Compliance report exports

| Report type | Standard | What's included |
|---|---|---|
| **SBOM completeness** | NTIA minimum elements | Coverage check, gaps, per-repo status |
| **Artifact signing audit** | Custom | Every signed artifact, signer identity, timestamp, key used |
| **Policy compliance history** | SOC 2 CC8.1 | Pass/fail/waiver history per repo, trend over time |
| **Evidence bundle inventory** | ISO 27001 A.12.5 | All evidence bundles, signatures, availability |
| **CVE exposure report** | SSDF | Known CVEs in shipped artifacts, exploitability |
| **License compliance** | Custom | License breakdown, GPL exposure, FOSS obligations |

### Retention

| Tier | Evidence retention | SBOM retention | Audit log retention |
|---|---|---|---|
| Starter | 30 days | 1 year | 1 year |
| Team | 1 year | 3 years | 3 years |
| Business | 7 years | 7 years | 7 years |
| Enterprise | Custom | Custom | Immutable (configurable) |

---

## 14. CI/CD Integration

### GitHub Action (Cloud-connected)

```yaml
- uses: releaseguard/action@v1
  with:
    token: ${{ secrets.RELEASEGUARD_TOKEN }}   # Cloud API token
    path: ./dist
    policy-group: frontend-release             # from Cloud policy registry
    sbom: true
    obfuscation: medium                        # Cloud tier
    sign: keyless
    require-approval: false
```

Cloud-specific additions over OSS:
- Fetches active policy bundle from Cloud policy registry
- Reports scan results and evidence bundle to Cloud dashboard
- Creates approval request if `require-approval: true`
- Streams events to org real-time feed

### GitLab CI

```yaml
include:
  - project: releaseguard/ci-templates
    ref: main
    file: releaseguard-cloud.yml

variables:
  RELEASEGUARD_TOKEN: $RELEASEGUARD_API_TOKEN
  RELEASEGUARD_POLICY_GROUP: backend-service
  RELEASEGUARD_OBFUSCATION: medium
```

### CLI Cloud plugin

The OSS CLI gains Cloud connectivity via a plugin loaded when a valid API token is present:

```bash
export RELEASEGUARD_TOKEN=rg_live_...
releaseguard check ./dist           # fetches policy from Cloud, reports results up
releaseguard waiver request --rule require_notice_file --justification "hotfix"
releaseguard release approve        # submit for approval gate
```

---

## 15. API Design

### Authentication

```
Authorization: Bearer rg_live_<token>
```

API keys have scopes: `scan:read`, `scan:write`, `policy:read`, `policy:write`, `waiver:request`, `waiver:approve`, `release:approve`, `sbom:read`, `sbom:write`, `admin`.

### Core REST endpoints

```
# Orgs and repos
GET    /api/v1/org
GET    /api/v1/org/repos
POST   /api/v1/org/repos

# Scan results
POST   /api/v1/scan                             # submit scan results from CLI
GET    /api/v1/scan/{scan_id}
GET    /api/v1/org/scans?repo=&status=&from=&to=

# Evidence bundles
POST   /api/v1/evidence                         # upload evidence bundle
GET    /api/v1/evidence/{evidence_id}
GET    /api/v1/evidence/{evidence_id}/download

# SBOM
POST   /api/v1/sbom                             # submit SBOM
GET    /api/v1/sbom/{sbom_id}
POST   /api/v1/sbom/search
GET    /api/v1/sbom/diff

# Policy
GET    /api/v1/policy/bundle/{org}/{group}      # fetch active policy bundle
POST   /api/v1/policy/evaluate                  # server-side policy eval
GET    /api/v1/policy/waivers
POST   /api/v1/policy/waivers                   # request waiver
PATCH  /api/v1/policy/waivers/{id}              # approve / deny

# Release approvals
POST   /api/v1/release/approval                 # request approval
PATCH  /api/v1/release/approval/{id}            # approve / reject
GET    /api/v1/release/approval/{id}

# License server
POST   /api/v1/license/validate
POST   /api/v1/license/issue
GET    /api/v1/license/list
POST   /api/v1/license/revoke

# Signing
POST   /api/v1/sign/token                       # issue short-lived signing token for CLI
GET    /api/v1/sign/verify                      # server-side signature verification
```

### Webhooks

Configurable webhook events:

| Event | Payload |
|---|---|
| `scan.completed` | scan_id, repo, result (pass/warn/fail) |
| `scan.failed` | scan_id, repo, critical findings |
| `waiver.requested` | waiver_id, repo, rule, requester |
| `waiver.approved` | waiver_id, approver, expiry |
| `waiver.denied` | waiver_id, reviewer, reason |
| `release.approval.requested` | release_id, repo, approvers |
| `release.approved` | release_id, approver |
| `release.rejected` | release_id, reason |
| `sbom.cve_detected` | sbom_id, cve_id, cvss_score |
| `license.validation_failed` | license_id, product_id, reason |

---

## 16. Data Model Extensions

### Org

```json
{
  "org_id": "org_abc",
  "name": "Acme Corp",
  "plan": "business",
  "seats_used": 42,
  "seats_limit": 100,
  "policy_group_default": "default",
  "kms_backend": "aws",
  "sso_enabled": true,
  "created_at": "2026-01-01T00:00:00Z"
}
```

### Scan Result (Cloud extended)

```json
{
  "scan_id": "scan_xyz",
  "org_id": "org_abc",
  "repo": "my-app",
  "version": "v2.1.0",
  "commit": "a3f9bc...",
  "branch": "main",
  "triggered_by": "ci",
  "policy_group": "frontend-release",
  "policy_bundle_version": "v3.2.1",
  "result": "fail",
  "findings_count": { "critical": 1, "high": 2, "medium": 5, "low": 3 },
  "evidence_bundle_id": "ev_123",
  "sbom_id": "sbom_456",
  "waiver_ids": [],
  "timestamp": "2026-03-11T10:00:00Z"
}
```

### Release Approval

```json
{
  "approval_id": "appr_abc",
  "org_id": "org_abc",
  "repo": "my-app",
  "version": "v2.1.0",
  "scan_id": "scan_xyz",
  "evidence_bundle_id": "ev_123",
  "status": "pending",
  "approvers": ["alice@company.com", "bob@company.com"],
  "decisions": [],
  "requires_all": false,
  "created_at": "2026-03-11T10:00:00Z",
  "expires_at": "2026-03-12T10:00:00Z"
}
```

---

## 17. Repo Structure

```text
releaseguard-cloud/
├── services/
│   ├── api/                          # Go: REST + GraphQL API service
│   │   ├── cmd/server/main.go
│   │   ├── internal/
│   │   │   ├── handler/
│   │   │   │   ├── scan.go
│   │   │   │   ├── sbom.go
│   │   │   │   ├── policy.go
│   │   │   │   ├── waiver.go
│   │   │   │   ├── approval.go
│   │   │   │   ├── license.go
│   │   │   │   └── signing.go
│   │   │   ├── middleware/
│   │   │   │   ├── auth.go
│   │   │   │   ├── ratelimit.go
│   │   │   │   └── tenant.go
│   │   │   ├── model/
│   │   │   └── db/
│   │   └── go.mod
│   ├── policy-engine/                # Go: policy evaluation service
│   │   ├── cmd/server/main.go
│   │   ├── internal/
│   │   │   ├── registry/             # policy bundle storage and serving
│   │   │   ├── evaluator/            # OPA + builtin rule engine
│   │   │   └── signer/               # policy bundle signing
│   │   └── go.mod
│   ├── license-server/               # Go: license enforcement service
│   │   ├── cmd/server/main.go
│   │   ├── internal/
│   │   │   ├── validator/
│   │   │   ├── issuer/
│   │   │   ├── activations/
│   │   │   └── fingerprint/
│   │   └── go.mod
│   ├── sbom-registry/                # Go: SBOM store and query service
│   │   ├── cmd/server/main.go
│   │   ├── internal/
│   │   │   ├── store/
│   │   │   ├── search/
│   │   │   ├── diff/
│   │   │   └── vex/
│   │   └── go.mod
│   ├── evidence-store/               # Go: evidence bundle storage service
│   │   ├── cmd/server/main.go
│   │   ├── internal/
│   │   │   ├── upload/
│   │   │   ├── download/
│   │   │   └── verify/
│   │   └── go.mod
│   ├── notification/                 # Go: webhook + Slack + email dispatcher
│   │   ├── cmd/server/main.go
│   │   └── internal/
│   │       ├── slack/
│   │       ├── email/
│   │       └── webhook/
│   └── key-mgmt/                     # Go: KMS adapter service
│       ├── cmd/server/main.go
│       └── internal/
│           ├── aws/
│           ├── gcp/
│           ├── azure/
│           ├── vault/
│           └── pkcs11/
├── dashboard/                        # TypeScript/Next.js: web app
│   ├── app/
│   │   ├── (auth)/
│   │   ├── (dashboard)/
│   │   │   ├── overview/
│   │   │   ├── repos/
│   │   │   ├── sbom/
│   │   │   ├── policy/
│   │   │   ├── waivers/
│   │   │   ├── releases/
│   │   │   ├── evidence/
│   │   │   └── compliance/
│   │   └── api/                      # Next.js route handlers (BFF)
│   ├── components/
│   │   ├── scan-result/
│   │   ├── sbom-explorer/
│   │   ├── policy-editor/
│   │   ├── waiver-flow/
│   │   ├── release-approval/
│   │   └── compliance-report/
│   └── package.json
├── stubs/                            # Pre-built DRM / integrity stubs
│   ├── js/
│   │   ├── integrity-check.js
│   │   ├── license-online.js
│   │   ├── license-offline.js
│   │   ├── license-timebound.js
│   │   └── antidebug.js
│   ├── go/
│   │   ├── integrity.go.tmpl
│   │   └── license.go.tmpl
│   ├── dotnet/
│   │   ├── TamperCheck.cs.tmpl
│   │   └── LicenseValidator.cs.tmpl
│   ├── python/
│   │   └── license_check.py.tmpl
│   └── jvm/
│       └── LicenseValidator.java.tmpl
├── infra/
│   ├── terraform/
│   │   ├── aws/
│   │   ├── gcp/
│   │   └── modules/
│   ├── k8s/
│   │   ├── base/
│   │   └── overlays/
│   │       ├── staging/
│   │       └── production/
│   └── docker/
│       └── compose.yml               # local dev environment
├── policies/
│   ├── managed/                      # curated policy bundles served to customers
│   │   ├── frontend-release/
│   │   ├── backend-service/
│   │   ├── oss-library/
│   │   └── electron-desktop/
│   └── templates/                    # customer-editable starting points
├── sdk/
│   ├── go/                           # Go SDK for Cloud API
│   └── typescript/                   # TypeScript SDK for Cloud API
├── docs/
│   ├── api-reference.md
│   ├── saas-architecture.md
│   ├── license-server.md
│   ├── policy-registry.md
│   ├── waiver-workflow.md
│   ├── compliance-reports.md
│   └── deployment/
│       ├── aws.md
│       ├── gcp.md
│       └── enterprise-vpc.md
├── test/
│   ├── integration/
│   ├── e2e/
│   └── load/
├── .github/
│   └── workflows/
│       ├── ci.yml
│       ├── deploy-staging.yml
│       └── deploy-production.yml
└── Makefile
```

---

## 18. Tech Stack

| Layer | Choice | Rationale |
|---|---|---|
| Backend services | Go | Consistent with OSS core, fast, low memory |
| API framework | Chi (Go) | Lightweight, idiomatic REST |
| GraphQL | gqlgen | Type-safe GraphQL codegen for Go |
| Dashboard | Next.js 15 + React 19 | App router, RSC, strong ecosystem |
| UI components | shadcn/ui + Tailwind | Accessible, composable, fast to build |
| Database | PostgreSQL (primary) | ACID, row-level security for multi-tenancy |
| Search | PostgreSQL full-text + pgvector | Avoid Elastic dependency for initial scale |
| Object storage | S3-compatible (AWS S3 / GCS / MinIO for self-hosted) | Evidence bundles, SBOM files, reports |
| Cache | Redis | Sessions, rate limiting, real-time feed |
| Message queue | NATS JetStream | Lightweight, CI event streaming |
| Auth | Custom JWT + SAML2 (crewjam/saml) + OIDC | Avoid vendor lock in identity layer |
| KMS | Multi-backend adapter (AWS SDK, GCP SDK, Vault API) | Pluggable by design |
| Policy engine | Open Policy Agent (rego/opa-go) | Consistent with OSS |
| Container orchestration | Kubernetes (EKS / GKE / self-hosted) | Standard for this scale |
| Observability | OpenTelemetry → Grafana stack | Vendor-neutral, exportable |
| Billing | Stripe | Subscription management, usage metering |
| Email | Resend | Transactional email |
| Feature flags | Custom (DB-backed) | Avoid Launchdarkly dependency at start |

---

## 19. Implementation Phases

| Phase | Deliverable | Exit Criteria |
|---|---|---|
| **1** | API service skeleton, auth, tenant model, database schema | JWT auth works, org and repo CRUD |
| **2** | CLI → Cloud scan result ingestion | OSS CLI uploads scan results to Cloud, visible in basic dashboard |
| **3** | Evidence bundle store | Evidence uploaded, downloadable, signature verifiable from browser |
| **4** | SBOM registry (Node + Go + Python) | SBOM submitted and queryable |
| **5** | Basic dashboard (scan history, findings, SBOM view) | Team can see release health across repos |
| **6** | Policy registry (managed bundles, bundle signing, CLI fetch) | CLI fetches org policy bundle from Cloud |
| **7** | Waiver workflow (request, approve, deny, expiry enforcement) | Full waiver cycle works end-to-end |
| **8** | Release approval gates | CI can be blocked pending human approval |
| **9** | Stripe billing, seat management, plan gating | Paid plans enforce feature gates |
| **10** | Notification service (Slack, email, webhook) | Scan events trigger notifications |
| **11** | KMS integration (AWS + GCP first) | Artifacts signed with org KMS key |
| **12** | SBOM registry (remaining ecosystems + SPDX + VEX + diff) | Full SBOM coverage |
| **13** | Medium / aggressive obfuscation profiles | Cloud-tier obfuscation works via CLI token |
| **14** | License server (online mode first) | ISV can issue and validate licenses |
| **15** | License server (offline + time-bound + machine fingerprint) | All license modes work |
| **16** | DRM managed profiles (all language stubs) | Cloud-managed stub injection |
| **17** | SSO (SAML + OIDC) | Enterprise auth works |
| **18** | Compliance reports (SOC 2, NTIA SBOM, ISO 27001 mapping) | Downloadable compliance PDF |
| **19** | HashiCorp Vault + Azure Key Vault KMS | Full KMS coverage |
| **20** | Self-hosted / VPC deployment package | Enterprise tier deployable in customer environment |
| **21** | Air-gapped mode (offline policy eval, local signing proxy) | No artifact data leaves customer network |
| **22** | Load testing, security audit, pen test | Production launch |

---

## 20. Security and Trust Architecture

### Tenant isolation
- All database queries scoped by `org_id` using PostgreSQL Row Level Security
- Object storage uses per-org key prefixes with bucket policies
- No cross-tenant data access possible at the DB or storage layer

### Secret management
- All secrets stored in AWS Secrets Manager / GCP Secret Manager
- No secrets in environment variables or config files
- Automatic rotation for database credentials and internal service keys

### Evidence bundle integrity
- Every evidence bundle signed before upload
- Signature verified server-side on upload and on every download
- Bundle stored immutably in object storage (object versioning + delete protection)

### Artifact data handling
- Artifacts themselves **never leave the customer's environment** (OSS model)
- Only scan results, findings, SBOMs, and evidence bundles are uploaded to Cloud
- For Enterprise VPC: even these stay in the customer's network

### Pen testing and audits
- Annual third-party penetration test
- SOC 2 Type II audit (target: 12 months post-launch)
- Bug bounty program (HackerOne)

### Compliance targets
- SOC 2 Type II
- ISO 27001
- GDPR (data residency options for EU customers)
- CCPA

---

## 21. Go-to-Market Strategy

### Funnel

```
OSS CLI user
  → Discovers Cloud via upsell CTAs in CLI output and docs
  → Signs up for Starter (self-serve, credit card)
  → Hits seat limit or needs waiver workflow → upgrades to Team
  → Enterprise intro needed (SSO, VPC, compliance) → Sales-assisted upgrade to Business/Enterprise
```

### OSS → Cloud conversion hooks

- CLI outputs `🔒 Upgrade to ReleaseGuard Cloud for [feature]` messages at natural boundaries
- `releaseguard check` suggests Cloud policy registry when no local policy file found
- `releaseguard obfuscate --level medium` returns a clear "medium+ requires Cloud" message with signup link
- GitHub Action prompts with Cloud dashboard link after successful scan
- `README.md` badge: `![ReleaseGuard](https://releaseguard.dev/badge/my-org/my-repo)`

### Developer community

- Sponsor OSS conferences (KubeCon, SupplyChainSecurityCon, FOSDEM)
- Write for Hacker News / dev.to on artifact security topics
- Release example integrations for popular stacks (React, Electron, Spring Boot)
- Publish the SBOM and evidence bundle for every ReleaseGuard release itself (dogfooding)

### Enterprise sales motion

- ICP: ISVs shipping commercial desktop or server software, platform/DevSecOps teams at 200+ engineer orgs
- Outbound: target heads of platform engineering and VPs of security
- Inbound: SEO on "artifact signing", "release policy", "SBOM generation", "software supply chain"
- Trial: 30-day Business trial (self-serve, no credit card) for Enterprise evaluation
- POC: hands-on POC with dedicated engineer for accounts >$50k ARR

### Pricing levers for upsell

- **Seats**: natural limit that drives team-to-business upgrade
- **Repos**: Starter cap drives upgrade
- **Evidence retention**: compliance teams need 7-year retention
- **Obfuscation levels**: medium/aggressive is a hard feature gate, easy upsell for ISVs
- **License server**: clear value for any ISV shipping commercial software
- **SSO**: required by enterprise security teams, hard requirement

---

> **Open-source core:** [github.com/releaseguard/releaseguard](https://github.com/releaseguard/releaseguard)
>
> **ReleaseGuard Cloud:** [releaseguard.dev](https://releaseguard.dev)
