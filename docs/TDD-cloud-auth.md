# Technical Design Document: cloud-auth

Cross-Cloud Workload Identity Federation for Go

| | |
|---|---|
| **Status** | Draft v0.1 — derived from PRD-cloud-auth v0.2 |
| **Module** | `github.com/anirudhbiyani/cloud-auth` (existing repo) |
| **Binary** | `cloud-auth` |
| **Source PRD** | `PRD-cloud-auth.md` |
| **Last updated** | 2026-07-04 |

> This TDD is the engineering realization of `PRD-cloud-auth.md`. Section numbers in `[P0-n]`/`[P1-n]` brackets trace back to PRD §9 requirements. Where the design reuses or extends code already in this repository, it says so explicitly.

---

## 1. Scope & context

### 1.1 What we are building
A single Go module exposing (a) a **library** that lets a workload in cloud X obtain short-lived credentials for cloud Y with zero static secrets, and (b) a **CLI (`cloud-auth`)** wrapping the same core. The library auto-detects its runtime, mints a native proof of identity, exchanges it at the target cloud's STS, and returns a credential object the target's own SDK understands.

### 1.2 Relationship to the existing `cloud-auth` code
The repo already contains the **control-plane** of the story:

| Existing artifact | Role today | Reused as |
|---|---|---|
| `core` `MechanismManager`, `LifecycleProvider`, `Setup/Validate/Delete` | Establishes/validates target-side trust | **Trust Scaffolder** (PRD §8.5 / P1-1) and `cloud-auth validate` |
| `core` `MechanismSpec`, `specs.go`, `validation.go` | Declarative trust specs + validation | Basis for the **federation config schema** (P0-5) |
| `core` `TokenProvider`, `TokenRequest`, `TokenResponse` | Abstract token acquisition | Seed of the **Target Exchanger** contract (P0-2) |
| `provider/{aws,gcp,azure}` | Per-cloud API clients + capability model | Foundation for both SIP detection and TE exchange |
| `provider/{cloudflare,vault}` | Extra providers | Out of v1 scope; prove the plugin seam |

**Design principle:** cloud-auth adds the **data-plane / runtime** (detect → mint → exchange → adapt → refresh). It does *not* rewrite the control-plane. Two new top-level packages carry the new surface; existing packages are extended, not forked.

### 1.3 Non-goals (technical restatement of PRD §5)
- No secret storage/rotation/vaulting. No `keyring`, no encrypted file store.
- No data-plane proxy — we return credentials, never bytes.
- No `apply` of trust changes in v1 (scaffolder is print-only).
- No SPIFFE/X.509 source in v1 (design the seam, don't build it).
- No browser/interactive OAuth.

---

## 2. Requirements → design map

### 2.1 Functional (from PRD §9)
| Req | Design owner (§) | Package |
|---|---|---|
| P0-1 Source detection & minting | §5 SIP | `source/` |
| P0-2 Six first-class target exchanges | §6 TE | `target/` |
| P0-3 Native adapters + auto-refresh | §7 Adapters | `adapters/`, `internal/cache` |
| P0-4 `credential_process` / `external_account` | §7.4 | `adapters/`, root command |
| P0-5 Declarative config + validation | §8 Config | `config/` |
| P0-6 Security baseline | §9 Security | cross-cutting |
| P0-7 EC2→Azure gap handling | §6.4 | `te/azure`, `source` |
| P1-1 Trust scaffolder | §10 | `core` (existing) |
| P1-2 More runtimes | §5 SIP | `source/` |
| P1-3 `cloud-auth exec` | §11 CLI | root command |
| P1-4 Observability | §12 | local audit log only — no telemetry (dropped) |
| P1-6 Azure flexible FIC | §10 | scaffolder |

### 2.2 Non-functional (from PRD §11)
- **p95 exchange latency < 500 ms** (excl. cold network) → in-memory cache, connection reuse, no synchronous disk I/O on the hot path.
- **Exchange success rate > 99%** against correct trust → deterministic error taxonomy, no silent retries that mask config errors.
- **Time-to-first-exchange < 30 min** → `cloud-auth doctor`, `cloud-auth init` scaffolding, copy-pasteable errors.
- **Zero static secrets, fails closed** → no credential-caching to disk by default; ambiguous config is a hard error.

---

## 3. High-level architecture

```
                          ┌──────────────────────────────────────────────┐
   cloud-auth CLI  ──┐          │                cloud-auth (library core)         │
              ├──────────►│                                                │
  Go import ──┘          │   ┌────────────┐   SourceToken   ┌───────────┐ │
                          │   │  Source    │────────────────►│  Target   │ │
   runtime metadata ─────────►│ Identity   │  {OIDC|SigV4}   │ Exchanger │ │
   (IMDS/metadata/         │  │ Provider   │                 │  (TE)     │ │
    projected SA token)    │  │  (SIP)     │                 └─────┬─────┘ │
                          │   └────────────┘                       │       │
                          │        ▲ Detect()/Mint()               ▼       │
                          │        │                        native creds   │
                          │   ┌────┴──────┐              ┌──────────────┐  │
                          │   │  Config   │              │  Credential  │  │
                          │   │ & Policy  │──────────────►   Adapter    │──┼──► aws/gcp/azure SDK
                          │   └───────────┘   Target      │  + Cache/    │  │
                          │                   binding     │  Refresh     │  │
                          │                               └──────────────┘  │
                          └──────────────────────────────────────────────┘
                                          │ (P1) generates
                                          ▼
                          ┌──────────────────────────────────────────────┐
                          │  Trust Scaffolder  = existing core           │
                          │  LifecycleProvider.Setup → Terraform/CLI print │
                          └──────────────────────────────────────────────┘
```

Five internal components (PRD §8), each an interface with per-cloud implementations:

1. **Source Identity Provider (SIP)** — detect runtime, mint audience-pinned proof.
2. **Target Exchanger (TE)** — call the target STS, return native creds.
3. **Credential Adapter** — wrap creds in each SDK's native interface + cache/refresh.
4. **Config & Policy** — declarative source-predicate → target-binding map.
5. **Trust Scaffolder** — reuse `core`; print IaC/CLI, no apply.

---

## 4. Package layout

```
github.com/anirudhbiyani/cloud-auth
├── core.go                 // public façade: NewCredentialsProvider, Target, Cloud
├── source/                        // Source Identity Providers  [P0-1, P1-2]
│   ├── sip.go                  //   SourceProvider iface, SourceToken, Detect registry
│   ├── aws.go                  //   EC2/ECS/EKS-IRSA/(Lambda P1); SigV4 + OIDC mint
│   ├── gcp.go                  //   GCE/GKE (+Cloud Run/Functions P1); OIDC via metadata
│   └── azure.go                //   VM/VMSS/AKS (+ Container Apps P1); IMDS + AKS WI OIDC
├── target/                         // Target Exchangers          [P0-2, P0-7]
│   ├── te.go                   //   Exchanger iface, Credentials result type
│   ├── aws.go                  //   AssumeRoleWithWebIdentity
│   ├── gcp.go                  //   STS token exchange + direct access / impersonation
│   └── azure.go                //   Entra client-assertion (FIC); EC2→Azure gap guard
├── adapters/                   // SDK-native credential providers  [P0-3, P0-4]
│   ├── aws.go                  //   aws.CredentialsProvider + credential_process JSON
│   ├── gcp.go                  //   oauth2.TokenSource / external_account
│   └── azure.go                //   azcore.TokenCredential via ClientAssertionCredential
├── config/                     // Declarative config          [P0-5]
│   ├── config.go               //   schema, load (file/env/code), strict validation
│   └── cloud-auth.schema.json
├── internal/
│   ├── cache/                  //   in-memory credential cache + proactive refresh [P0-3]
│   ├── imds/                   //   IMDSv2 client (token-required, hop-limit) [P0-6]
│   ├── jwt/                    //   JWKS fetch/verify, claim extraction (doctor)
│   ├── audit/                  //   structured audit events  [P0-6]
├── main.go                     // The command, at the module root: doctor, exchange,
├── controlplane.go             //   exec, credential-process, init, validate
├── runtime.go                  //   [P0, P1-3]
├── ...                         //
└── core/, provider/         // EXISTING — control-plane / scaffolder (reused)
```

Rationale: `source`/`target`/`adapters`/`config` are the public data-plane API and stay top-level. Everything an integrator should not import (IMDS, cache, JWT, audit) lives under `internal/`. The existing `pkg/` tree is untouched in structure.

---

## 5. Component: Source Identity Provider (SIP) — [P0-1, P1-2, P0-7]

### 5.1 Interface & core type
```go
package sip

type Kind int
const ( OIDC Kind = iota; AWSSigV4 )

// SourceToken is the normalized proof handed to a Target Exchanger.
type SourceToken struct {
    Kind     Kind      // OIDC (JWT) or AWSSigV4 (pre-signed GetCallerIdentity)
    Value    string    // JWT compact form, or the pre-signed request payload
    Issuer   string    // OIDC iss (empty for SigV4)
    Subject  string    // OIDC sub / AWS principal ARN
    Audience string    // pinned aud
    Expiry   time.Time
}

type Runtime struct {
    Cloud      Cloud      // AWS | GCP | Azure
    SubRuntime string     // "ec2" | "eks-irsa" | "eks-pod-identity" | "gke" | "aks" | ...
    Federatable bool      // false ⇒ e.g. EKS Pod Identity: reject with guidance [P0-1]
    Identity   Identity   // subject/issuer discovered without any credential input
}

type SourceProvider interface {
    // Detect resolves the runtime with no credential input; returns
    // ErrNotThisRuntime if it isn't running here (registry tries each).
    Detect(ctx context.Context) (*Runtime, error)
    // Mint returns an audience-pinned proof. Errors if the runtime is
    // non-federatable (Federatable=false) with an actionable message.
    Mint(ctx context.Context, audience string) (*SourceToken, error)
}
```

### 5.2 Detection strategy (fail-fast, deterministic order)
A `Detect()` registry probes providers cheaply and in a fixed order so results are stable and testable:

1. **Env hints first** (cheap, no network): `AWS_*`/`ECS_CONTAINER_METADATA_URI`, `KUBERNETES_SERVICE_HOST` + projected-token file, `AZURE_*`/`MSI_ENDPOINT`, GCE metadata env.
2. **Metadata endpoints** (short timeout, e.g. 1 s): AWS IMDSv2 (`169.254.169.254`, token-required), GCP metadata (`metadata.google.internal`, `Metadata-Flavor: Google`), Azure IMDS (`169.254.169.254/metadata`, `Metadata: true`).
3. **Kubernetes sub-runtime disambiguation:** presence of a projected SA token → EKS-IRSA (federatable OIDC) vs. EKS Pod Identity (agent socket / `AWS_CONTAINER_CREDENTIALS_FULL_URI`, **not** federatable).

Config `source.detect` may force a sub-runtime, skipping probes (dev/CI).

### 5.3 Minting per source
| SubRuntime | Proof | Mechanism |
|---|---|---|
| GCP GCE/GKE/Run/Fn | OIDC JWT | metadata `…/identity?audience=<aud>&format=full` |
| Azure VM/VMSS/App | Entra token (IMDS) | `…/oauth2/token?resource=<aud>` — used for Azure-native; **not** a portable OIDC JWT for foreign STS |
| Azure AKS Workload Identity | OIDC JWT | projected SA token signed by cluster OIDC issuer |
| AWS EKS-IRSA | OIDC JWT | projected SA token (`AWS_WEB_IDENTITY_TOKEN_FILE`), audience configurable on the SA token |
| AWS EC2/ECS/Lambda | SigV4 proof | build + pre-sign `sts:GetCallerIdentity` (SigV4) with IMDSv2 creds |
| AWS EKS Pod Identity | — | `Federatable=false`; `Mint` returns `ErrNonFederatableSource` with guidance to IRSA/OIDC [P0-1] |

**SigV4 proof construction:** build a canonical `GetCallerIdentity` request to the regional STS endpoint, SigV4-sign with IMDSv2-obtained instance creds, and serialize the signed headers + URL as the `SourceToken.Value`. GCP WIF replays this (`subject_token_type = urn:ietf:params:aws:token-type:aws4_request`). This is the highest-risk path — de-risked in the Phase 0 spike.

### 5.4 The EC2→Azure gap [P0-7]
A SigV4 `SourceToken` targeting Azure is a **compile-time-impossible / runtime-guarded** combination: Azure TE inspects `SourceToken.Kind`; if `AWSSigV4`, it returns `ErrNoFirstClassPath` describing the three OIDC-bridge options (Amazon Cognito, EKS-IRSA source, self-hosted OIDC broker). Surfaced identically in `cloud-auth doctor` when config declares such a pair. No silent failure.

---

## 6. Component: Target Exchanger (TE) — [P0-2]

### 6.1 Interface
```go
package te

type Credentials struct {
    Cloud       Cloud
    AccessKeyID, SecretAccessKey, SessionToken string // AWS
    AccessToken string                                 // GCP/Azure bearer
    Expiry      time.Time
    STSRequestID string                                // for audit
}

type Exchanger interface {
    // Exchange trades a source proof for native target credentials.
    Exchange(ctx context.Context, tok *sip.SourceToken, b Target) (*Credentials, error)
}
```

### 6.2 Per-target flows
| Target | Accepts | API | Result |
|---|---|---|---|
| **AWS** | OIDC JWT (≤20,000 chars) | `sts:AssumeRoleWithWebIdentity` (role ARN, session name, duration ≤ role max) | AK/SK/token |
| **GCP** | OIDC JWT or AWS SigV4 | STS `sts.googleapis.com/v1/token` (RFC 8693) → **direct resource access** default; `generateAccessToken` impersonation opt-in | access token |
| **Azure** | RS256 OIDC JWT only | Entra client-credentials, JWT as `client_assertion`, `aud=api://AzureADTokenExchange` | access token |

### 6.3 Design notes
- **GCP default = direct resource access** (`principal://`/`principalSet://`); impersonation only when `impersonate_service_account` is set (PRD open-question leaning resolved). TE picks path from config, not heuristics.
- **Duration:** requested = `min(config, role/provider max)`; TE never silently exceeds a cap.
- **Case-sensitivity (Azure):** issuer/subject/audience compared case-sensitively; `cloud-auth doctor` explicitly diffs expected vs. actual to catch this common failure.
- **Retries:** network/5xx retried with jittered backoff (bounded); 4xx/trust errors are **not** retried — they are config problems surfaced immediately (supports the >99% success + fail-fast goals).

---

## 7. Component: Credential Adapters + cache — [P0-3, P0-4]

### 7.1 Native interfaces
```go
// AWS: single-method interface — Retrieve delegates to cache→TE.
func (p *awsProvider) Retrieve(ctx context.Context) (aws.Credentials, error)

// GCP: external_account is preferred; also expose oauth2.TokenSource.
func (p *gcpSource) Token() (*oauth2.Token, error)

// Azure: build azidentity.ClientAssertionCredential; getAssertion callback
// returns the freshly minted OIDC JWT from SIP.
cred, _ := azidentity.NewClientAssertionCredential(tenant, clientID,
    func(ctx context.Context) (string, error) { return mintJWT(ctx) }, nil)
```

### 7.2 Cache & refresh (`internal/cache`)
- **In-memory only by default.** No disk writes. If (and only if) a user opts into a file sink, write `0600` — gated behind the resolution of PRD open-question §12 (see §14).
- **Proactive refresh** at `expiry - buffer` (default buffer = `min(20% of TTL, configured refresh.buffer)`), so the next call never blocks on a cold exchange.
- **Single-flight**: concurrent `Retrieve` during refresh share one in-flight exchange (`golang.org/x/sync/singleflight`) — prevents thundering-herd against STS.
- **Clock-skew tolerance:** treat token as expired `skew` earlier (configurable, default 60 s) [P0-6].

### 7.3 Zero-code integration [P0-4]
- **AWS `credential_process`:** `cloud-auth credential-process --to aws --role …` emits `{Version:1, AccessKeyId, SecretAccessKey, SessionToken, Expiration}`; SDK caches by `Expiration`.
- **GCP `external_account`:** `cloud-auth init`/config emits an `external_account` credential JSON pointing `credential_source` at `cloud-auth` (executable source) or the projected token; consumed via `GOOGLE_APPLICATION_CREDENTIALS`.

---

## 8. Component: Config & Policy — [P0-5]

### 8.1 Schema (v1, matches PRD §8)
```yaml
version: 1
source: { detect: auto }          # or forced sub-runtime
targets:
  - name: s3-reader
    cloud: aws
    role: arn:aws:iam::123:role/reader
    audience: sts.amazonaws.com     # REQUIRED, pinned per target
  - name: bigquery
    cloud: gcp
    workload_identity_pool: projects/…/providers/aws
    # impersonate_service_account: reader@proj.iam…   # optional fallback
  - name: synapse
    cloud: azure
    tenant: <tenant-id>
    client_id: <app-or-uami-id>
    audience: api://AzureADTokenExchange
refresh: { buffer: 5m }
```

### 8.2 Loading & precedence
`code > env > file` (later wins), resolved into one validated struct. Env keys namespaced `CLOUD_AUTH_…`. **Strict validation, fail-closed:**
- `audience` required per target (missing = hard error) [P0-6].
- Unknown target cloud, malformed ARN/pool/tenant → error before any network call.
- Ambiguity (two targets same `name`) → error.
- Reuses/extends `core/validation.go` validation primitives.

---

## 9. Security design — [P0-6]

Trust anchored **only** in the receiving cloud's IAM. cloud-auth presents provable identity; it holds no trust.

| Control | Implementation |
|---|---|
| No static secrets at rest | No secret store; creds in-memory; disk sink opt-in `0600` only |
| Short-lived only, fail closed | No static-credential fallback path exists in code |
| IMDSv2 required (AWS) | `internal/imds` always token-first (PUT token, then GET), hop-limit aware; honors account/AMI IMDSv2 enforcement |
| Audience pinning | `audience` mandatory per target; TE passes it; `doctor` verifies `aud` claim |
| Subject/claim conditions | Authored in target IAM (scaffolder emits GCP attribute conditions, AWS `sub`/`aud` trust conditions, Azure case-sensitive match / flexible-FIC) |
| Confused-deputy defense | Distinct audience + subject conditions per trust; documented in `init` output |
| Structured audit per exchange | `internal/audit` emits `{ts, source_identity, target_cloud, role, sts_request_id, outcome, latency}` as JSON to stderr/sink |
| Clock skew | Configurable `skew` buffer on expiry checks |
| SSRF resistance | IMDSv2 token-required; short metadata timeouts; no proxy of metadata responses |

---

## 10. Trust Scaffolder (P1-1) — reuse existing `core`

`cloud-auth init --to <cloud>` maps a config target to a `MechanismSpec` and calls the existing `LifecycleProvider.Setup` **in `DryRun` mode**, rendering the resulting `Plan`/`Outputs` as Terraform + native CLI (`gcloud`/`az`/`aws`). **Print-only in v1** — no apply (PRD §5.5). This is where the existing control-plane code earns its keep; the scaffolder is a thin renderer over `Setup(DryRun)`.

Emits: AWS IAM OIDC provider + role trust policy; GCP WIF pool/provider + `principal://` binding (impersonation binding optional); Azure app/UAMI federated identity credential (flexible-FIC variant behind P1-6 flag, mindful of 20-FIC/identity limit).

---

## 11. CLI surface (module root)

| Command | Req | Behavior |
|---|---|---|
| `cloud-auth doctor` | P0-1/P0-6 | Detect runtime; print cloud, sub-runtime, subject/issuer; if a target is given, verify trust preconditions (audience, JWKS reachability, case match) and give the **exact** refusal reason |
| `cloud-auth exchange --to <cloud> --role … --format env\|json` | P0-2/3 | One exchange, print/export creds |
| `cloud-auth credential-process --to aws --role …` | P0-4 | Emit AWS credential_process JSON |
| `cloud-auth exec --to <cloud> -- <cmd>` | P1-3 | Inject creds into subprocess env |
| `cloud-auth init --to <cloud>` | P1-1 | Print target-side trust IaC/CLI |
| `cloud-auth validate` | P0-5 | Lint config against target trust (reuses `MechanismManager.Validate`) |

CLI is a thin shell over the library — no business logic in `cmd/`.

---

## 12. Observability — no telemetry (decided)
**CrossFed ships no telemetry.** No OpenTelemetry, no metrics exporters, no phone-home, no `internal/telemetry` package — nothing leaves the host. The only observability surface is the **local structured audit log** (`internal/audit`, P0), written to stderr/a local sink and consumed by the operator's own SIEM. This is a deliberate trust decision for a security-sensitive credential broker, not a deferral. The former P1-4 "OTel observability" item is **dropped**.

---

## 13. Testing strategy

| Layer | Approach |
|---|---|
| SIP detection | Table-driven, fake metadata servers (`httptest`) per cloud; assert sub-runtime + `Federatable` incl. Pod-Identity rejection |
| SIP minting | Golden SigV4 canonical-request tests; OIDC mint against fake metadata; assert audience pinning |
| TE | Mock each STS endpoint; assert request shape (grant type, subject_token_type, aud) and error taxonomy (4xx not retried) |
| Adapters | Contract tests against real SDK interfaces (compile-time assertions `var _ aws.CredentialsProvider = …`); cache/refresh timing with injectable clock |
| Config | Fuzz + table validation; fail-closed cases enumerated |
| `doctor` | Snapshot tests of diagnostic output for each failure mode (wrong aud, missing trust, skew, case mismatch) |
| **Integration (Phase 0 + CI)** | Live matrix behind build tag `//go:build integration`: the 6 first-class pairs against provisioned test trust; gated by cloud creds in CI secrets |
| Injectable clock | All expiry/refresh logic uses a `Clock` interface so time is deterministic in tests |

Coverage target: unit ≥ 80% on `source`/`target`/`adapters`/`config`; the 6 pairs each have one green integration test before v0.1.

---

## 14. Resolved decisions (were open questions; carried from PRD §12)
1. **Credential sink → in-memory only by default; opt-in `0600` file sink behind an explicit flag.** No credential is ever written to disk unless the operator explicitly opts in, in which case the file is created `0600`. **Decided.**
2. **EC2→Azure gap → document-only for v1.** Detect the SigV4→Azure pairing and return an actionable message pointing to the OIDC-bridge options (Cognito / EKS-IRSA / self-hosted broker). No bridge helper ships in v1. **Decided.**
3. **GCP target → direct resource access is the default**, with `impersonate_service_account` as an explicit opt-in for APIs lacking direct-federation support. Both paths are implemented. (Non-blocking follow-up: reconfirm direct-access service coverage against Google's list at release.) **Decided.**
4. **Azure flexible FIC (preview) → not depended on for v1.** Static-subject FICs are the v1 default; flexible-FIC support is a post-v1 follow-up, not a launch dependency. **Decided.**
5. **Telemetry → none, ever.** See §12. **Decided.**
6. **License → AGPL-3.0.** The repository `LICENSE` is the GNU Affero General Public License v3.0. Contribution model (CLA vs DCO) still to confirm; DCO (`Signed-off-by`) is the lightweight default recommendation pending sign-off.

## 15. Key trade-offs
- **Reuse control-plane vs. clean-slate:** reusing `core` cuts scaffolder cost and keeps one trust model, at the cost of carrying its current abstractions. Chosen: reuse.
- **`internal/` for IMDS/cache/jwt:** narrows the public API (easier SemVer) but blocks external reuse of those helpers. Chosen: internal until asked otherwise.
- **No retry on 4xx:** favors fast, honest failure (>99% + <30 min goals) over resilience to transient trust propagation delay; mitigated by `doctor` guidance.
- **SigV4 path complexity:** GCP-only consumer today, but building it unlocks EC2→GCP without an OIDC bridge — worth the spike risk.
