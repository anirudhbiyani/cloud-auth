# Task Backlog: cloud-auth

Epics (E1–E14) → tasks. Each task: **estimate (pts)**, **deps**, **acceptance criteria (AC)**, PRD trace. Sprint assignments per `SPRINT-PLAN-cloud-auth.md`.

Legend: pts ≈ ideal-days. `→` = depends on.

---

## E1 — Core types & interfaces  ·  Sprint 1  ·  [P0 foundation]
- **T1.1 Define core domain types** (2) — `Cloud`, `Target`, `SourceToken{Kind,Value,Issuer,Subject,Audience,Expiry}`, `Runtime`, `Credentials`. AC: compiles; documented; `var _` interface assertions where applicable.
- **T1.2 Define `SourceProvider`, `Exchanger` interfaces** (1) → T1.1. AC: interfaces match TDD §5.1/§6.1; godoc complete.
- **T1.3 Public façade `cloudauth.NewCredentialsProvider`** (2) → T1.2. AC: signature per PRD §8 SDK example; returns adapter given detected source + explicit target.
- **T1.4 Injectable `Clock` + test helpers** (1). AC: all time reads go through `Clock`; fake clock in tests.

## E2 — IMDSv2 client  ·  Sprint 1  ·  [P0-6]
- **T2.1 `internal/imds` token-required client** (3) → T1.4. AC: PUT-token then GET; hop-limit aware; short timeout; refuses IMDSv1 fallback; unit-tested against `httptest` fake.

## E3 — Phase 0 spikes  ·  Sprint 1  ·  [de-risk]
- **T3.1 Spike A: GCP→AWS `AssumeRoleWithWebIdentity`** (3) → T2.1,T1.2. AC: live exchange returns usable AWS creds from a GKE/GCE OIDC token.
- **T3.2 Spike B: AWS-EC2→GCP WIF (SigV4)** (5) → T2.1,T1.2. AC: pre-signed `GetCallerIdentity` accepted by GCP STS (direct access); returns GCP access token. **Go/no-go gate.**
- **T3.3 SigV4 canonical-request golden tests** (2) → T3.2. AC: deterministic signing verified against known-good fixtures.

## E4 — Source Identity Providers  ·  Sprint 2  ·  [P0-1, P1-2]
- **T4.1 `source` registry + deterministic `Detect()`** (2) → T1.2. AC: fixed probe order (env → metadata → k8s); returns `ErrNotThisRuntime` cleanly; forced-detect via config.
- **T4.2 AWS SIP detect+mint** (5) → T4.1,T2.1,T3.3. AC: distinguishes EC2/ECS/EKS-IRSA; mints SigV4 (EC2/ECS) and IRSA-OIDC (audience-pinned); **EKS-Pod-Identity → `ErrNonFederatableSource` with guidance** [P0-1].
- **T4.3 GCP SIP detect+mint** (3) → T4.1. AC: GCE/GKE detected; OIDC minted via metadata `identity?audience=`; audience pinned.
- **T4.4 Azure SIP detect+mint** (3) → T4.1,T2.1. AC: VM/VMSS/AKS detected; IMDS Entra token for Azure-native; AKS-WI projected OIDC JWT minted.
- **T4.5 SIP fake-metadata test harness** (2) → T4.2–4.4. AC: table-driven `httptest` servers per cloud; each sub-runtime + non-federatable case covered.

## E5 — Target Exchangers  ·  Sprint 3  ·  [P0-2, P0-7]
- **T5.1 AWS TE** (3) → T1.2. AC: `AssumeRoleWithWebIdentity`; duration = min(config, role max); token ≤20k enforced; 4xx not retried, 5xx bounded backoff.
- **T5.2 GCP TE** (4) → T1.2. AC: STS token exchange; **direct resource access default**; `impersonate_service_account` opt-in path; both OIDC and SigV4 subject-token types.
- **T5.3 Azure TE** (3) → T1.2. AC: Entra client-assertion, `aud=api://AzureADTokenExchange`; **case-sensitive** iss/sub/aud; RS256-only.
- **T5.4 EC2→Azure gap guard** (2) → T5.3,T4.2. AC: `SourceToken.Kind==AWSSigV4` + Azure target → `ErrNoFirstClassPath` listing Cognito / EKS-IRSA / self-hosted-broker options [P0-7].
- **T5.5 TE error taxonomy + mock-STS tests** (3) → T5.1–5.3. AC: distinct typed errors (missing trust, wrong aud, expired, skew, case-mismatch); mock STS asserts request shape.

## E6 — Adapters & cache  ·  Sprint 4  ·  [P0-3]
- **T6.1 `internal/cache` in-memory + proactive refresh + single-flight** (4) → T1.4,T5.*. AC: refresh at `expiry-buffer`; concurrent Retrieve shares one exchange; clock-skew honored; no disk writes.
- **T6.2 AWS adapter `aws.CredentialsProvider`** (2) → T6.1,T5.1. AC: `Retrieve(ctx)` returns cached/refreshed creds; compile-time `var _ aws.CredentialsProvider`.
- **T6.3 GCP adapter `oauth2.TokenSource`** (2) → T6.1,T5.2. AC: satisfies `oauth2.TokenSource`; usable by `cloud.google.com/go`.
- **T6.4 Azure adapter via `ClientAssertionCredential`** (2) → T6.1,T5.3. AC: `getAssertion` returns freshly minted JWT; satisfies `azcore.TokenCredential`.

## E7 — Zero-code integration  ·  Sprint 4  ·  [P0-4]
- **T7.1 AWS `credential_process` emit** (2) → T6.2. AC: `cloud-auth credential-process --to aws` outputs `{Version:1,...,Expiration}`; SDK consumes transparently.
- **T7.2 GCP `external_account` config emit** (3) → T6.3. AC: emits external_account JSON (executable/file source); works via `GOOGLE_APPLICATION_CREDENTIALS`.

## E8 — Config & policy  ·  Sprint 5  ·  [P0-5]
- **T8.1 Config schema + loader (file/env/code precedence)** (3) → T1.1. AC: `code>env>file`; `CLOUD_AUTH_*` env; unmarshals to validated struct.
- **T8.2 Strict fail-closed validation** (3) → T8.1. AC: audience required per target; malformed ARN/pool/tenant, duplicate names, unknown cloud all error before network; reuses `cloudauth/validation.go`.
- **T8.3 `cloud-auth.schema.json` + fuzz tests** (2) → T8.2. AC: schema published; fuzz corpus of invalid configs all rejected.

## E9 — `cloud-auth doctor` / `validate`  ·  Sprints 2,5,6  ·  [P0-1, P0-5]
- **T9.1 `doctor` identity report** (2, S2) → T4.*. AC: prints cloud/sub-runtime/subject/issuer with no credential input.
- **T9.2 `doctor` trust preflight + failure diagnostics** (4, S6) → T5.5. AC: for a given target, checks audience, JWKS reachability, case match; prints **exact** refusal reason per failure mode.
- **T9.3 `cloud-auth validate`** (2, S5) → T8.2. AC: lints config against target trust via `MechanismManager.Validate`.

## E10 — Security baseline & audit  ·  Sprint 5  ·  [P0-6]
- **T10.1 `internal/audit` structured events** (2) → T5.*. AC: JSON `{ts,source_identity,target_cloud,role,sts_request_id,outcome,latency}` per exchange.
- **T10.2 Security baseline sweep** (3) → all P0. AC: no-disk-by-default verified; IMDSv2 enforced; clock-skew applied; confused-deputy review documented; fail-closed (no static fallback) asserted by test.

## E11 — Docs & release  ·  Sprint 6  ·  [metrics/goals]
- **T11.1 Per-pair guides (6) + <30 min quickstart** (4) → M1 features. AC: each first-class pair has copy-pasteable setup; TTFE dry-run < 30 min.
- **T11.2 Release engineering** (3) → all P0. AC: `go install` + Homebrew tap; versioned tag `v0.1.0`; CHANGELOG.

## E12 — Decision gate: credential sink  ·  Sprint 4  ·  [PRD §12 Q1]
- **T12.1 Resolve in-memory-only vs opt-in `0600` file sink** (1). AC: decision recorded in TDD §14; if file sink kept, gated behind explicit flag + `0600` enforced.

## E13 — CI integration matrix  ·  Sprint 6
- **T13.1 Live 6-pair integration tests behind `//go:build integration`** (4) → all TE/SIP. AC: matrix runs in CI with sandbox creds; each pair green before v0.1 tag.

## E14 — Legal/community gate  ·  Sprint 6  ·  [PRD §12]
- **T14.1 License + contribution model decision** (1). AC: Apache-2.0 vs copyleft chosen; CLA vs DCO chosen; `CONTRIBUTING.md` + `LICENSE` reflect it before public launch.

---

## Critical path
`T1.1→T1.2 → T2.1 → T3.2 (SigV4 go/no-go) → T4.2 → T5.2 → T6.1 → T6.2/6.3/6.4 → T7.* → T8.* → T13.1 → v0.1`

## Point summary
| Sprint | Epics | Pts |
|---|---|---|
| S1 | E1,E2,E3 | 19 |
| S2 | E4 (+T9.1) | 17 |
| S3 | E5 | 15 |
| S4 | E6,E7,E12 | 18 |
| S5 | E8,E10,T9.3 | 16 |
| S6 | T9.2,E11,E13,E14 | 19 |

## Next actions for the team
1. Confirm planning assumptions (team size / sprint length) — adjust point budget if different.
2. Provision AWS/GCP/Azure sandbox trust for the 2 spike pairs **before** Sprint 1.
3. Resolve decision gates T12.1 (S4) and T14.1 (S6) owners now — they block code/launch respectively.
