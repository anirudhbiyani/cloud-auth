# Sprint Plan: cloud-auth

Derived from `PRD-cloud-auth.md` (§13 phasing) and `TDD-cloud-auth.md`.

## Planning assumptions (state → adjust before committing)
- **Team:** 3 engineers (1 lead + 2), each fluent in Go; access to AWS/GCP/Azure sandbox accounts.
- **Sprint length:** 2 weeks. **Velocity target:** ~20 points/sprint (team), points ≈ ideal-days.
- **No hard external deadline** (PRD §13) — sequencing is **dependency-driven**: proof minting → exchange → adapters → scaffolding.
- **Definition of Done (every task):** code + unit tests (≥80% on new pkgs) + docs updated + CI green + reviewed. Integration-touching tasks add a live test behind `//go:build integration`.

## Milestone → sprint map
| Milestone | PRD phase | Sprints | Exit criteria |
|---|---|---|---|
| **M0 Spike** | Phase 0 | S1 | GCP→AWS *and* AWS-EC2→GCP proven end-to-end live; SigV4 path de-risked |
| **M1 v0.1 MVP (P0)** | Phase 1 | S2–S6 | 6 first-class pairs + adapters + credential_process/external_account + config + security baseline + docs |
| **M2 v0.2 (P1)** | Phase 2 | S7–S9 | Scaffolder, more runtimes, `exec`, OTel, flexible FIC |
| **M3 v0.3+ (P2)** | Phase 3 | later | SPIFFE/X.509, more clouds, apply, policy-as-code (design-only now) |

---

## Sprint 1 — Phase 0 Spike & foundations (de-risk) — ~20 pts
**Goal:** Prove the two hardest exchanges end-to-end; lock core types.
- Core types & interfaces: `SourceToken`, `Runtime`, `SourceProvider`, `Exchanger`, `Credentials`, `Target`, `Cloud` (E1)
- `internal/imds` IMDSv2 client (token-required, hop-limit) (E2)
- **Spike A:** GCP→AWS via `AssumeRoleWithWebIdentity` (GCP OIDC mint → AWS TE) — live (E3)
- **Spike B:** AWS-EC2→GCP via WIF `aws` (SigV4 proof → GCP STS, direct access) — live (E3)
- Injectable `Clock` + test scaffolding
**Exit:** both spikes green against real trust; SigV4 canonical-request logic validated. Go/no-go on architecture.

## Sprint 2 — Source Identity Providers (P0-1) — ~20 pts
**Goal:** Detect + mint for all primary runtimes; reject non-federatable.
- `sip` registry + deterministic `Detect()` ordering (E4)
- AWS SIP: EC2/ECS/EKS-IRSA detection; SigV4 + IRSA-OIDC mint; **EKS-Pod-Identity reject with guidance** [P0-1] (E4)
- GCP SIP: GCE/GKE detection; OIDC mint via metadata (E4)
- Azure SIP: VM/VMSS/AKS detection; IMDS token + AKS-WI OIDC mint (E4)
- `cloud-auth doctor` v1: print cloud/sub-runtime/subject/issuer, no creds needed [P0-1] (E9)
**Exit:** `cloud-auth doctor` correctly identifies every primary runtime in live sandboxes.

## Sprint 3 — Target Exchangers (P0-2, P0-7) — ~20 pts
**Goal:** All three target STS flows + honest gap handling.
- AWS TE: `AssumeRoleWithWebIdentity`, duration capping, error taxonomy (E5)
- GCP TE: STS token exchange, **direct resource access default** + impersonation opt-in (E5)
- Azure TE: Entra client-assertion/FIC, case-sensitive match (E5)
- **EC2→Azure gap guard** → `ErrNoFirstClassPath` w/ bridge options [P0-7] (E5)
- No-retry-on-4xx policy; bounded backoff on 5xx (E5)
**Exit:** all 6 first-class pairs exchange live; gap pair returns actionable message.

## Sprint 4 — Adapters, cache, zero-code integration (P0-3, P0-4) — ~20 pts
**Goal:** Drop-in SDK providers + auto-refresh + credential_process/external_account.
- `internal/cache`: in-memory, proactive refresh, single-flight, clock-skew (E6)
- AWS adapter (`aws.CredentialsProvider`) + `credential_process` JSON emit (E6, E7)
- GCP adapter (`oauth2.TokenSource` / `external_account`) (E6, E7)
- Azure adapter (`ClientAssertionCredential`) (E6)
- **Decision gate:** file-sink vs in-memory-only (PRD §12 Q1) (E12)
**Exit:** long-running sample service refreshes transparently; existing AWS/GCP SDK config uses `cloud-auth` with zero app code.

## Sprint 5 — Config, security baseline, audit (P0-5, P0-6) — ~20 pts
**Goal:** Declarative config + fail-closed validation + security controls + audit.
- `config` schema, load (file/env/code) precedence, strict fail-closed validation, `cloud-auth.schema.json` (E8)
- Audience-required-per-target enforcement (E8)
- `internal/audit` structured events per exchange [P0-6] (E10)
- Security baseline pass: no-disk-by-default, IMDSv2 enforcement audit, clock-skew, confused-deputy review (E10)
- `cloud-auth validate` (reuse `MechanismManager.Validate`) (E9)
**Exit:** invalid config fails closed with clear messages; every exchange audited; security checklist signed off.

## Sprint 6 — Hardening, docs, v0.1 release (M1) — ~18 pts
**Goal:** Ship v0.1.
- `doctor` failure-mode diagnostics: wrong aud, missing trust, expired token, skew, case mismatch (E9)
- Per-pair docs (all 6) + quickstart targeting <30 min TTFE (E11)
- CI integration matrix for 6 pairs behind build tag (E13)
- Latency pass: verify p95 < 500 ms; release engineering, `go install`/Homebrew, LICENSE/CLA-or-DCO decision (E11, E14)
**Exit:** **v0.1 tagged**; 6 pairs documented + tested; success-metric instrumentation baseline in place.

---

## Sprint 7–9 — v0.2 (P1) — outline
- **S7:** Trust Scaffolder `cloud-auth init` over existing `LifecycleProvider.Setup(DryRun)` — AWS/GCP/Azure IaC+CLI print (P1-1).
- **S8:** More runtimes (Lambda, Cloud Run/Functions, Container Apps/App Service) + `cloud-auth exec` (P1-2, P1-3).
- **S9:** OTel observability hooks (P1-4); Azure flexible FIC generate/validate (P1-6); multi-hop design spike (P1-5).

## Risks & mitigations
| Risk | Mitigation |
|---|---|
| SigV4 proof path harder than expected | De-risked first, Sprint 1 spike; go/no-go gate |
| Live cloud trust flakiness in CI | Integration behind build tag; pre-provisioned stable test trust; unit mocks primary |
| Azure flexible FIC still preview | Static-subject FIC is v1 default; flexible behind flag |
| Open questions (file sink, bridge) block coding | Explicit decision gates in S4; in-memory + document-only defaults keep progress |
| Direct-access coverage gaps (GCP) | Verify in Phase 0; impersonation fallback always available |
