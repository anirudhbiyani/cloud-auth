# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is 0, the public Go API may change in a minor release.
Breaking changes are called out explicitly.

## [Unreleased]

### Added
- API reference in the documentation site: every exported identifier of the public packages, generated from the source by `go run ./internal/apidoc` (stdlib `go/doc`, no dependency) on each docs build, with each package linked to the curated page that shows it in use and the packages' `Example_*` tests rendered inline.
- SDK section of the documentation site: runtime exchange and the AWS/GCP/Azure SDK adapters, control plane, audit inventory, error taxonomy and redaction, and the three extension interfaces. Every Go snippet is a complete program and is compile-checked.
- Documentation site at https://anirudhbiyani.com/cloud-auth/ (MkDocs Material, deployed by `.github/workflows/docs.yml`). Pages pull their text from README.md by section markers, so the README stays the single source. Includes the integration harness guide and a test plan for the remaining unproven items.
- OpenAI as a federation target: `--to openai --identity-provider <id> --service-account-id <id>` performs the RFC 8693 token exchange at auth.openai.com and hands the token to the child as `OPENAI_API_KEY`. Audience defaults to `https://api.openai.com/v1`.
- Anthropic control plane: `setup -f` with an `anthropic_federation` spec registers the issuer, creates or reuses the service account, and creates the federation rule through the Admin API; `validate` diffs the live rule, `delete` archives in dependency order and keeps shared parents. Requires an `org:admin` OAuth token in `ANTHROPIC_AUTH_TOKEN`.
- `exec`/`env` now emit `ANTHROPIC_AUTH_TOKEN` for Anthropic credentials instead of the generic `CLOUD_AUTH_ACCESS_TOKEN`.
- Integration harness: run on clusters you already operate. `scripts/existing.sh` captures an EKS or AKS cluster's facts, `up.sh --existing <clouds>` skips provisioning for them, `GKE_CLUSTER`/`GKE_LOCATION`/`GKE_PROJECT` put the GCP source on an existing GKE cluster via Workload Identity instead of a GCE VM, and `EKS_CONTEXT`/`AKS_CONTEXT`/`GKE_CONTEXT` pin each runtime to its own kube context. `aws/stage2` can reuse an IAM OIDC provider that already registers the AKS issuer (`azure_oidc_provider_arn`).
- Integration harness: `LAMBDA=1` deploys the verifier as a Lambda function (`tofu/aws/lambda`), giving the AWS SigV4 source path and the AWS → Azure negative test without an EC2 instance. The verifier speaks the Lambda runtime API itself (stdlib, no new dependency).
- First live proof of all six first-class cross-cloud pairs (GKE/EKS/AKS → AWS/GCP/Azure) through the harness.

### Changed
- Dependencies upgraded (AWS SDK v2 1.47.8, azcore 1.24.0, x/net 0.62.0 and transitive). GitHub Actions bumped: checkout v7, setup-go v7, setup-python v7, upload-pages-artifact v5, deploy-pages v5, goreleaser-action v7.3.0, govulncheck v1.9.0, mkdocs-material 9.8.1. Go 1.27.3, golangci-lint v2.15.0 and gosec v2.30.0 were already the latest.

### Changed
- SigV4 `GetCallerIdentity` is now explicitly the legacy AWS proof; `sts:GetWebIdentityToken` (outbound identity federation) is the standard. Nothing is removed: `auto` still falls back when the account has outbound federation disabled, but it logs a warning once per process; `doctor` names the legacy path even when GCP accepts it; `setup --type gcp-wif --provider-type aws` prints a note recommending `oidc`; `cloud-auth audit` marks aws-type pool providers `legacy_proof` and counts them. Pin `CLOUD_AUTH_AWS_PROOF=sigv4` to keep the legacy path deliberately and silence the warning.

### Added (validation)
- Three `validate` checks that the README had advertised but did not exist. **OIDC provider configuration** fetches the issuer's discovery document, requires its `issuer` to match the trust exactly, and fetches a non-empty JWKS (keys without `kid` are flagged). **Clock skew** compares the local clock with the `Date` header of the discovery endpoint and fails beyond the target's tolerance (30 s Anthropic, 5 min clouds); skipped without a remote time source. **Token acquisition** (`--include-token-test`, previously accepted and ignored) detects the local runtime, mints a proof, and exchanges it at the target built from the mechanism's recorded ids; skipped off-workload, failed on refusal. All four OIDC-capable providers (AWS, GCP, Azure, Anthropic) run the first two always and the third on request. `core.DefaultValidationHTTPClient` lets tests and embedders redirect the probes.

### Fixed (documentation)
- Audited every documentation claim against the source. Corrected: the SigV4 proof is accepted by GCP only (the matrix and proof table said AWS too); EKS Pod Identity is refused, not "unaffected"; `k8s-federation` targets AWS, GCP or Azure; Quick Start Example 2 lacked the required `--attribute-condition` and `--attribute-scope`; `CLOUD_AUTH_AWS_PROOF` does not override a config-file key and `CLOUD_AUTH_REFRESH_BUFFER` is consumed by library adapters only; the "common options" apply to control-plane commands only and `--force` means different things on `setup` and `delete`; `init` prints Terraform; there is no `env` command; `VAULT_NAMESPACE` was missing. SDK pages: detection order is GitHub Actions first; `NewFileStateStore` takes an explicit path (`DefaultStateStorePath()`); `StateStore` has six methods; nine error categories, not six; `MarshalJSON` yields a redacted string; liveness states are `live-and-ours` / `live-but-not-ours`; Anthropic has no inventory source; the extension rules are in code, not in Decisions; `AWSTarget.DurationSeconds` and the bare WIF pool form were undocumented. `broker.New`'s doc comment named the wrong detection order. Validation table: OIDC-discovery, token-acquisition and clock-skew checks were listed as implemented but do not exist (`--include-token-test` is accepted and ignored), and Azure permission checks are not implemented; a missing `GOOGLE_CLOUD_PROJECT` fails the audit source rather than producing a gap row; `audit` has no `--state`; the extensibility section showed a `TokenProvider` interface that does not exist; the repository tree omitted `state/`; `--source` and `--app-id` help were incomplete. Harness docs: `LAMBDA=1` adds a Lambda alongside the EC2 rather than replacing it, there is no CI teardown job, GCP targets have no probe yet, and the smoke workflow reads a repository variable, not a secret.
- JSON Schema for the runtime config now covers `scope` and `session_name`, so the README example validates against it. (The config file resolves AWS, GCP and Azure targets only; Anthropic and OpenAI targets are passed by flags.)
- `setup --type azure-federated --identity-type managed_identity` (the spelling the help text advertises) is now accepted alongside `managed-identity` and `mi`.

### Fixed (harness)
- Stage2 preflight demanded `run_id` in tfvars although the driver passes it as `-var`, so stage2 could never start.
- Service-account annotations were applied before the account existed, so no runtime got its federation wiring.
- Pods lacked RBAC to re-mint their projected token via TokenRequest, which AKS → GCP needs.
- Azure targets carried no `scope`; the verifier now uses the ARM scope the harness grants Reader on.
- `verify.sh` read a `.passed` key that never existed: every case printed FAIL and no failure was counted.
- Teardown deleted hand-written facts files and the stage2 tfvars a destroy retry needs.

### Fixed

- **`audit` reported 65 false criticals in one tenant.** ARM returns managed
  identity ids with `/resourcegroups/` in lower case; the resource-group parser
  was case-sensitive, so every identity became a gap record — and gap records
  were then scored as "critical, no subject condition", overwriting the
  explanation of what could not be read. Gaps are no longer scored.
- **`audit` called a private GitHub repository "unregistered — anyone can
  register it".** GitHub answers 404 for a private repository the caller cannot
  see, so an unauthenticated 404 is now reported as not visible; the land-grab
  verdict requires `GITHUB_TOKEN`.
- **AWS on a laptop with no region configured.** The SDK probes IMDS for a
  region before applying a default and an unreachable IMDS aborted every AWS
  call. IAM is global, so the client now defaults to `us-east-1`. Credentials
  are resolved at client construction, so `setup --dry-run` without credentials
  degrades to "plan a create" by design rather than by the accident of the
  earlier failure.
- **Live `setup` → `validate` → `delete` on all three clouds, found by running
  it.** AWS: a re-run tried to re-create the OIDC provider (IAM returns the URL
  without its scheme, the comparison was scheme-sensitive) and got
  `EntityAlreadyExists`. GCP: the Compute default service account
  (`<number>-compute@developer.gserviceaccount.com`) was rejected as an invalid
  email; a single-subject impersonation binding was built as `principalSet://`,
  which IAM refuses — it is `principal://`; a refused binding left the pool
  and provider this run had just created; and `delete` left the
  `workloadIdentityUser` member on the service account after the pool was gone. Azure: every run created another app
  registration of the same display name, and the first run's cleanup left the
  second behind; the federated credential and service principal are now found
  on a re-run rather than created. The lifecycle test now asserts a re-run
  lands on the same resources.
- **`doctor` exited 0 after a failed preflight.** `doctor && deploy` proceeded
  off-cloud. A failed check now exits as a validation failure, in both text and
  `--format json`.

### Changed

- Dependencies upgraded (AWS SDK v2 1.47, azidentity 1.15, x/oauth2 0.37 and
  the rest); CI's golangci-lint pinned to v2.15.0, which reads Go 1.27.3 export
  data.

## [0.1.0] - 2026-08-29

First tagged release. Before this, `go install …@latest` resolved to a
pseudo-version of an unreleased `main`.

### Added

- **AWS IAM outbound identity federation.** `sts:GetWebIdentityToken` mints an
  RS256 JWT asserting the calling principal, which closes the EC2/ECS/Lambda →
  Azure gap: those runtimes previously had only a SigV4 proof, which GCP's STS
  accepts and Entra does not. Selected with `CLOUD_AUTH_AWS_PROOF`
  (`auto` | `oidc` | `sigv4`) or `source.WithAWSProof`.
- **Control-plane clients for GCP, Azure and Vault.** All four providers now
  reach their service on a real run. Each enforces its cloud's documented
  constraints before the call rather than discovering them from a refusal:
  GCP's attribute-mapping limits, Azure's 20-credential cap, no-wildcards rule
  and creation throttle, Vault's address and token requirements.
- **`k8s-federation` for `--target-cloud aws`.** A Kubernetes ServiceAccount
  federated to AWS is an OIDC role trust with subject
  `system:serviceaccount:<ns>:<name>`, so it translates and delegates rather
  than reimplementing.
- **Audit records** for every operation that issues a credential or changes a
  trust relationship — `exchange`, `credential-process`, `exec`, `setup`,
  `delete` — one JSON line per operation on stderr, on both the success and
  failure paths.
- **Structured diagnostics** via `log/slog`, on stderr, raised by `--verbose`.
- Build matrix covering Windows, so the non-Unix state-lock path is compiled.
- `CONTRIBUTING.md`, `SECURITY.md` and this changelog.

### Changed

- **stdout now carries only results.** Diagnostics, warnings, the delete
  confirmation prompt and audit records moved to stderr, so `--output json` and
  `--format json` stay machine-readable whatever else a run has to say.
- Go 1.27.0, and every dependency updated.
- `validate` and `delete` accept `-v` / `--verbose`, which the README had
  documented but neither parsed.
- `cloud-auth version` reports the real build, set at release time. It
  previously printed a hardcoded `0.2.0` from every binary ever built.
- CI lint is pinned and no longer advisory; `gofmt`, `go mod tidy` and a plain
  `go vet` are enforced; the gosec action is pinned.

### Fixed

- **`cloud-auth doctor` with no arguments segfaulted** — the tool's most common
  invocation. `core.Target` is an interface and an untyped nil has no method
  table. Fixed with a typed zero rather than nil checks at the call sites.
- **`list --output json` emitted prose** when there were no mechanisms, so the
  case a script is most likely to hit was the one that did not produce JSON. The
  table separator was 100 NUL bytes rather than a rule.
- **`internal/redact` had a data race.** `Scrub` released its lock and then
  ranged over the array `AddSecret` sorts in place — which could move a
  registered secret past the cursor, so it reached the output unredacted.
- **Pagination was nondeterministic in both state stores**, since both ranged a
  map before slicing, and an offset past the end returned the full list instead
  of nothing.
- `AADSTS70021` (Entra propagation) is now retried, and only it: the codes are
  prefixes of one another, so a substring match also caught `AADSTS700213` — a
  genuinely wrong subject, which must fail immediately.
- `CreateRole` rejects an out-of-range `MaxSessionDuration` instead of
  truncating `int` to `int32`, which turned `2^32+3600` into a silent 3600.
- Azure `isNotFoundError` checks the typed error, so a 403 no longer reads as
  absence.

### Removed

- **Cloudflare provider.** Cloudflare Access has no workload identity
  federation — only service tokens and mTLS, which are shared secrets. Shipping
  that under this project's banner would have been the opposite of the point.
- `source/azure.go`'s `mintManagedIdentityToken`, which had no caller and a doc
  comment claiming two.

### Security

- Documentation corrected where it claimed federation paths the code refuses on
  purpose. The runtime matrix marked `eks-pod-identity` and Azure managed
  identity as working; both return `ErrNonFederatableSource`, and a ✅ against a
  refusal tells the reader a security control is a bug. A test now pins both
  README matrices to the code.
- Headline examples pin the subject instead of using `repo:org/repo:*`.

[Unreleased]: https://github.com/anirudhbiyani/cloud-auth/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/anirudhbiyani/cloud-auth/releases/tag/v0.1.0
