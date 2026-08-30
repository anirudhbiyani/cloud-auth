# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is 0, the public Go API may change in a minor release.
Breaking changes are called out explicitly.

## [Unreleased]

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
