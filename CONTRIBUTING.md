# Contributing to cloud-auth

Thanks for your interest. This document covers what a change needs before it can
merge, and the few conventions that are not obvious from the code.

## Developer Certificate of Origin

Contributions are accepted under the [Developer Certificate of Origin][dco].
Sign off every commit:

```bash
git commit -s -m "your message"
```

That adds a `Signed-off-by:` trailer, which certifies you wrote the patch or
otherwise have the right to submit it under the project's licence. A pull
request whose commits are not signed off cannot be merged.

[dco]: https://developercertificate.org/

## Licence

This project is licensed under **AGPL-3.0**. By contributing, you agree your
contribution is licensed under the same terms.

## Before you open a pull request

Everything CI runs, you can run:

```bash
go build ./...
go vet ./...
go test -race ./...
gofmt -l .
go mod tidy -diff
golangci-lint run
```

A change is ready when all of those are clean and:

1. **New or changed logic has a test.** Table-driven, in the package it tests.
2. **Documentation changes in the same commit as the code.** A README that
   describes behaviour the code does not have is treated here as a build
   failure, not a docs bug. `readme_matrix_test.go` enforces part of this
   automatically.
3. **No new dependency without a one-line justification in the commit message.**
   Prefer the standard library, then something already in `go.mod`. The
   exception that is always worth making is credential handling — see below.

## Things that will fail review

### Weakening an architecture test to make a change compile

`test/architecture/layering_test.go` enforces six rules: the data plane must not
import `provider/*`, `core` imports no first-party package, providers do not
import each other, adapters depend on neither source nor target,
`internal/redact` stays dependency-free, and there are no import cycles
including test-only edges the compiler ignores.

If a change does not fit, change the design. These are the rules that keep
`core` a leaf and keep the two planes separable.

### Turning a skipped check into a passing one

Validators that cannot reach their data source report **Skipped**, with an
explicit "was NOT verified" message and manual remediation text. `Valid: true`
means *nothing failed*, not *everything was checked*.

Never convert a skip into a pass to make output look cleaner. If you are
tempted, the fix is to make the check able to run.

### Hand-rolling a credential path

Signing a service-account assertion, implementing a refresh-token flow, or
reimplementing a cloud's default credential chain is exactly where a dependency
earns its place. `x/oauth2/google` and `azidentity` are here for that reason. Say
so in the commit message and it will not be questioned.

### Retrying a 4xx

A rejected trust does not become accepted on the third attempt, and retrying it
turns a clear misconfiguration into a slow one. There are exactly three
documented exceptions in `target/te.go` — 429, in-body throttle codes, and
Entra's `AADSTS70021` propagation window — each a named code rather than a rule
about a status class. Adding a fourth needs the same treatment and a comment
saying why.

### A new failure mode expressed as string matching

Errors that a user needs to act on differently get a sentinel
(`ErrNonFederatableSource`, `ErrNoFirstClassPath`, `ErrTrustMissing`,
`ErrRuntimeMismatch`), which flows from the deepest layer up to a specific
paragraph in `doctor`. New failure modes get new sentinels, not
`strings.Contains`.

## Commit messages

Explain **why**, not what — the diff already says what. Where a decision has a
trade-off, or where the obvious alternative is wrong, record that. Several of
this project's sharper design notes exist only in commit messages, and they are
what makes the code reviewable a year later.

Conventional-commit prefixes (`feat:`, `fix:`, `docs:`, `chore:`) are used but
not enforced.

## Getting set up

```bash
git clone https://github.com/anirudhbiyani/cloud-auth.git
cd cloud-auth
go mod download
go test ./...
```

No cloud credentials are needed for the test suite. Live-cloud tests are behind
`//go:build integration` and the OpenTofu harness in `test/harness/`.

## Reporting a vulnerability

Do not open a public issue. See [SECURITY.md](SECURITY.md).
