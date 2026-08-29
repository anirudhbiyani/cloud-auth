# Baseline — PRD v0 Phase 0, Task 0.1

**Date:** 2026-08-29
**Commit:** `5719917` on `dev` — tree-identical to `f25baf1` on `main` (the PR #4 merge commit). `git diff origin/main dev` is empty.
**Toolchain:** go1.27.0 darwin/arm64
**Size:** 27,676 LOC Go across 143 `.go` files (the PRD's 211-file count includes non-Go files)
**Tags:** none

The PRD was written without a Go toolchain. This document is the first execution
of the commands it could not run. **Where this file and the PRD disagree, this
file wins** — every line here is command output, not static reading.

## Toolchain

| Command | Result |
|---|---|
| `go build ./...` | ✅ exit 0, no output |
| `go vet ./...` | ✅ exit 0, no output |
| `go test ./...` | ✅ all 21 packages `ok` |
| `go test -race ./...` | ✅ exit 0, 21 packages `ok` |
| `go test ./test/architecture/ -v` | ✅ all 6 invariants PASS |
| `go test -run 'Fuzz' ./...` | ✅ exit 0, seed corpora pass |
| `golangci-lint run` | ⚠️ **could not run** — see below |
| `git tag` | (empty) |

### golangci-lint does not run against this module

```
can't load config: the Go language version (go1.26) used to build golangci-lint
is lower than the targeted Go version (1.27.0)
```

This is not a local-only problem, and it sharpens **Task 1.6**. CI pins
`version: latest` *and* sets `continue-on-error: true`, so if the released
golangci-lint binary is still built against go1.26, the lint step has been
failing silently on every run since the Go 1.27 bump in `e25b563`. Task 1.6
must confirm a golangci-lint release that targets 1.27 exists before dropping
`continue-on-error`, or the change turns a silent no-op into a hard red build.

## Coverage

**Total: 50.3% of statements.**

| Package | Coverage | Note |
|---|---:|---|
| `internal/httpx` | 100.0% | |
| `internal/cache` | 93.1% | |
| `internal/audit` | 92.3% | |
| `config` | 91.2% | |
| `internal/jwt` | 89.7% | |
| `internal/imds` | 87.5% | |
| `internal/k8stoken` | 84.8% | |
| `target` | 83.0% | |
| `adapters` | 81.8% | |
| `broker` | 81.5% | |
| `provider/cloudflare` | 63.5% | no client; no `nopanic_test.go` |
| `core` | 55.3% | |
| `provider/vault` | 54.5% | no client; no `nopanic_test.go` |
| `provider/gcp` | 49.9% | no client |
| `provider/aws` | 45.3% | only wired provider |
| **`.` (root / CLI)** | **18.7%** | **the Task 1.1 gap, quantified** |
| `provider/azure` | 13.1% | no client |
| `internal/redact` | — | **no test files at all** (Task 1.9) |
| `test/integration` | — | no test files (build-tagged) |

The root package at 18.7% is the direct cause of Task 1.1: there is no test for
`cmdDoctor`, `cmdExchange`, `cmdExec` or `resolveRuntimeConfig`, so a nil-interface
panic on the tool's most common invocation reached a tagged-and-merged `main`.

## PRD blocking claims — verification

### Task 1.1 — `doctor` nil-target panic: **CONFIRMED**

`cloud-auth doctor` with no arguments, exit code **2**:

```
Detected runtime:
  (none) — cloud-auth/source: no supported runtime detected
panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x2 addr=0x20]
main.cmdDoctor(...) runtime.go:167
main.run(...) controlplane.go:66
main.main() main.go:38
```

`runtime.go:167` is exactly the line the PRD names. The detection-only path
prints its first line and then dies on `target.Cloud()`.

### Task 1.2 — machine-readable output: **BOTH CONFIRMED**

(a) `controlplane.go:1335` is `fmt.Println(string(make([]byte, 100)))` — 100 NUL
bytes. `controlplane.go:1407` does the same job correctly with
`strings.Repeat("-", 72)`.

(b) `list --output json` against an empty state file prints `No mechanisms found`
and `jq` rejects it:

```
jq: parse error: Invalid numeric literal at line 1, column 3
```

The early return sits at `controlplane.go:1324-1327`, above the `switch opts.output`.

**Additional finding, same function:** `controlplane.go:1332` is
`data, _ := json.MarshalIndent(refs, ...)` — a discarded error that would print
an empty line as if it were valid JSON. Fold into Task 1.2.

### Task 1.3(b) — README runtime matrix: **CONFIRMED, and the error is mine**

The Runtime Federation Matrix was added in `7839911`, earlier in this same
session, and it is wrong in exactly the way the PRD describes. It was built from
`core/selector.go`'s `knownSubRuntimes` (which lists *detectable* sub-runtimes)
and from which sources emit `core.OIDC`, without checking `Runtime.Federatable`.

Verified against the code:

| Sub-runtime | `Federatable` | README says |
|---|---|---|
| `eks-pod-identity` | `false` — `source/aws.go:139` | ✅✅✅ — **wrong** |
| `vm` | `false` — `source/azure.go:175` | ✅✅✅ — **wrong** |
| `app-service`, `container-apps` | `false` — `source/azure.go:165` | ✅✅✅ — **wrong** |
| `aks-workload-identity` | `true` — `source/azure.go:152` | ✅✅✅ — correct |
| `ec2`, `ecs`, `lambda`, `eks-irsa` | `true` | ✅✅✅ — correct |
| GCP (all four) | `true` — `source/gcp.go:97` | ✅✅✅ — correct |

`source/aws.go:161-166` and `source/azure.go:193-200` return
`ErrNonFederatableSource` for those rows. The Azure refusal carries the reasoning
the PRD quotes: a managed-identity access token is a live bearer credential for
an Azure resource, not an audience-pinned assertion, so forwarding one to a
third-party STS discloses a working Azure credential *and* still fails.

The column header "OIDC (managed identity token)" on that row is a category
error and must go with it.

### Task 1.4 — four client-less providers: **CONFIRMED**

`grep` for `http.Client`, `http.NewRequest` or any cloud SDK across
`provider/{gcp,azure,cloudflare,vault}` returns nothing. No `With*Client` call
appears anywhere outside tests. AWS is the exception and is wired *lazily by the
provider itself* at `provider/aws/provider.go:45` calling `NewIAMClient`, not by
`controlplane.go`.

Live, with an otherwise fully valid spec:

```
$ cloud-auth setup --type gcp-wif --project-id my-project ... --subject-scope ...
Error: setup failed: [gcp:validation] GCP Workload Identity client not configured
```

Reaching that error took three successive validation refusals first
(`attribute_condition` required, then `subject_scope`/`attribute_scope` required).
Those refusals are good — they are the confused-deputy guardrails — but they mean
the "client not configured" wall is only met by someone who has already done
everything right.

`provider/cloudflare` and `provider/vault` have **no `nopanic_test.go`**, as the
PRD states. Only `aws`, `azure` and `gcp` do.

### Task 1.5 — `k8s-federation`: **CONFIRMED**

`K8sServiceAccountFederationSpec` appears in `controlplane.go`, `core/specs.go`,
`core/doc.go` and `README.md` — and in **no provider**. Live, exit code **1**,
even with `--dry-run`:

```
Error: setup failed: [aws:validation] unsupported spec type: *core.K8sServiceAccountFederationSpec
```

## What is already healthy

Recorded so a later change cannot quietly undo it: build, vet, race and fuzz all
clean; all six architecture invariants pass; `internal/httpx` at 100%; the whole
`target` data plane above 80%. The PRD's Appendix A properties were spot-checked
against the tree and hold.
