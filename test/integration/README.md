# Cloud integration tests

Go tests that exercise the source→target pair matrix in
[`../harness/CONTRACT.md`](../harness/CONTRACT.md) against **real cloud
infrastructure**. They are behind the `integration` build tag, so
`go test ./...` never runs them.

```sh
go test -tags integration -v ./test/integration/...
```

On a laptop with no harness state this **skips** every test with an explanatory
message. It never fails and never hangs: plan loading is a file check, and
runtime detection is bounded to 10s.

## What must exist first

1. **Harness applied.** `test/harness/scripts/up.sh` applies stage 1 (compute)
   then stage 2 (trust) for all three clouds and writes
   `test/harness/state/<cloud>-stage<n>.json`.
2. **Merged plan.** The driver merges the stage-2 outputs into
   `test/harness/state/targets.json` — the only file these tests read. They do
   not read tofu state.
3. **Execution inside a source runtime.** Each case declares the
   `source_runtime` it belongs to. A test process runs only the cases matching
   the runtime it detects (via cloud-auth's own detector) and skips the rest, so
   the full matrix is covered by running this same suite in *every* source
   runtime: EKS-IRSA pod, AKS workload-identity pod, EC2 instance, GCE instance.
4. **Ambient identity only.** No static credentials. The pod/instance identity
   is the input; anything else means the test is not testing what it claims to.

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `../harness/state/targets.json` | — | merged plan (tests run with this package as cwd) |
| `$CLOUD_AUTH_TARGETS_FILE` | unset | path override for the plan |
| `$CLOUD_AUTH_TARGETS_JSON` | unset | the plan inline, for ConfigMap/user-data delivery |

## Tests

| Test | What it asserts |
|---|---|
| `TestPairMatrix` | one subtest per case, named after the case. Cases for other runtimes skip; a matching case must produce non-empty, unexpired credentials (`expect: "success"`) or fail with the named sentinel via `errors.Is` (`expect: "error"`). |
| `TestPlanCoversTheDocumentedGap` | the plan actually contains the negative row — AWS-EC2 → Azure asserting `ErrNoFirstClassPath`. Without it the suite could go green while the guard rotted away. |
| `TestPlanRuntimeCoverage` | logs how many cases each source runtime owns, so a run where a runtime was never scheduled is visible instead of silently all-skipped. |

Subtest names come from the plan, so failures read as the pair that broke:

```
--- FAIL: TestPairMatrix/azure-aks-wi-to-gcp
```

## Relationship to the verifier

These tests and `test/harness/verifier` share one implementation
(`test/harness/verifier/verify`): the same case selection, sentinel mapping,
credential assertions, probes, and redaction. The verifier is the container
image the harness schedules in each runtime; this suite is the same logic driven
by `go test` when you are already on the box and want per-pair output.

Both go through `broker.Broker` — the real detect→mint→exchange path — never a
reimplementation of it.

## Output safety

No credential, token, or assertion value is ever logged. Results are emitted as
scrubbed JSON: identity metadata (issuer, subject, role, pool, client id, STS
request id, expiry) and outcomes only. See `verify.Scrubber` and its tests.
