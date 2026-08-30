# Live control-plane tests

`matrix_test.go` covers the **runtime** half — a workload exchanging a proof for
credentials — and is driven by the OpenTofu harness in `../harness/`.

`controlplane_test.go` covers the other half: `setup` → `validate` → `delete`
against a real cloud API. It exists because the GCP, Azure and Vault clients
otherwise have only fake-server coverage, and **a fake agrees with whatever the
code believes the protocol is**. That is precisely the class of mistake it
cannot catch — `client_arm.go` silently not compiling was found by a build
matrix, not by its tests.

Everything here is behind `//go:build integration` and **skips** unless the
environment names a real project. Skipping rather than failing is deliberate: a
contributor without a GCP project should see the suite pass, not a wall of red
they cannot act on.

```bash
go test -tags integration ./test/integration/ -run Lifecycle -v
```

## Environment

| Variable | Used by |
|---|---|
| `CLOUD_AUTH_IT_OIDC_ISSUER` | all — an issuer already registered in each account |
| `CLOUD_AUTH_IT_AWS_ACCOUNT_ID` | AWS |
| `CLOUD_AUTH_IT_GCP_PROJECT_ID`, `_GCP_PROJECT_NUMBER`, `_GCP_SERVICE_ACCOUNT` | GCP |
| `CLOUD_AUTH_IT_AZURE_TENANT_ID`, `_AZURE_SUBSCRIPTION_ID` | Azure |
| `CLOUD_AUTH_IT_AZURE_APP_OBJECT_ID` | the manual FIC-cap case |

Credentials come from the ambient chain each provider already uses — AWS shared
config, `gcloud auth application-default login`, `az login`.

## What these assert

Beyond "it worked":

- **Cleanup is registered immediately after setup**, so a failure part-way still
  removes the trust relationship. A test that leaves a federated role behind is
  worse than one that fails — it leaves a trust nobody is watching.
- **A dry run creates nothing**, checked by the delete at the end finding exactly
  one thing to remove.
- **Validate ran real checks.** `HasChecks()` is asserted before the result is
  read at all: a report with no checks is a vacuous pass, not a pass.
- **Setup is idempotent.** Re-running must not fail and must not create a second
  resource — an operator re-running a pipeline is the common case, not an edge
  one.

## Costs and limits

These create real resources. They are cheap, but they are not free, and two
Azure limits make that suite slower than it looks: federated credential creation
is throttled to roughly 0.25 requests per second per resource, and a newly
created credential does not work for the first few minutes while Entra
replicates it.

The 20-credentials-per-application cap has a placeholder case that **skips by
default**. Proving the 21st is refused means creating twenty first, which is
destructive and slow, so it is something to run deliberately rather than on
every CI pass.
