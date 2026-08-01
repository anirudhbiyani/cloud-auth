# Harness contract (authoritative)

Every module in this harness codes against **this file**. Do not invent alternative
names — the stage-2 modules and the verifier consume these exact keys.

Tooling: **OpenTofu** (`tofu`), not Terraform. HCL is compatible, but all docs,
scripts, and CI must invoke `tofu`. Local state only (`terraform.tfstate` in each
module dir, gitignored) — no remote backend, no vendor login.

## Why two stages

The three clouds' trusts are mutually dependent: an AWS IAM OIDC provider needs
GCP's / Azure's issuer URL; a GCP WIF provider needs AWS's EKS OIDC issuer; an
Azure FIC needs both. You cannot express that as one apply across three providers
without a cycle. So:

- **stage1 (compute)** — create source runtimes; export issuer URLs + subjects.
- **stage2 (trust)** — consume every cloud's stage-1 facts; create the trust objects.
- **verify** — run the verifier inside each source runtime; assert each pair works.
- **destroy** — stage2 down, then stage1 down, per cloud.

## Shared conventions

- Resource name prefix: `var.name_prefix`, default `cloud-auth-test`.
- Every resource carries tags/labels: `managed-by = "cloud-auth-harness"`,
  `run-id = var.run_id` (so orphans are findable and bulk-deletable).
- Kubernetes namespace / service account: `cloud-auth-test` / `verifier`.
- Every module writes its outputs as JSON to `test/harness/state/<cloud>-<stage>.json`
  via an `output` consumed by the driver scripts (`tofu output -json`).
- No secrets in state files that get committed. `test/harness/state/` is gitignored
  except `.gitkeep` and `*.example.json`.

## stage1 outputs — exact keys

### `state/aws-stage1.json`
```json
{
  "account_id": "123456789012",
  "region": "us-east-1",
  "eks_cluster_name": "cloud-auth-test",
  "eks_oidc_issuer_url": "https://oidc.eks.us-east-1.amazonaws.com/id/ABC123",
  "eks_oidc_issuer_host_path": "oidc.eks.us-east-1.amazonaws.com/id/ABC123",
  "irsa_namespace": "cloud-auth-test",
  "irsa_service_account": "verifier",
  "irsa_subject": "system:serviceaccount:cloud-auth-test:verifier",
  "ec2_instance_id": "i-0abc",
  "ec2_role_arn": "arn:aws:iam::123456789012:role/cloud-auth-test-ec2-source",
  "ec2_role_name": "cloud-auth-test-ec2-source"
}
```

### `state/gcp-stage1.json`
GCE VM is the OIDC source (issuer `https://accounts.google.com`, `sub` = the service
account's numeric unique id). GKE is optional/not required for v1 of the harness.
```json
{
  "project_id": "my-proj",
  "project_number": "123456789",
  "region": "us-central1",
  "zone": "us-central1-a",
  "source_sa_email": "cloud-auth-test-src@my-proj.iam.gserviceaccount.com",
  "source_sa_unique_id": "109876543210987654321",
  "issuer_url": "https://accounts.google.com",
  "gce_instance_name": "cloud-auth-test-src"
}
```

### `state/azure-stage1.json`
```json
{
  "tenant_id": "aaaa-...",
  "subscription_id": "bbbb-...",
  "location": "eastus",
  "resource_group": "cloud-auth-test",
  "aks_cluster_name": "cloud-auth-test",
  "aks_oidc_issuer_url": "https://eastus.oic.prod-aks.azure.com/aaaa/bbbb/",
  "namespace": "cloud-auth-test",
  "service_account": "verifier",
  "subject": "system:serviceaccount:cloud-auth-test:verifier"
}
```

## stage2 outputs — exact keys

Stage 2 for cloud X creates the trust that lets **other** clouds in. Naming is
`*_for_<source>_source`.

### `state/aws-stage2.json`  (AWS as TARGET)
```json
{
  "audience": "sts.amazonaws.com",
  "role_arn_for_gcp_source": "arn:aws:iam::123:role/cloud-auth-test-from-gcp",
  "role_arn_for_azure_source": "arn:aws:iam::123:role/cloud-auth-test-from-azure"
}
```
- OIDC provider for Azure: url = `aks_oidc_issuer_url`, client id = `audience`.
- **GCP needs no IAM OIDC provider.** Google (like Facebook/Cognito) is a built-in
  AWS IdP; the trust-policy principal is the bare string `"accounts.google.com"`,
  not a provider ARN.
- Trust policies condition on `:sub` = the source subject (GCP:
  `source_sa_unique_id`; Azure: `subject`).
- **Audience pinning differs per IdP — do not blindly use `:aud`.** For
  `accounts.google.com`, AWS maps `:aud` to the token's **`azp`** claim whenever
  `azp` is present, and exposes the real `aud` as **`:oaud`**. Google service-account
  ID tokens *do* set `azp`, so conditioning on `accounts.google.com:aud = <audience>`
  would **never match** and the pair fails with an opaque AccessDenied. Pin the
  audience with `:oaud` for Google; `:aud` is correct for the Azure (generic OIDC)
  provider. Ref: AWS IAM condition-key reference.
- **Azure issuer trailing slash:** AKS issuer URLs end with `/`. Whether IAM
  preserves it in the condition key prefix is undocumented, so emit one fully-scoped
  statement per candidate prefix (with and without the slash) rather than relaxing
  any condition.
- Attach a harmless read policy (e.g. `sts:GetCallerIdentity` is implicit; grant
  `s3:ListAllMyBuckets`) so the verifier can prove the creds actually work.

### `state/gcp-stage2.json`  (GCP as TARGET)
```json
{
  "pool_id": "cloud-auth-test",
  "provider_for_aws_oidc":   "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/cloud-auth-test/providers/aws-oidc",
  "provider_for_azure_oidc": "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/cloud-auth-test/providers/azure-oidc",
  "provider_for_aws_sigv4":  "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/cloud-auth-test/providers/aws-sigv4",
  "audience_for_aws_oidc":   "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/cloud-auth-test/providers/aws-oidc",
  "audience_for_azure_oidc": "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/cloud-auth-test/providers/azure-oidc",
  "audience_for_aws_sigv4":  "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/cloud-auth-test/providers/aws-sigv4",
  "test_bucket": "cloud-auth-test-<run_id>"
}
```
- Use **direct resource access**: bind roles to `principal://` / `principalSet://`
  on the pool subject — do NOT require SA impersonation (that path is the opt-in
  fallback, not the default under test).
- Grant `roles/storage.objectViewer` on `test_bucket` to the federated principal so
  the verifier can prove the token works.

### `state/azure-stage2.json`  (Azure as TARGET)
```json
{
  "audience": "api://AzureADTokenExchange",
  "tenant_id": "aaaa-...",
  "client_id_for_gcp_source": "cccc-...",
  "client_id_for_aws_source": "dddd-..."
}
```
- One user-assigned managed identity (or app registration) per source, each with a
  federated identity credential: issuer = source issuer URL, subject = source
  subject, audience = `audience`. **Issuer/subject/audience match is
  case-sensitive** — emit them exactly as stage 1 reported them.

## The pair matrix under test

| # | Source runtime | Target | Mechanism | Needs |
|---|---|---|---|---|
| 1 | GCP GCE | AWS | AssumeRoleWithWebIdentity | `aws-stage2.role_arn_for_gcp_source` |
| 2 | GCP GCE | Azure | FIC client assertion | `azure-stage2.client_id_for_gcp_source` |
| 3 | Azure AKS-WI | AWS | AssumeRoleWithWebIdentity | `aws-stage2.role_arn_for_azure_source` |
| 4 | Azure AKS-WI | GCP | WIF (oidc) | `gcp-stage2.provider_for_azure_oidc` |
| 5 | AWS EKS-IRSA | GCP | WIF (oidc) | `gcp-stage2.provider_for_aws_oidc` |
| 6 | AWS EKS-IRSA | Azure | FIC client assertion | `azure-stage2.client_id_for_aws_source` |
| 7 | AWS EC2 | GCP | WIF (aws / SigV4) | `gcp-stage2.provider_for_aws_sigv4` |
| — | AWS EC2 | Azure | **documented gap** — must fail with `ErrNoFirstClassPath` | asserts the guard |

Rows 1–6 are the six first-class pairs. Row 7 additionally covers the SigV4 path.
The final row is a **negative** test: the harness asserts cloud-auth refuses with
actionable guidance rather than failing obscurely.

## `state/targets.json` — what the verifier reads

The driver merges the stage-2 files into one verifier input. The verifier does NOT
read tofu state.
```json
{
  "run_id": "20260705-abc123",
  "cases": [
    {
      "name": "gcp-gce-to-aws",
      "expect": "success",
      "source_runtime": "gcp-gce",
      "target": { "cloud": "aws", "role": "arn:aws:iam::123:role/...", "audience": "sts.amazonaws.com" },
      "probe": "sts-get-caller-identity"
    },
    {
      "name": "aws-ec2-to-azure-gap",
      "expect": "error",
      "expect_error": "ErrNoFirstClassPath",
      "source_runtime": "aws-ec2",
      "target": { "cloud": "azure", "tenant": "...", "client_id": "...", "audience": "api://AzureADTokenExchange" }
    }
  ]
}
```
Each case's `source_runtime` tells the driver **where** to run it; the verifier
process only executes the cases matching the runtime it finds itself on
(it calls cloud-auth's own detection to decide).

## Non-negotiable safety rules

1. **Destroy must always be possible.** `down.sh` tears down stage2 then stage1 and
   must succeed even if `verify` failed or a stage-2 apply half-failed. Never make
   destroy depend on verify passing.
2. **No auto-run in CI.** The GitHub workflow is `workflow_dispatch` only. Never on
   `push`/`pull_request` — it costs money and needs cloud credentials.
3. **Cost warning + confirmation.** `up.sh` prints an itemized cost estimate and
   requires an explicit confirmation (`--yes` for automation) before applying.
4. **No credentials or tokens in logs or state committed to git.** Redact tokens in
   verifier output — report success/failure and identity, never the raw JWT/secret.
5. **Everything tagged** with `managed-by=cloud-auth-harness` + `run-id` so a stray
   `down` failure leaves findable, sweepable resources.
