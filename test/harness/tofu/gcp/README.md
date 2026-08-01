# GCP harness modules (OpenTofu)

Real infrastructure for the cloud-auth cross-cloud federation harness. Two
applyable modules, both governed by [`../../CONTRACT.md`](../../CONTRACT.md):

| Module   | Role                | Depends on                                            |
| -------- | ------------------- | ----------------------------------------------------- |
| `stage1` | GCP as a **source** | nothing                                                |
| `stage2` | GCP as a **target** | AWS + Azure stage-1 facts, passed in as tfvars         |

> **Tooling is OpenTofu.** Every command below is `tofu`, not `terraform`. The
> HCL dialect is shared, but the harness pins `tofu` so the provider lock file
> and registry namespace stay consistent. State is local
> (`terraform.tfstate` in each module directory) and gitignored — there is no
> remote backend and no vendor login.

```
tofu -chdir=test/harness/tofu/gcp/stage1 init
tofu -chdir=test/harness/tofu/gcp/stage1 apply
tofu -chdir=test/harness/tofu/gcp/stage2 init
tofu -chdir=test/harness/tofu/gcp/stage2 apply
```

---

## stage1 — GCP as a source runtime

### What it creates

| Resource                         | Notes                                                           |
| -------------------------------- | --------------------------------------------------------------- |
| `google_service_account`         | `<name_prefix>-src`. **Zero project IAM roles** — pure identity. |
| `google_compute_instance`        | `<name_prefix>-src`, `e2-micro`, 10 GB `pd-standard`, default network, runs as the SA above. |
| `google_project_service` × 3     | `compute`, `iam`, `iamcredentials` (skippable via `enable_apis = false`). |

No GKE cluster. For v1 of the harness the GCE VM *is* the GCP source runtime; a
cluster would cost more than everything else in the run combined.

### Why a plain VM is enough

The GCE metadata server will mint a Google-signed OIDC ID token for any
audience, to any process on the box, with no credentials required:

```sh
curl -s -H 'Metadata-Flavor: Google' \
  'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/identity?audience=sts.amazonaws.com&format=full'
```

- `iss` = `https://accounts.google.com`
- **`sub` = the service account's numeric unique id**, *not* its email.

That last point is the whole reason `source_sa_unique_id` is an output. An AWS
role trust policy or an Azure federated identity credential that conditions on
`cloud-auth-test-src@PROJECT.iam.gserviceaccount.com` will never match. It must
condition on the 21-digit numeric id.

### Outputs (`state/gcp-stage1.json`)

```
project_id            e.g. my-proj
project_number        e.g. 123456789
region                e.g. us-central1
zone                  e.g. us-central1-a
source_sa_email       cloud-auth-test-src@my-proj.iam.gserviceaccount.com
source_sa_unique_id   109876543210987654321   <-- foreign trusts scope to THIS
issuer_url            https://accounts.google.com
gce_instance_name     cloud-auth-test-src
```

Serialise them for the driver with:

```sh
tofu -chdir=test/harness/tofu/gcp/stage1 output -json \
  | jq 'map_values(.value)' > test/harness/state/gcp-stage1.json
```

The output set is exactly these eight keys — adding any output here would leak
an extra key into the contract file.

Reaching the VM (not an output; look it up when the driver needs it):

```sh
gcloud compute ssh cloud-auth-test-src --zone us-central1-a --tunnel-through-iap
```

`assign_external_ip = true` (default) attaches an ephemeral external IPv4 so
plain `gcloud compute ssh` works on the default network's `default-allow-ssh`
rule. Set it to `false` to save ~$0.004/hour, at the cost of needing IAP TCP
forwarding plus a firewall rule for `35.235.240.0/20` on `tcp:22`.

---

## stage2 — GCP as a target cloud

### What it creates

| Resource                                          | Notes                                                        |
| ------------------------------------------------- | ------------------------------------------------------------ |
| `google_iam_workload_identity_pool`                | one pool, id includes `run_id` (see soft delete below)        |
| provider `aws-oidc`                                | **OIDC** type — trusts the EKS cluster's OIDC issuer          |
| provider `azure-oidc`                              | **OIDC** type — trusts the AKS cluster's OIDC issuer          |
| provider `aws-sigv4`                               | **AWS** type — `aws { account_id = ... }`, no issuer          |
| `google_storage_bucket` + one probe object         | the thing the verifier reads to prove the token works         |
| 3 × `google_storage_bucket_iam_member`             | `roles/storage.objectViewer` bound to each federated principal |
| `google_project_service` × 4                       | `iam`, `sts`, `iamcredentials`, `storage`                     |

### Inputs

stage2 consumes the *other* clouds' stage-1 facts as ordinary variables. It
never reads another cloud's tofu state. The driver writes
`stage2/harness.auto.tfvars` (gitignored, auto-loaded) from
`state/aws-stage1.json` and `state/azure-stage1.json` — see
[`stage2/harness.auto.tfvars.example`](stage2/harness.auto.tfvars.example).

| Variable                    | Source                                 |
| --------------------------- | -------------------------------------- |
| `aws_account_id`            | `aws-stage1.account_id`                |
| `aws_eks_oidc_issuer_url`   | `aws-stage1.eks_oidc_issuer_url`       |
| `aws_irsa_subject`          | `aws-stage1.irsa_subject`              |
| `aws_ec2_role_name`         | `aws-stage1.ec2_role_name`             |
| `azure_aks_oidc_issuer_url` | `azure-stage1.aks_oidc_issuer_url`     |
| `azure_subject`             | `azure-stage1.subject`                 |

These six have **no defaults on purpose**. They are foreign trust anchors; a
stale or wrong value is a confused-deputy hole, not an inconvenience, so the
module refuses to guess.

### OIDC providers vs. the AWS provider — the distinction that matters

`aws-oidc` and `azure-oidc` are ordinary OIDC providers: the source workload
presents a JWT, Google fetches the issuer's JWKS and verifies the signature.

`aws-sigv4` is a **different provider type**. An EC2 instance has no OIDC
identity document, so the subject token is not a JWT at all — it is a
SigV4-signed, pre-signed `sts:GetCallerIdentity` request, submitted with
`subject_token_type=urn:ietf:params:aws:token-type:aws4_request`. Google
*replays* that request against AWS STS and takes the returned ARN as the
assertion. Hence the `aws { account_id = ... }` block instead of
`oidc { issuer_uri = ... }`, and hence the claims available to attribute
mapping are `assertion.arn` / `assertion.account` / `assertion.userid`, not
`sub` / `iss` / `aud`.

### Attribute conditions — scoped, not wide open

Every provider carries an `attribute_condition`. An unscoped pool means any
workload the issuer will sign for can walk in:

| Provider     | Condition                                                                 |
| ------------ | ------------------------------------------------------------------------- |
| `aws-oidc`   | `assertion.sub == '<aws_irsa_subject>'`                                   |
| `azure-oidc` | `assertion.sub == '<azure_subject>'`                                      |
| `aws-sigv4`  | `assertion.account == '<aws_account_id>' && attribute.aws_role == '<aws_ec2_role_name>'` |

### Why `google.subject` is namespaced

A `principal://` identifier is scoped to the **pool**, not to the provider — the
subject string alone determines who you are. Both Kubernetes sources in this
harness present the identical `sub`
(`system:serviceaccount:cloud-auth-test:verifier`), so mapping
`google.subject = assertion.sub` on both providers would collapse the EKS pod
and the AKS pod into a single GCP principal. Each OIDC provider therefore
prefixes a literal:

```
aws-oidc    google.subject = 'aws-eks::'   + assertion.sub
azure-oidc  google.subject = 'azure-aks::' + assertion.sub
```

`aws-sigv4` maps `google.subject = assertion.arn`, whose trailing session
component is the EC2 instance id and so changes per instance. The IAM binding
therefore targets the stable derived attribute instead:

```
attribute.aws_role = assertion.arn.extract('assumed-role/{role_name}/')
```

### Direct resource access — no impersonation

Roles are bound straight to the federated principal:

```
principal://iam.googleapis.com/projects/<NUM>/locations/global/workloadIdentityPools/<POOL>/subject/aws-eks::system:serviceaccount:cloud-auth-test:verifier
principal://iam.googleapis.com/projects/<NUM>/locations/global/workloadIdentityPools/<POOL>/subject/azure-aks::system:serviceaccount:cloud-auth-test:verifier
principalSet://iam.googleapis.com/projects/<NUM>/locations/global/workloadIdentityPools/<POOL>/attribute.aws_role/<aws_ec2_role_name>
```

There is **no** `roles/iam.workloadIdentityUser` binding and no service account
to impersonate. In cloud-auth, impersonation is the opt-in fallback for
services that still cannot consume `external_account` credentials — it is not
the default, so the harness must not test it as if it were.

The bucket sets `uniform_bucket_level_access = true`: legacy ACLs cannot
express a federated principal, so IAM-only is a hard requirement here, not a
style preference.

### Audiences

`allowed_audiences` is deliberately left unset on both OIDC providers. With no
override, Google accepts the provider's own full resource name as the audience,
in both the `//iam.googleapis.com/...` and `https://iam.googleapis.com/...`
spellings — and the `//` form is exactly what the contract's `audience_*`
outputs emit. Setting `allowed_audiences` would *replace* those defaults and
break the contract.

### Outputs (`state/gcp-stage2.json`)

```
pool_id                  cloud-auth-test-<run_id>
provider_for_aws_oidc    //iam.googleapis.com/projects/<NUM>/locations/global/workloadIdentityPools/<POOL>/providers/aws-oidc
provider_for_azure_oidc  //iam.googleapis.com/.../providers/azure-oidc
provider_for_aws_sigv4   //iam.googleapis.com/.../providers/aws-sigv4
audience_for_aws_oidc    (same string as provider_for_aws_oidc)
audience_for_azure_oidc  (same string as provider_for_azure_oidc)
audience_for_aws_sigv4   (same string as provider_for_aws_sigv4)
test_bucket              cloud-auth-test-<run_id>
```

`provider_*` and `audience_*` are the same value by design: the provider
resource name *is* the audience the source must present. They are separate keys
because they play different roles at exchange time — one names the trust
object, the other is what goes in the token's `aud` claim.

```sh
tofu -chdir=test/harness/tofu/gcp/stage2 output -json \
  | jq 'map_values(.value)' > test/harness/state/gcp-stage2.json
```

---

## Cost estimate

List prices, `us-central1`, at time of writing. Check the
[GCP pricing calculator](https://cloud.google.com/products/calculator) for
current numbers — these are estimates for the cost warning `up.sh` prints, not
a billing guarantee.

| Item                                        | Per hour     | Per day     | Notes                              |
| ------------------------------------------- | ------------ | ----------- | ---------------------------------- |
| stage1 · `e2-micro` VM (on-demand)          | **$0.00838** | **$0.201**  | 0.25 vCPU / 1 GB                   |
| stage1 · 10 GB `pd-standard` boot disk      | **$0.00055** | **$0.013**  | $0.040 / GB-month                  |
| stage1 · ephemeral external IPv4 (in use)   | **$0.00400** | **$0.096**  | $0 if `assign_external_ip = false` |
| stage1 · service account                    | $0           | $0          | free                               |
| stage2 · Workload Identity Pool             | $0           | $0          | **free**                           |
| stage2 · 3 WIF providers                    | $0           | $0          | **free**                           |
| stage2 · STS token exchanges                | $0           | $0          | **free**                           |
| stage2 · GCS bucket + 1 tiny object         | ~$0          | ~$0         | $0.026 / GB-month; bytes, not GB   |
| stage2 · GCS class A/B operations           | ~$0          | ~$0         | a handful of requests per run      |
| Network egress                              | ~$0          | ~$0         | token exchanges are kilobytes      |
| **Total**                                   | **~$0.013**  | **~$0.31**  | **~$9.40 / month if left running** |

Practical framing: a harness run that applies, verifies and destroys inside an
hour costs **about one and a half US cents** on the GCP side. The failure mode
that actually costs money is a *leaked* VM — hence the label-based sweep below.

Levers:

- `assign_external_ip = false` → −$0.096/day (needs IAP for SSH).
- `preemptible = true` → e2-micro Spot is roughly $0.0025/hour instead of
  $0.0084. Off by default: a preemption mid-verify is a spurious failure.
- Google Cloud's Free Tier covers one non-preemptible `e2-micro` per month in
  `us-west1` / `us-central1` / `us-east1` plus 30 GB-months of `pd-standard`,
  so on an eligible billing account the VM may cost nothing at all.

---

## Required APIs

Both modules enable what they need by default (`enable_apis = true`,
`disable_on_destroy = false` — an API is never turned back off on destroy).
Set `enable_apis = false` if the caller cannot manage service usage.

| API                          | Needed by      | For                                        |
| ---------------------------- | -------------- | ------------------------------------------ |
| `compute.googleapis.com`     | stage1         | the GCE source VM                          |
| `iam.googleapis.com`         | stage1, stage2 | service accounts, WIF pools and providers  |
| `iamcredentials.googleapis.com` | stage1, stage2 | ID-token minting / credential generation |
| `sts.googleapis.com`         | stage2         | the `sts.googleapis.com/v1/token` exchange |
| `storage.googleapis.com`     | stage2         | the probe bucket                           |

```sh
gcloud services enable \
  compute.googleapis.com iam.googleapis.com iamcredentials.googleapis.com \
  sts.googleapis.com storage.googleapis.com --project "$PROJECT_ID"
```

## Required permissions

Easiest is `roles/owner` on a throwaway project. Least privilege:

**stage1**

- `roles/compute.instanceAdmin.v1` — create/delete the VM and its disk
- `roles/iam.serviceAccountAdmin` — create/delete the source service account
- `roles/iam.serviceAccountUser` **on the source SA** — required to attach it
  to the VM (`actAs`); a common first-run failure
- `roles/serviceusage.serviceUsageAdmin` — only if `enable_apis = true`

**stage2**

- `roles/iam.workloadIdentityPoolAdmin` — pool and providers
- `roles/storage.admin` — create the bucket, write the probe object, set
  bucket IAM
- `roles/serviceusage.serviceUsageAdmin` — only if `enable_apis = true`

`roles/resourcemanager.projectIamAdmin` is **not** needed: nothing here touches
project-level IAM. All grants are bucket-scoped.

---

## Destroying

Order matters — stage2 first, then stage1 (safety rule #1: this must work even
if `verify` failed or a stage-2 apply half-failed).

```sh
tofu -chdir=test/harness/tofu/gcp/stage2 destroy -auto-approve
tofu -chdir=test/harness/tofu/gcp/stage1 destroy -auto-approve
```

Nothing in either module has deletion protection, retention or a `prevent`
deletion policy:

- `google_compute_instance.deletion_protection = false`
- `google_storage_bucket.force_destroy = true` (objects go with the bucket)
- both WIF resources set `deletion_policy = "DELETE"`

### ⚠️ WIF soft delete — read before re-running

**Deleted Workload Identity Pools and providers are soft-deleted for
approximately 30 days.** During that window:

- the pool still exists in a `DELETED` state,
- **its id cannot be reused** — recreating a pool with the same id fails until
  the old one is purged,
- it can be restored with
  `gcloud iam workload-identity-pools undelete POOL_ID --location=global`,
- already-issued credentials stop granting access, but they start working again
  if the pool is undeleted before they expire.

This module handles it by folding `run_id` into the pool id by default
(`include_run_id_in_pool_id = true`), so every run gets a fresh id:
`cloud-auth-test-20260705-abc123`. Two consequences:

1. **Do not set `include_run_id_in_pool_id = false`** unless you are willing to
   wait 30 days between runs, or to `undelete` the old pool first.
2. Pool ids are capped at 32 characters and the module truncates to fit. With
   the default 15-character `name_prefix`, keep `run_id` at **16 characters or
   fewer** or the distinguishing tail gets cut off and runs collide again. The
   contract's `20260705-abc123` (15 chars) fits exactly.

Provider ids (`aws-oidc`, `azure-oidc`, `aws-sigv4`) are fixed by the contract,
but they live *inside* the per-run pool, so they never collide.

### Sweeping orphans

Everything that supports GCP labels carries
`managed-by=cloud-auth-harness` and `run-id=<run_id>`:

```sh
RUN_ID=20260705-abc123

# VMs
gcloud compute instances list \
  --filter="labels.managed-by=cloud-auth-harness AND labels.run-id=${RUN_ID}" \
  --format='value(name,zone)'
gcloud compute instances delete NAME --zone ZONE --quiet

# Buckets
gcloud storage buckets list \
  --filter="labels.managed-by=cloud-auth-harness AND labels.run-id=${RUN_ID}" \
  --format='value(name)'
gcloud storage rm --recursive gs://BUCKET
```

Service accounts, WIF pools and WIF providers have **no `labels` field** in the
GCP API. The modules stamp the same facts into `description` / `display_name`
instead, so sweep those by name and description:

```sh
# Source service account (name is <name_prefix>-src, description carries run-id)
gcloud iam service-accounts list \
  --filter="description~cloud-auth-harness" \
  --format='value(email,description)'
gcloud iam service-accounts delete EMAIL --quiet

# WIF pools
gcloud iam workload-identity-pools list --location=global \
  --filter="description~cloud-auth-harness AND state=ACTIVE" \
  --format='value(name,state)'

# Providers inside a pool
gcloud iam workload-identity-pools providers list \
  --location=global --workload-identity-pool=POOL_ID \
  --format='value(name,state)'

gcloud iam workload-identity-pools delete POOL_ID --location=global --quiet
```

To see soft-deleted pools still holding an id hostage, add
`--show-deleted`:

```sh
gcloud iam workload-identity-pools list --location=global --show-deleted \
  --format='value(name,state,expireTime)'
```

---

## Development

`tofu` is the supported tool. Both modules were checked with:

```sh
tofu -chdir=test/harness/tofu/gcp/stage1 init -backend=false
tofu -chdir=test/harness/tofu/gcp/stage1 validate
tofu -chdir=test/harness/tofu/gcp/stage2 init -backend=false
tofu -chdir=test/harness/tofu/gcp/stage2 validate
tofu fmt -recursive -check test/harness/tofu/gcp
```

`validate` needs no cloud credentials. `plan` does — it reads
`data.google_project`.
