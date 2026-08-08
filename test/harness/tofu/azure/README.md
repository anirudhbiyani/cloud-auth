# Azure harness modules (OpenTofu)

Real Azure infrastructure for the cloud-auth cross-cloud federation test
harness. Two applyable modules, per `test/harness/CONTRACT.md`:

| Module   | Role                | What it proves |
|----------|---------------------|----------------|
| `stage1` | Azure as a **source** | An AKS pod's projected service-account token is a usable identity proof at AWS and GCP. |
| `stage2` | Azure as a **target** | A GCP- or AWS-minted OIDC token can be exchanged at Entra ID for real Azure authority. |

Everything is driven with **OpenTofu** (`tofu`), never `terraform`. The HCL is
compatible with Terraform, but the harness scripts, docs and CI invoke `tofu`.
Local state only — there is no backend block, state lands in
`terraform.tfstate` inside each module directory, and `.gitignore` here keeps it
out of git.

```
tofu -chdir=test/harness/tofu/azure/stage1 init
tofu -chdir=test/harness/tofu/azure/stage1 apply -var="run_id=$RUN_ID"

tofu -chdir=test/harness/tofu/azure/stage2 init
tofu -chdir=test/harness/tofu/azure/stage2 apply -var-file=azure-stage2.auto.tfvars
```

---

## ⚠️ The case-sensitivity rule — read this first

**Entra ID matches a federated identity credential's `issuer`, `subject` and
`audience` against the presented token's `iss`, `sub` and `aud`
character-for-character and case-sensitively. It performs no normalization
whatsoever.**

- No case folding. `https://Accounts.Google.com` does not match
  `https://accounts.google.com`.
- No trailing-slash tolerance. An AKS issuer URL **ends with `/`**
  (`https://eastus.oic.prod-aks.azure.com/<tenant>/<uuid>/`); an EKS issuer URL
  **does not** (`https://oidc.eks.us-east-1.amazonaws.com/id/ABC123`). Adding or
  removing one breaks the match.
- No URL canonicalization, no percent-decoding, no whitespace trimming.
- The audience is literally `api://AzureADTokenExchange` — the capital A, D and
  T all matter.
- The GCP subject is the service account's **numeric unique id** (21 digits),
  *not* its email. Google puts the numeric id in `sub`.

This is the single most common cause of a silent failure in this integration,
because **nothing goes wrong at apply time**. `tofu apply` succeeds, the FIC is
created, and the mismatch only appears later at token-exchange time as:

```
AADSTS70021: No matching federated identity record found for presented assertion.
```

That error does not tell you *which* of the three fields was wrong.

Accordingly, `stage2/main.tf` passes every issuer/subject/audience straight
through from its input variable to the resource with **no `lower()`,
`trimsuffix()`, `trimspace()`, `replace()` or `format()` anywhere in the path**.
Please keep it that way. If a value looks wrong, fix it in the stage-1 module
that produced it, not on the way in here.

To debug a mismatch, decode the token the source actually minted and compare
byte-for-byte:

```sh
# claims only; never log or paste the signature
cut -d. -f2 <<<"$ASSERTION" | base64 -d 2>/dev/null | jq '{iss, sub, aud}'
az identity federated-credential list \
  --identity-name "$IDENTITY" --resource-group "$RG" \
  --query '[].{issuer:issuer, subject:subject, audiences:audiences}'
```

## ⚠️ The FIC limit

Entra ID allows a maximum of **20 federated identity credentials per
user-assigned managed identity** (the same cap applies to app registrations).
Creating the 21st fails.

This harness creates exactly **one FIC per identity** (two identities, two
FICs), so the cap is nowhere near. It matters if you extend the pair matrix:
add a **new managed identity** per source runtime rather than piling extra FICs
onto an existing one. Fanning out over `local.sources` in `stage2/main.tf`
already does this correctly.

Also note the FIC properties are largely immutable — changing `issuer` or
`subject` replaces the credential rather than updating it in place.

---

## stage1 — Azure as a SOURCE runtime

Creates:

| Resource | Name | Notes |
|---|---|---|
| `azurerm_resource_group.harness` | `<name_prefix>-<run_id>` | Holds everything. |
| `azurerm_kubernetes_cluster.source` | `<name_prefix>-<run_id>` | `sku_tier = "Free"`, `oidc_issuer_enabled = true`, `workload_identity_enabled = true`, system-assigned identity. |
| (implicit) node resource group | `<name_prefix>-<run_id>-nodes` | Created and owned by AKS: node VM, NIC, OS disk, NSG, route table, Standard Load Balancer + outbound public IP. **Azure does not propagate our tags into it** — sweep by name. |

Node pool is deliberately minimal: **1 × `Standard_B2s`** (2 vCPU / 4 GiB — the
AKS system-pool floor), 32 GiB managed OS disk, autoscaling off. If a region
refuses burstable SKUs for a system pool, set
`-var="node_vm_size=Standard_B2ms"` or `Standard_D2s_v5` (roughly 2× the hourly
node cost).

The Kubernetes namespace `cloud-auth-test` and service account `verifier` are
**not** created here — the verifier deployment creates them. This module only
exports the resulting subject string so the other clouds' stage-2 modules can
trust it.

### Outputs (`state/azure-stage1.json`)

| Key | Example |
|---|---|
| `tenant_id` | `aaaaaaaa-....` |
| `subscription_id` | `bbbbbbbb-....` |
| `location` | `eastus` |
| `resource_group` | `cloud-auth-test-20260705abc` |
| `aks_cluster_name` | `cloud-auth-test-20260705abc` |
| `aks_oidc_issuer_url` | `https://eastus.oic.prod-aks.azure.com/<tenant>/<uuid>/` |
| `namespace` | `cloud-auth-test` |
| `service_account` | `verifier` |
| `subject` | `system:serviceaccount:cloud-auth-test:verifier` |

The output set is exactly these nine keys, so the driver can do:

```sh
tofu -chdir=test/harness/tofu/azure/stage1 output -json \
  | jq 'map_values(.value)' > test/harness/state/azure-stage1.json
```

Consumers: `aws-stage2` builds an IAM OIDC provider from `aks_oidc_issuer_url`
and conditions its trust policy on `subject` (pair-matrix row 3);
`gcp-stage2` builds a workload identity pool OIDC provider from the same two
values (row 4).

## stage2 — Azure as a TARGET

Consumes the **other** clouds' stage-1 facts as plain input variables. It never
reads another cloud's tofu state — `test/harness/state/*-stage1.json` is the
only interface. See `stage2/terraform.tfvars.example` for the generated tfvars
shape.

Creates:

| Resource | Name | Notes |
|---|---|---|
| `azurerm_resource_group.trust` | `<name_prefix>-<run_id>-trust` | Own RG so stage2 destroys independently of stage1; also the (empty, harmless) scope of the Reader grants. |
| `azurerm_user_assigned_identity.source["gcp"]` | `<prefix>-<run>-from-gcp` | |
| `azurerm_user_assigned_identity.source["aws"]` | `<prefix>-<run>-from-aws` | |
| `azurerm_federated_identity_credential.source["gcp"]` | same | issuer `https://accounts.google.com`, subject = GCP SA numeric unique id, audience `api://AzureADTokenExchange`. |
| `azurerm_federated_identity_credential.source["aws"]` | same | issuer = EKS OIDC issuer URL, subject `system:serviceaccount:cloud-auth-test:verifier`, audience `api://AzureADTokenExchange`. |
| `azurerm_role_assignment.source_reader[*]` | — | `Reader` on the trust RG, `principal_type = "ServicePrincipal"`. |

`Reader` is what lets the verifier prove the exchanged token carries real
authority (it can list the resource group) without letting it change anything.
`principal_type = "ServicePrincipal"` skips azurerm's Entra existence pre-check,
which otherwise flakes with `PrincipalNotFound` on an identity created seconds
earlier.

### Required inputs

`gcp_source_sa_unique_id` and `aws_eks_oidc_issuer_url` have empty defaults with
validation blocks that reject empty — so a run that forgets to wire in another
cloud's stage-1 JSON **fails loudly at plan time** rather than quietly creating
a half-configured trust.

### Outputs (`state/azure-stage2.json`)

| Key | Example |
|---|---|
| `audience` | `api://AzureADTokenExchange` |
| `tenant_id` | `aaaaaaaa-....` |
| `client_id_for_gcp_source` | `cccccccc-....` |
| `client_id_for_aws_source` | `dddddddd-....` |

`client_id` is the managed identity's **client id** — the value the
client-assertion flow presents as `client_id` on the
`POST /{tenant}/oauth2/v2.0/token` request. It is **not** the principal id /
object id and **not** the ARM resource id. Sending the principal id instead
fails with `AADSTS700016` (application not found in the directory), which is a
confusingly different error from the FIC-mismatch one.

Consumers: the verifier, for pair-matrix rows 2 (GCP GCE → Azure) and 6 (AWS
EKS-IRSA → Azure), plus the negative row (AWS EC2 → Azure, which must fail with
`ErrNoFirstClassPath` — there is no SigV4 path into Entra ID).

---

## Cost estimate

Pay-as-you-go list prices, East US, USD, no reservations or credits. Round
numbers — treat as a planning estimate, not a quote.

| Item | Where | $/hour | $/day |
|---|---|---|---|
| AKS control plane (**Free** tier — no uptime SLA) | stage1 | **0.000** | **0.00** |
| 1 × `Standard_B2s` Linux node (2 vCPU / 4 GiB) | stage1 node RG | 0.0416 | 1.00 |
| 32 GiB managed OS disk (P4 premium SSD) | stage1 node RG | 0.0073 | 0.18 |
| Standard Load Balancer (AKS outbound, first 5 rules) | stage1 node RG | 0.025 | 0.60 |
| Standard static public IPv4 (LB outbound) | stage1 node RG | 0.005 | 0.12 |
| Egress bandwidth (a few MB of token/JWKS traffic) | — | ~0 | ~0 |
| Resource groups | both | 0.000 | 0.00 |
| 2 × user-assigned managed identity | stage2 | **0.000** | **0.00** |
| 2 × federated identity credential | stage2 | **0.000** | **0.00** |
| 2 × role assignment | stage2 | **0.000** | **0.00** |
| **Total** | | **≈ $0.079** | **≈ $1.90** |

Roughly **$0.08/hour, $1.90/day, ~$57/month if left running**.

Notes:

- **stage2 is free.** Managed identities, federated identity credentials and
  role assignments carry no charge. Every dollar here is the stage-1 node pool
  and its supporting network plumbing.
- The AKS **control plane is free on the Free tier**; switching `sku_tier` to
  `Standard` adds ~$0.10/hour for a financially-backed uptime SLA the harness
  does not need. Do not switch it.
- Most of the non-VM cost is the Standard Load Balancer + public IP that AKS
  provisions for outbound connectivity. It is not avoidable without a
  significantly more complex (outbound-type `userDefinedRouting`) setup.
- Typical harness run (apply → verify → destroy) is well under an hour, so
  expect **cents**, not dollars. The risk is a failed `down` — see sweeping,
  below.

## Required Azure permissions

Authenticate however azurerm normally does (`az login`, `ARM_*` env vars,
workload identity in CI). The subscription must be set via
`-var="subscription_id=..."`, `ARM_SUBSCRIPTION_ID`, or `az account set` —
azurerm 4.x requires it explicitly.

**stage1**

- **Contributor** on the subscription (or on a pre-existing parent scope that
  permits creating resource groups). Creating an AKS cluster also creates the
  `MC_*`-style node resource group; Azure handles granting the cluster's
  system-assigned identity rights there for you.
- No Entra ID directory permissions.

**stage2**

- **Contributor** on the subscription (create RG, managed identities, FICs).
- **User Access Administrator** *or* **Role Based Access Control
  Administrator** at the subscription (or at least at the trust RG's parent
  scope) — creating the `Reader` role assignments requires
  `Microsoft.Authorization/roleAssignments/write`, which plain Contributor does
  **not** grant. This is the permission people most often lack.
- **No Entra ID directory permissions** (see below).

**Resource provider registration.** By default azurerm's
`resource_provider_registrations = "legacy"` registers a batch of RPs on the
subscription, which needs subscription-level write. If you run as a narrowly
scoped principal on a subscription where `Microsoft.ContainerService`,
`Microsoft.ManagedIdentity`, `Microsoft.Authorization`, `Microsoft.Network` and
`Microsoft.Compute` are already registered, pass
`-var="resource_provider_registrations=none"`.

### Why managed identities and not app registrations

Entra workload identity federation works with either a **user-assigned managed
identity** or an **app registration**. This harness uses managed identities:

- **Managed identity** — an ARM resource. Creating it and its FICs needs only
  Azure RBAC (Contributor) on a subscription. No `azuread` provider, no Entra
  directory writes. This module therefore declares **only the `azurerm`
  provider**.
- **App registration** — an Entra *directory* object. Creating one needs
  `Application.ReadWrite.OwnedBy` (or an admin role) in the tenant, which most
  organizations restrict, and pulls in the `azuread` provider.

The client-assertion exchange is identical from the workload's point of view
either way. The tradeoff: managed identities are regional ARM resources tied to
a subscription and cannot be multi-tenant, and they cannot hold client secrets
or certificates. None of that matters for a federation test, and avoiding the
directory-write requirement means the harness runs on a subscription handed out
by an org that will not grant Entra app-creation rights.

## Destroying

Stage 2 first, then stage 1. Destroy must always work — never gate it on
`verify` having passed.

```sh
tofu -chdir=test/harness/tofu/azure/stage2 destroy -auto-approve \
  -var-file=azure-stage2.auto.tfvars
tofu -chdir=test/harness/tofu/azure/stage1 destroy -auto-approve \
  -var="run_id=$RUN_ID"
```

If a `destroy` half-fails or state is lost, everything is tagged
`managed-by=cloud-auth-harness` and `run-id=<run_id>` so orphans are findable.

**Sweep by tag:**

```sh
# What is still out there, all runs
az resource list --tag managed-by=cloud-auth-harness -o table
az group list --query "[?tags.\"managed-by\"=='cloud-auth-harness'].{name:name,run:tags.\"run-id\",location:location}" -o table

# Everything from one run
RUN_ID=20260705abc
az group list \
  --query "[?tags.\"run-id\"=='$RUN_ID'].name" -o tsv \
  | xargs -r -n1 -I{} az group delete --name {} --yes --no-wait
```

**Do not forget the node resource group.** AKS creates
`<name_prefix>-<run_id>-nodes` itself and **Azure does not copy our tags into
it**, so a tag-only sweep misses it. It is normally deleted along with the
cluster; if the cluster deletion failed, delete it by name:

```sh
az group delete --name "cloud-auth-test-$RUN_ID-nodes" --yes --no-wait
```

**Federated identity credentials and role assignments** go away with their
parent identity / resource group. To check for strays:

```sh
az role assignment list --all \
  --query "[?contains(description || '', 'cloud-auth harness')].{id:id,scope:scope}" -o table
```

Deleting the RGs is sufficient for a full teardown — nothing this module creates
lives outside them, and no Entra directory objects are created at all.

## Provider pinning and validation

- `required_version = ">= 1.6.0, < 2.0.0"`, provider `hashicorp/azurerm ~> 4.40`.
- Pinned to the 4.x line on purpose. azurerm **5.x** makes
  `node_provisioning_profile` mandatory on `azurerm_kubernetes_cluster`, flips
  `oidc_issuer_enabled` to default `true`, and removes the deprecated
  `parent_id` from `azurerm_federated_identity_credential`. This module already
  uses the non-deprecated `user_assigned_identity_id`, but the pin keeps the
  whole harness on a schema it was validated against. Bumping to 5.x is a
  deliberate, separate change.
- `.terraform.lock.hcl` is gitignored: the harness always runs `tofu init`
  fresh, and a single-platform lock file would just break other runners.

Both modules were checked with `tofu init -backend=false`, `tofu validate` and
`tofu fmt -recursive` against azurerm **4.81.0** — all clean. Every resource
type and attribute used here was additionally confirmed against
`tofu providers schema -json` rather than from memory. Nothing was `apply`ed;
that costs money and needs live credentials.
