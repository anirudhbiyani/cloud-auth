<p align="center">
  <h1 align="center">☁️ cloud-auth</h1>
  <p align="center">
    <strong>Unified Cross-Cloud Authentication Lifecycle Management</strong>
  </p>
</p>

<p align="center">
  <a href="https://pkg.go.dev/github.com/anirudhbiyani/cloud-auth"><img src="https://pkg.go.dev/badge/github.com/anirudhbiyani/cloud-auth.svg" alt="Go Reference"></a>
  <a href="https://goreportcard.com/report/github.com/anirudhbiyani/cloud-auth"><img src="https://goreportcard.com/badge/github.com/anirudhbiyani/cloud-auth" alt="Go Report Card"></a>
  <a href="https://www.gnu.org/licenses/agpl-3.0"><img src="https://img.shields.io/badge/License-AGPL_v3-blue.svg" alt="License: AGPL-3.0"></a>
  <img src="https://img.shields.io/badge/Go-1.27.0+-00ADD8?logo=go&logoColor=white" alt="Go Version">
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-why-cloud-auth">Why cloud-auth?</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-documentation">Documentation</a> •
  <a href="#-contributing">Contributing</a>
</p>

---

**cloud-auth** is a Go library and CLI tool that simplifies the setup, validation, and lifecycle management of cross-cloud authentication mechanisms. It enables workloads running in one cloud provider (or CI/CD platform) to securely access resources in another cloud without managing long-lived credentials.

```bash
# Setup GitHub Actions → AWS authentication in one command
cloud-auth setup --type aws-oidc \
  --role-name github-deploy-role \
  --account-id 123456789012 \
  --oidc-url https://token.actions.githubusercontent.com \
  --subject "repo:myorg/myrepo:ref:refs/heads/main" \
  --source github
```

## 🎯 Why cloud-auth?

Setting up cross-cloud authentication typically requires:
- Deep knowledge of each cloud's IAM/identity systems
- Manual configuration of OIDC providers, trust policies, and role bindings
- No easy way to validate configurations before they fail in production
- Difficulty tracking and cleaning up resources

**cloud-auth solves these problems by providing:**

| Problem | Solution |
|---------|----------|
| Complex multi-step setup | Single command/API call with sensible defaults |
| Configuration drift | Validation framework with remediation hints |
| Orphaned resources | State tracking for safe cleanup |
| Vendor lock-in | Unified interface across AWS, GCP, Azure |
| Security blind spots | Built-in security checks and best practices |

## ✨ Features

### 🔄 Complete Lifecycle Management
- **Setup** - Create cross-cloud authentication mechanisms with a single command
- **Validate** - Verify configurations are correct and functional
- **Delete** - Safely remove mechanisms and associated resources
- **Dry-Run** - Preview changes before applying them

### 📍 Current status

**All four providers are wired.** AWS, GCP, Azure and HashiCorp Vault each reach
their service on a real run. The runtime data plane
(`doctor`, `exchange`, `exec`) is the more mature half of this project and works
across all three clouds.

`--dry-run` needs no cloud credentials on any provider. That is deliberate:
planning is what you do *before* you have them.

### 🌐 Multi-Cloud Support

Control-plane lifecycle — establishing the trust relationship.

**Legend:** ✅ implemented and reaches the cloud · 🅿️ plan/validation only, no
client (`--dry-run` works, a real run does not) · — not applicable.

| Provider | Setup | Validate | Delete | Dry-run | Federation Types |
|----------|:-----:|:--------:|:------:|:-------:|------------------|
| **AWS** | ✅ | ✅ | ✅ | ✅ | OIDC Trust |
| **GCP** | ✅ | ✅ | ✅ | ✅ | Workload Identity |
| **Azure** | ✅ | ✅ | ✅ | ✅ | Federated Credentials |
| **Vault** | ✅ | ✅ | ✅ | ✅ | JWT Auth |
| **GitHub OIDC** | — | — | — | — | Token source only |
| **Kubernetes** | — | — | — | — | Token source only (`--type k8s-federation`, AWS target) |

> **How far each ✅ has been verified.** AWS is exercised against live AWS in the
> integration harness. The GCP and Azure clients are covered by unit tests that
> speak the documented wire protocols against a fake server — GCP's
> long-running-operation envelope, error envelope and IAM policy etag; Azure's
> Graph and ARM envelopes, `@odata.nextLink` paging and the Entra `AADSTS` codes
> — and have not yet been run against their live clouds.
>
> Credentials: GCP uses Application Default Credentials
> (`GOOGLE_APPLICATION_CREDENTIALS`, `gcloud auth application-default login`, or
> the metadata server). Azure uses `DefaultAzureCredential` (`az login`, managed
> identity, workload identity, or the `AZURE_*` environment variables). Vault
> uses `VAULT_ADDR` and `VAULT_TOKEN`, plus `VAULT_NAMESPACE` on Enterprise —
> there is deliberately no discovery chain, because guessing an address would
> mean sending a token somewhere you did not name.

> **Cloudflare was removed.** Cloudflare Access has no workload identity
> federation — only service tokens and mTLS, which are shared secrets. Shipping
> that under this project's banner would have been the opposite of the point.

#### Azure constraints cloud-auth enforces for you

These are Azure's, not cloud-auth's, and each one is checked *before* the API
call rather than discovered from a refusal that names a limit without naming
what is using it:

| Constraint | What cloud-auth does |
|---|---|
| **20 federated identity credentials** per application or user-assigned managed identity | Refuses the 21st, naming the current count. The flexible-FIC preview raises this, but is readable only through Graph or the portal — Azure CLI, PowerShell and Terraform error on both read *and* write — so adopting it makes existing IaC state unreadable. cloud-auth does not use it, and says so in the error. |
| **No wildcards in any FIC property** | Rejected up front. Azure matches issuer, subject, audience and name literally, so a wildcard produces a credential that is created successfully and then never matches a token. |
| **Creation throttled to ~0.25 req/sec per resource; HTTP 409 on concurrent creation** | Credential creation is serialized and paced. Fanning out yields conflicts, not speed — and a conflict is indistinguishable from "already exists", so the two get conflated and a setup reports success having created nothing. |
| **Propagation delay after creation** | `AADSTS70021` is retried with bounded backoff, in both the control plane and the runtime exchanger. Nothing else is: `AADSTS700213`, a genuinely wrong subject, fails on the first attempt. |

> Azure matches issuer, subject and audience **case-sensitively**, and a wrong
> subject produces a credential that Microsoft's own documentation describes as
> failing without error. `cloud-auth doctor` reports a case-only audience
> mismatch explicitly for that reason.

### 🔀 Runtime Federation Matrix

Which source runtimes can obtain credentials at which targets, and the proof
each one presents. This is the `exchange`/`exec` path, not the control plane:

**Legend:** ✅ works · ❌ the target STS will not accept this proof · 🚫 **refused
by design** — cloud-auth returns `ErrNonFederatableSource` rather than attempt it.

| Source runtime | Proof it mints | → AWS | → GCP | → Azure |
|---|---|:---:|:---:|:---:|
| **AWS** — `eks-irsa` | OIDC (projected SA token) | ✅ | ✅ | ✅ |
| **AWS** — `ec2`, `ecs`, `lambda` | OIDC via `sts:GetWebIdentityToken` | ✅ | ✅ | ✅ |
| **AWS** — `ec2`, `ecs`, `lambda` | SigV4 `GetCallerIdentity` | ✅ | ✅ | ❌ |
| **AWS** — `eks-pod-identity` | *none* | 🚫 | 🚫 | 🚫 |
| **GCP** — `gce`, `gke`, `cloud-run`, `cloud-functions` | OIDC (metadata identity token) | ✅ | ✅ | ✅ |
| **Azure** — `aks-workload-identity` | OIDC (projected SA token) | ✅ | ✅ | ✅ |
| **Azure** — `vm`, `app-service`, `container-apps` | *none* | 🚫 | 🚫 | 🚫 |

**Why two runtimes are refused rather than attempted.**

*EKS Pod Identity* vends AWS-internal credentials. There is no
externally-verifiable token to present, so no other cloud's STS can check
anything. Use EKS IRSA, which projects a real OIDC token.

*Azure managed identity* — a bare VM, App Service, Container Apps — vends Entra
**access tokens**. An access token is a live bearer credential for whatever
Azure resource was named in the request, not an audience-pinned assertion about
the workload. Forwarding one to a third-party STS discloses a working Azure
credential **and still fails**, because its `aud` is an Azure resource rather
than the target's audience. Use AKS Workload Identity
(`AZURE_FEDERATED_TOKEN_FILE`), or bridge the identity through an OIDC issuer.

Azure Entra accepts **only** RS256 OIDC JWTs. Until AWS shipped outbound
identity federation, an EC2/ECS/Lambda workload had no OIDC token of its own and
that cell was a documented gap (`ErrNoFirstClassPath`); the `sts:GetWebIdentityToken`
path closes it. See [AWS proof selection](#aws-proof-selection).

### 🔐 Security-First Design
- **No secrets in output** - Secrets are routed to secure storage, never returned directly
- **Ownership tracking** - Only delete resources cloud-auth created
- **Least privilege** - Minimal permissions with policy attachment support
- **Audit trail** - State file tracks all managed resources

### 🛠️ Flexible Usage
- **CLI** - Perfect for scripts, CI/CD pipelines, and manual operations
- **Go Library** - Embed in your applications and infrastructure tools
- **Spec Files** - Declarative JSON/YAML configuration

## 📦 Installation

### CLI

**Using Go:**
```bash
go install github.com/anirudhbiyani/cloud-auth@latest
```

**Pre-built binaries** for linux, darwin and windows on amd64 and arm64, with
checksums, are attached to each [release](https://github.com/anirudhbiyani/cloud-auth/releases).

**From Source:**
```bash
git clone https://github.com/anirudhbiyani/cloud-auth.git
cd cloud-auth
go build -o cloud-auth .
```

### Library

```bash
go get github.com/anirudhbiyani/cloud-auth
```

## 🚀 Quick Start

### Example 1: GitHub Actions → AWS

Enable GitHub Actions workflows to deploy to AWS without static credentials:

```bash
cloud-auth setup --type aws-oidc \
  --role-name github-deploy-role \
  --account-id 123456789012 \
  --oidc-url https://token.actions.githubusercontent.com \
  --subject "repo:myorg/myrepo:ref:refs/heads/main" \
  --source github \
  --policy-arns arn:aws:iam::aws:policy/AmazonS3FullAccess
```

Then in your GitHub Actions workflow:
```yaml
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::123456789012:role/github-deploy-role
    aws-region: us-east-1
```

### Example 2: AWS → GCP Cross-Cloud Access

Allow an AWS workload to access GCP resources:

```bash
cloud-auth setup --type gcp-wif \
  --project-id my-gcp-project \
  --project-number 123456789012 \
  --pool-id aws-federation-pool \
  --provider-id aws-provider \
  --provider-type aws \
  --aws-account-id 987654321098 \
  --service-account my-sa@my-gcp-project.iam.gserviceaccount.com \
  --source aws
```

### Example 3: Kubernetes → AWS (IRSA)

Enable Kubernetes pods to access AWS services:

```bash
cloud-auth setup --type k8s-federation \
  --cluster-name my-eks-cluster \
  --k8s-namespace default \
  --k8s-sa-name my-app-sa \
  --oidc-url https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E \
  --target-cloud aws \
  --role-name k8s-workload-role \
  --account-id 123456789012 \
  --policy-arns arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
```

## 📖 Documentation

### CLI Commands

**Control-plane** — establish and manage the trust relationship:

| Command | Description |
|---------|-------------|
| `setup` | Create or update a cross-cloud authentication mechanism |
| `validate` | Validate an existing mechanism configuration |
| `delete` | Delete a mechanism and its resources |
| `list` | List all managed mechanisms |
| `describe` | Show details of a specific mechanism |
| `providers` | List available providers and their capabilities |
| `version` | Show version information |

**Runtime** — obtain short-lived credentials at workload run time, with zero
static secrets. The workload detects its own identity, mints a native proof, and
exchanges it at the target cloud's STS:

| Command | Description |
|---------|-------------|
| `doctor` | Detect the runtime and preflight a target; explains exactly why an exchange would be refused |
| `exchange` | Obtain short-lived target credentials (`--format env\|json\|credential-process`) |
| `exec` | Mint + exchange, then run a command with the credentials injected (`... -- <cmd>`) |
| `init` | Print the target-side trust scaffold (Terraform/OpenTofu + CLI). Print-only; never applies changes |
| `credential-process` | Emit the AWS `credential_process` JSON contract for zero-code SDK integration |
| `config-validate` | Lint a declarative federation config file |

### AWS proof selection

On EC2, ECS and Lambda the AWS source can prove its identity two ways. Both
assert the *same* IAM principal — they differ in format, and therefore in which
target-side trust configuration applies:

| Proof | Minted by | Accepted by |
|---|---|---|
| **OIDC** | `sts:GetWebIdentityToken` (AWS IAM outbound identity federation) | AWS, GCP, Azure |
| **SigV4** | Signed `GetCallerIdentity` request | AWS, GCP |

Outbound identity federation is **opt-in per AWS account**
(`iam:EnableOutboundWebIdentityFederation`), and the calling principal needs
`sts:GetWebIdentityToken`. The minted JWT is RS256, bound to exactly one
audience, valid 15 minutes, and verifiable against the account's OIDC discovery
document.

Select the proof with `CLOUD_AUTH_AWS_PROOF`, or `source.WithAWSProof(...)` in
the library:

| Value | Behaviour |
|---|---|
| `auto` *(default)* | Prefer OIDC; fall back to SigV4 only when the account has **not** enabled outbound federation. An `AccessDenied` does **not** fall back — the feature is on and this principal is not permitted, which is a policy you need to see. |
| `oidc` | Require the STS-vended JWT; fail if the account has not enabled it. |
| `sigv4` | Require the SigV4 proof. GCP-only. |

> **Pin `sigv4` if your GCP workload identity pool has only an `aws` provider.**
> Under `auto`, the day someone enables outbound federation on the account the
> source starts presenting an OIDC JWT, and a pool with no `oidc` provider will
> begin refusing the exchange.

EKS IRSA and Pod Identity are unaffected — they already carry a projected OIDC
token and never ask STS to vend one.

### Mechanism Types

#### AWS Role Trust OIDC (`aws-oidc`)

Creates an AWS IAM role that trusts an external OIDC identity provider.

```bash
cloud-auth setup --type aws-oidc \
  --role-name <name>           # IAM role name to create
  --account-id <id>            # AWS account ID (12 digits)
  --oidc-url <url>             # OIDC provider URL
  --audience <aud>             # Expected audience (default: sts.amazonaws.com)
  --subject <sub>              # Subject claim pattern
  --source <provider>          # Source: github, gcp, azure, k8s, okta
  --policy-arns <arns>         # Comma-separated policy ARNs
```

Or using a spec file:
```json
{
  "type": "aws_role_trust_oidc",
  "role_name": "github-actions-deploy",
  "account_id": "123456789012",
  "oidc_provider_url": "https://token.actions.githubusercontent.com",
  "audience": "sts.amazonaws.com",
  "subject": "repo:myorg/myrepo:ref:refs/heads/main",
  "subject_condition": "StringEquals",
  "source": "github_oidc",
  "policy_arns": [
    "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
  ]
}
```

#### GCP Workload Identity Pool (`gcp-wif`)

Creates a GCP Workload Identity Pool with a provider for external identities.

```bash
cloud-auth setup --type gcp-wif \
  --project-id <id>            # GCP project ID
  --project-number <num>       # GCP project number
  --pool-id <id>               # Workload Identity Pool ID
  --provider-id <id>           # Provider ID within the pool
  --provider-type <type>       # Provider type: aws, oidc
  --aws-account-id <id>        # AWS account ID (for aws type)
  --oidc-url <url>             # OIDC issuer URL (for oidc type)
  --service-account <sa>       # GCP service account email
  --source <provider>          # Source identity provider
```

#### Azure Federated Credential (`azure-federated`)

Creates an Azure federated identity credential for passwordless authentication.

```bash
cloud-auth setup --type azure-federated \
  --tenant-id <id>             # Azure AD tenant ID
  --identity-type <type>       # app or managed-identity
  --app-name <name>            # Application name (for app type)
  --identity-name <name>       # Managed identity name (for managed-identity)
  --resource-group <rg>        # Resource group (for managed-identity)
  --subscription-id <id>       # Subscription ID
  --credential-name <name>     # Federated credential name
  --issuer <url>               # OIDC issuer URL
  --subject <sub>              # Subject claim
  --source <provider>          # Source identity provider
```

#### Kubernetes Service Account Federation (`k8s-federation`)

Sets up federation between Kubernetes ServiceAccounts and cloud identities.

```bash
cloud-auth setup --type k8s-federation \
  --cluster-name <name>        # Kubernetes cluster name
  --k8s-namespace <ns>         # Kubernetes namespace
  --k8s-sa-name <name>         # ServiceAccount name
  --oidc-url <url>             # Cluster OIDC issuer URL
  --target-cloud <cloud>       # Target: aws, gcp, or azure
  # Plus target-cloud specific options
```

### Validation

Validate a mechanism to ensure it's correctly configured:

```bash
# Basic validation
cloud-auth validate --ref aws_role_trust_oidc-aws-abc123

# Include token acquisition test
cloud-auth validate --ref aws_role_trust_oidc-aws-abc123 --include-token-test

# With custom timeout
cloud-auth validate --ref aws_role_trust_oidc-aws-abc123 --timeout 60s
```

Validation checks, and their **current** implementation status:

| Check | Status |
|---|---|
| Resource existence | ✅ implemented |
| OIDC provider configuration | ✅ implemented — fetches the issuer's `.well-known/openid-configuration` |
| Token acquisition | ✅ implemented (opt-in via `--include-token-test`) |
| Clock skew | ✅ implemented — requires a remote time source; reports **skipped** without one |
| Trust policy configuration | ✅ implemented for **AWS, GCP and Azure** — reads the live trust object and checks the issuer, audience and subject still match what was configured, and flags a *totally* unscoped trust outright |
| Permission policies | ✅ implemented for **AWS, GCP and Azure** — confirms the expected policies/roles are still attached |

> **What "unscoped" means per cloud.** The trust check fails outright when a
> trust admits any identity from its issuer: an AWS `sub: "*"` condition, a GCP
> workload identity pool provider with **no attribute condition**, or an Azure
> federated credential with an empty subject. Each is a confused-deputy hole,
> and each would otherwise "match" whatever you compared it to.

> **"Unscoped" is a narrow test, not a breadth score.** It answers *does this
> pin nothing at all*. A subject that pins some characters is not flagged, so
> `repo:myorg/*` (every repo in the org, including ones created tomorrow) and
> `repo:myorg/myrepo:*` (every branch, tag, and `pull_request` from a fork) both
> pass it today. Grading subject breadth is tracked separately; until it lands,
> pin the subject yourself — the examples in this README do.

> **Trust-policy and permission checks compare against the intent recorded at
> setup.** Mechanisms created before cloud-auth persisted that intent have
> nothing to compare against, so those checks report *skipped* rather than
> failing — re-run `setup` to record it.

> **Read the result carefully.** `Valid: true` means *nothing failed*, not
> *everything was checked*. Checks that cannot run are reported as **skipped**
> and never silently pass, and `validate` prints a prominent `⚠ INCOMPLETE`
> banner listing what went unverified. In the library, pair `report.IsValid()`
> with `report.IsComplete()` — and use `report.SkippedChecks()` to see the gaps.
> Every skipped check carries `Remediation` text telling you what to confirm by
> hand.

### Runtime Configuration File

`exchange`, `exec` and `doctor` accept a declarative config via `--config`;
`config-validate` lints it. Precedence is **code > env > file**, and validation
fails closed — an invalid or ambiguous config is a hard error, never a degraded
fallback.

```yaml
version: 1
source:
  # "auto" (default), a cloud ("aws"), or cloud and sub-runtime ("aws-ec2").
  # A mismatch is a hard error: a host can satisfy more than one probe, so
  # pinning lets an operator refuse any identity but the expected one.
  detect: aws-ec2
refresh:
  buffer: 5m
targets:
  - name: prod-gcp
    cloud: gcp
    audience: //iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/aws-pool/providers/aws-provider
    workload_identity_pool: projects/123/locations/global/workloadIdentityPools/aws-pool
    impersonate_service_account: deployer@my-project.iam.gserviceaccount.com
  - name: prod-azure
    cloud: azure
    tenant: 00000000-0000-0000-0000-000000000000
    client_id: 11111111-1111-1111-1111-111111111111
    scope: https://management.azure.com/.default
  - name: prod-aws
    cloud: aws
    role: arn:aws:iam::123456789012:role/deploy
    session_name: cloud-auth
```

A JSON Schema for editor completion and CI linting lives at
[`config/cloud-auth.schema.json`](config/cloud-auth.schema.json).

### State Management

cloud-auth tracks created resources in a local state file (`~/.cloud-auth/state.json`):

```bash
# List all managed mechanisms
cloud-auth list

# Show details of a specific mechanism
cloud-auth describe aws_role_trust_oidc-aws-abc123

# Use a custom state file
cloud-auth list --state /path/to/state.json
```

### Library Usage

Use cloud-auth as a Go library for programmatic access:

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/anirudhbiyani/cloud-auth/core"
    _ "github.com/anirudhbiyani/cloud-auth/provider/aws"
    _ "github.com/anirudhbiyani/cloud-auth/provider/gcp"
)

func main() {
    ctx := context.Background()

    // Define the mechanism specification
    spec := &core.AWSRoleTrustOIDCSpec{
        RoleName:         "github-actions-role",
        AccountID:        "123456789012",
        OIDCProviderURL:  "https://token.actions.githubusercontent.com",
        Audience:         "sts.amazonaws.com",
        Subject:          "repo:myorg/myrepo:ref:refs/heads/main",
        SubjectCondition: "StringEquals",
        Source:           core.GitHubOIDC,
        PolicyARNs: []string{
            "arn:aws:iam::aws:policy/ReadOnlyAccess",
        },
    }

    // Create a state store
    stateStore, err := core.NewFileStateStore("")
    if err != nil {
        log.Fatal(err)
    }

    // Create a manager
    manager := core.NewManager(
        core.WithStateStore(stateStore),
    )

    // Setup the mechanism
    outputs, err := manager.Setup(ctx, spec, core.SetupOptions{})
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Created mechanism: %s\n", outputs.Ref.ID)
    fmt.Printf("Role ARN: %s\n", outputs.Values["role_arn"])

    // Validate the mechanism
    report, err := manager.Validate(ctx, outputs.Ref, core.ValidateOptions{})
    if err != nil {
        log.Fatal(err)
    }

    if !report.IsValid() {
        for _, check := range report.FailedChecks() {
            fmt.Printf("Failed: %s - %s\n", check.Name, check.Remediation)
        }
    }
}
```

## ⚙️ Configuration

### Environment Variables

Configure cloud provider credentials using standard environment variables:

#### AWS
```bash
AWS_ACCESS_KEY_ID          # Static access key
AWS_SECRET_ACCESS_KEY      # Static secret key
AWS_SESSION_TOKEN          # Session token (optional)
AWS_REGION                 # Default region
AWS_PROFILE                # Named profile
```

#### GCP
```bash
GOOGLE_APPLICATION_CREDENTIALS  # Path to service account JSON
GOOGLE_CLOUD_PROJECT            # Default project ID
```

#### Azure
```bash
AZURE_CLIENT_ID            # Application client ID
AZURE_TENANT_ID            # Azure AD tenant ID
AZURE_CLIENT_SECRET        # Client secret
AZURE_SUBSCRIPTION_ID      # Subscription ID
```

#### Vault
```bash
VAULT_ADDR                 # Vault server address
VAULT_TOKEN                # Vault token
```

#### cloud-auth runtime

These override the config file (env > file):

```bash
CLOUD_AUTH_AWS_PROOF       # auto | oidc | sigv4 (see AWS proof selection)
CLOUD_AUTH_SOURCE_DETECT   # auto, a cloud, or a cloud and sub-runtime
CLOUD_AUTH_REFRESH_BUFFER  # credential refresh lead time, e.g. 5m
```

`source.detect` accepts `auto`, one of `aws` / `gcp` / `azure`, or a cloud plus
a known sub-runtime:

| Cloud | Sub-runtimes |
|---|---|
| `aws` | `ec2`, `ecs`, `lambda`, `eks-irsa`, `eks-pod-identity` |
| `gcp` | `gce`, `gke`, `cloud-run`, `cloud-functions` |
| `azure` | `vm`, `aks-workload-identity`, `app-service`, `container-apps` |

An unrecognised value is rejected rather than silently defaulted — including a
malformed `aws-`, which is an error and not a synonym for `aws`.

### Common Options

| Option | Description |
|--------|-------------|
| `--dry-run` | Preview changes without applying them |
| `--force` | Overwrite existing resources |
| `--state <path>` | Custom state file path |
| `-v, --verbose` | Diagnostic output on **stderr** |

## 📝 Output and audit

**stdout carries results; stderr carries everything else.** A result is the thing
you asked for — a validation report, a credential document, a table of
mechanisms — and something downstream may be parsing it. Diagnostics, warnings,
the delete confirmation prompt and audit records all go to stderr, so
`cloud-auth list --output json | jq .` and `cloud-auth exchange --format json`
stay clean whatever else the run has to say.

`--verbose` raises the diagnostic level; without it a normal run is quiet unless
something is worth saying.

### Audit records

Every operation that **issues a credential** or **changes a trust relationship**
emits exactly one JSON record to stderr, whether it succeeds or fails:

| Operation | Emitted by |
|---|---|
| `exchange` | `cloud-auth exchange` |
| `credential-process` | `cloud-auth credential-process` |
| `exec` | `cloud-auth exec` — written *before* the child runs, since the child may run for hours and replaces this process's exit path |
| `setup` | `cloud-auth setup`, including `--dry-run`, which still reads live state |
| `delete` | `cloud-auth delete` |

```console
$ cloud-auth setup --type aws-oidc ... --dry-run 2> audit.jsonl
$ jq -c '{operation, outcome, mechanism_type, latency_ms}' audit.jsonl
{"operation":"setup","outcome":"success","mechanism_type":"aws_role_trust_oidc","latency_ms":4011}
```

Records carry the source identity, target, role, STS request id, mechanism and
latency — whichever apply to that operation. **Exactly one record per operation,
including on the failure paths**, which are the ones worth reviewing. The `error`
field is redacted before it is written: upstream token endpoints echo request
material into their error descriptions, and the audit log is the one file built
for long-term retention.

Reads — `validate`, `list`, `describe`, `doctor` — do not emit records.

## 🏗️ Architecture

```
cloud-auth/
├── main.go                    # The cloud-auth command lives at the module root,
├── controlplane.go            #   so `go install github.com/anirudhbiyani/cloud-auth@latest`
├── runtime.go                 #   installs a binary named cloud-auth.
├── diagnose.go                #   main.go: entry point and exit codes
├── scaffold.go                #   controlplane.go: setup/validate/delete/list + argv dispatch
├── exec.go                    #   runtime.go: doctor/exchange/exec/config-validate
├── format.go                  #   diagnose.go: doctor's preflight logic (pure, no I/O)
│                              #   scaffold.go, exec.go, format.go: init, exec, output shapes
├── audit.go                   #   audit.go: one record per credential-issuing
├── logging.go                 #     or trust-changing operation
│                              #   logging.go: diagnostics to stderr
├── core/                      # Core domain package (one shared vocabulary)
│   ├── federation.go          # Runtime types (Cloud, Target, SourceToken, Credentials)
│   ├── federation_interfaces.go # SourceProvider, Exchanger, Runtime, sentinel errors
│   ├── interfaces.go          # Provider and Manager interfaces (control-plane)
│   ├── types.go               # Control-plane types (MechanismRef, Outputs, etc.)
│   ├── specs.go               # Mechanism specifications
│   ├── manager.go             # Default manager implementation
│   ├── registry.go            # Provider registry
│   ├── state.go               # State store implementations
│   ├── validation.go          # Validation framework
│   └── errors.go              # Structured errors
├── provider/                  # Control-plane provider implementations
│   ├── aws/                   # AWS IAM, STS, OIDC
│   ├── gcp/                   # GCP Workload Identity
│   ├── azure/                 # Azure AD Federated Credentials
│   └── vault/                 # HashiCorp Vault
├── source/                    # Runtime: source-identity detection + minting
│   └── aws_outbound.go        #   sts:GetWebIdentityToken OIDC proof (AWS → Azure)
├── target/                    # Runtime: target STS exchangers
├── adapters/                  # Runtime: SDK-native credential adapters
├── broker/                    # Runtime: detect→mint→exchange orchestrator
├── config/                    # Runtime: declarative federation config + JSON Schema
├── internal/                  # imds, jwt, k8stoken, cache, audit
├── test/                      # Cloud integration harness (OpenTofu) + build-tagged tests
├── docs/                      # BASELINE.md; internal/ holds planning history
└── examples/                  # Example spec files
```

### Core Concepts

| Concept | Description |
|---------|-------------|
| **Provider** | A cloud service or identity provider (AWS, GCP, GitHub) |
| **Mechanism** | A configured cross-cloud authentication relationship |
| **Spec** | Declarative configuration for a mechanism |
| **Ref** | Stable reference to a created mechanism instance |
| **StateStore** | Tracks created resources for lifecycle management |

### Extensibility

Add new providers by implementing the `Provider` interface:

```go
// TokenProvider for token acquisition
type TokenProvider interface {
    Provider
    Token(ctx context.Context, req TokenRequest) (*TokenResponse, error)
}

// LifecycleProvider for full lifecycle management
type LifecycleProvider interface {
    Provider
    Setup(ctx context.Context, spec MechanismSpec, opts SetupOptions) (*Outputs, error)
    Validate(ctx context.Context, ref MechanismRef, opts ValidateOptions) (*ValidationReport, error)
    Delete(ctx context.Context, ref MechanismRef, opts DeleteOptions) error
}
```

Register providers using `init()`:
```go
func init() {
    core.Register(&MyProvider{})
}
```

## 🤝 Contributing

Contributions are welcome! Here's how to get started:

1. **Fork** the repository
2. **Clone** your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/cloud-auth.git
   ```
3. **Create** a feature branch:
   ```bash
   git checkout -b feature/my-feature
   ```
4. **Make** your changes
5. **Test** your changes:
   ```bash
   go test -race ./...
   ```
6. **Lint** your code:
   ```bash
   golangci-lint run
   ```
7. **Sign off** your commits (`git commit -s`) — see [CONTRIBUTING.md](CONTRIBUTING.md)
8. **Submit** a pull request

Read [CONTRIBUTING.md](CONTRIBUTING.md) first: it covers the DCO sign-off, what a
change needs before it can merge, and the handful of things that will fail
review — weakening an architecture test to make a change compile, turning a
skipped validation check into a passing one, or retrying a 4xx.

Found a security issue? Do not open a public issue — see [SECURITY.md](SECURITY.md).

### Development Setup

```bash
# Install dependencies
go mod download

# Run tests
go test -v ./...

# Build
go build -o cloud-auth .

# Run linter
golangci-lint run
```

## 📋 Use Cases

| Use Case | Source | Target | Mechanism |
|----------|--------|--------|-----------|
| CI/CD Deployment | GitHub Actions | AWS | `aws-oidc` |
| Multi-Cloud Data Pipeline | AWS Lambda | GCP BigQuery | `gcp-wif` |
| Kubernetes Workloads | EKS Pod | AWS S3 | `k8s-federation` |
| Cross-Cloud Backup | GCP Cloud Run | Azure Blob | `azure-federated` |
| GitOps with ArgoCD | Kubernetes | Multiple Clouds | `k8s-federation` |

## 📄 License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)** - see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/anirudhbiyani">Anirudh Biyani</a>
</p>
