<p align="center">
  <h1 align="center">☁️ cloud-auth</h1>
  <p align="center">
    <strong>Unified Cross-Cloud Authentication Lifecycle Management</strong>
  </p>
</p>

<p align="center">
  <a href="https://pkg.go.dev/github.com/anirudhbiyani/cloud-auth"><img src="https://pkg.go.dev/badge/github.com/anirudhbiyani/cloud-auth.svg" alt="Go Reference"></a>
  <a href="https://goreportcard.com/report/github.com/anirudhbiyani/cloud-auth"><img src="https://goreportcard.com/badge/github.com/anirudhbiyani/cloud-auth" alt="Go Report Card"></a>
  <a href="https://opensource.org/licenses/LGPL-3.0"><img src="https://img.shields.io/badge/License-LGPL_v3-blue.svg" alt="License: LGPL-3.0"></a>
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white" alt="Go Version">
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
  --subject "repo:myorg/myrepo:*" \
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

### 🌐 Multi-Cloud Support
Full lifecycle support for major cloud providers:

| Provider | Token | Setup | Validate | Delete | Federation Types |
|----------|:-----:|:-----:|:--------:|:------:|------------------|
| **AWS** | ✅ | ✅ | ✅ | ✅ | OIDC Trust |
| **GCP** | ✅ | ✅ | ✅ | ✅ | Workload Identity |
| **Azure** | ✅ | ✅ | ✅ | ✅ | Federated Credentials |
| **Cloudflare** | ✅ | ✅ | ✅ | ✅ | Access Service Tokens |
| **Vault** | ✅ | ✅ | ✅ | ✅ | JWT Auth |
| **GitHub OIDC** | ✅ | - | - | - | Token Source |
| **Kubernetes** | ✅ | - | - | - | Token Source |

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

| Command | Description |
|---------|-------------|
| `setup` | Create or update a cross-cloud authentication mechanism |
| `validate` | Validate an existing mechanism configuration |
| `delete` | Delete a mechanism and its resources |
| `list` | List all managed mechanisms |
| `describe` | Show details of a specific mechanism |
| `providers` | List available providers and their capabilities |
| `version` | Show version information |

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
  "subject": "repo:myorg/myrepo:*",
  "subject_condition": "StringLike",
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

Validation checks include:
- ✅ Resource existence
- ✅ Trust policy configuration
- ✅ OIDC provider configuration
- ✅ Permission policies
- ✅ Audience/Subject claims
- ✅ Token acquisition (optional)

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

    "github.com/anirudhbiyani/cloud-auth/pkg/cloudauth"
    _ "github.com/anirudhbiyani/cloud-auth/pkg/providers/aws"
    _ "github.com/anirudhbiyani/cloud-auth/pkg/providers/gcp"
)

func main() {
    ctx := context.Background()

    // Define the mechanism specification
    spec := &cloudauth.AWSRoleTrustOIDCSpec{
        RoleName:         "github-actions-role",
        AccountID:        "123456789012",
        OIDCProviderURL:  "https://token.actions.githubusercontent.com",
        Audience:         "sts.amazonaws.com",
        Subject:          "repo:myorg/myrepo:*",
        SubjectCondition: "StringLike",
        Source:           cloudauth.ProviderGitHubOIDC,
        PolicyARNs: []string{
            "arn:aws:iam::aws:policy/ReadOnlyAccess",
        },
    }

    // Create a state store
    stateStore, err := cloudauth.NewFileStateStore("")
    if err != nil {
        log.Fatal(err)
    }

    // Create a manager
    manager := cloudauth.NewManager(
        cloudauth.WithStateStore(stateStore),
    )

    // Setup the mechanism
    outputs, err := manager.Setup(ctx, spec, cloudauth.SetupOptions{})
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Created mechanism: %s\n", outputs.Ref.ID)
    fmt.Printf("Role ARN: %s\n", outputs.Values["role_arn"])

    // Validate the mechanism
    report, err := manager.Validate(ctx, outputs.Ref, cloudauth.ValidateOptions{})
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

### Common Options

| Option | Description |
|--------|-------------|
| `--dry-run` | Preview changes without applying them |
| `--force` | Overwrite existing resources |
| `--state <path>` | Custom state file path |
| `-v, --verbose` | Verbose output |

## 🏗️ Architecture

```
cloud-auth/
├── main.go                    # CLI entry point
├── pkg/
│   ├── cloudauth/             # Core library
│   │   ├── interfaces.go      # Provider and Manager interfaces
│   │   ├── types.go           # Core types (MechanismRef, Outputs, etc.)
│   │   ├── specs.go           # Mechanism specifications
│   │   ├── manager.go         # Default manager implementation
│   │   ├── registry.go        # Provider registry
│   │   ├── state.go           # State store implementations
│   │   ├── validation.go      # Validation framework
│   │   └── errors.go          # Structured errors
│   └── providers/             # Provider implementations
│       ├── aws/               # AWS IAM, STS, OIDC
│       ├── gcp/               # GCP Workload Identity
│       ├── azure/             # Azure AD Federated Credentials
│       ├── cloudflare/        # Cloudflare Access
│       └── vault/             # HashiCorp Vault
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
    cloudauth.Register(&MyProvider{})
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
7. **Submit** a pull request

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

This project is licensed under the **LGPL-3.0 License** - see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/anirudhbiyani">Anirudh Biyani</a>
</p>
