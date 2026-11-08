# Control plane

The control plane creates the trust the runtime half later uses: an IAM role trusting
an issuer, a Workload Identity Pool provider, an Entra federated credential, a
Kubernetes service-account binding, or a Claude Platform federation rule. One manager,
one spec type per mechanism, three operations.

## Manager, specs, state

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/anirudhbiyani/cloud-auth/core"
	_ "github.com/anirudhbiyani/cloud-auth/provider/aws" // registers the AWS provider
)

func main() {
	ctx := context.Background()

	// Where mechanism references are recorded so `Delete` later knows what it owns.
	store, err := core.NewFileStateStore(core.DefaultStateStorePath()) // ~/.cloud-auth/state.json
	if err != nil {
		log.Fatal(err)
	}
	manager := core.NewManager(core.WithStateStore(store))

	spec := &core.AWSRoleTrustOIDCSpec{
		RoleName:         "github-deploy",
		AccountID:        "123456789012",
		OIDCProviderURL:  "https://token.actions.githubusercontent.com",
		Audience:         "sts.amazonaws.com",
		Subject:          "repo:myorg/myrepo:ref:refs/heads/main",
		SubjectCondition: "StringEquals",
		Source:           core.GitHubOIDC,
		PolicyARNs:       []string{"arn:aws:iam::aws:policy/ReadOnlyAccess"},
	}

	// Dry run: a plan, no credentials needed, nothing created.
	plan, err := manager.Setup(ctx, spec, core.SetupOptions{DryRun: true})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(plan.Values["plan"])

	// Real run. Re-running with the same spec converges on the same cloud resources (each run still records its own reference in the state store).
	out, err := manager.Setup(ctx, spec, core.SetupOptions{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(out.Ref.ID, out.Values["role_arn"])
	for _, line := range out.Instructions { // what the runtime side needs, e.g. the exec command
		fmt.Println(" ", line)
	}

	// Validate reads the live resource and diffs it against what was set up.
	report, err := manager.Validate(ctx, out.Ref, core.ValidateOptions{})
	if err != nil {
		log.Fatal(err)
	}
	for _, c := range report.FailedChecks() {
		fmt.Printf("FAIL %s: %s\n  fix: %s\n", c.Name, c.Message, c.Remediation)
	}

	// Delete removes what cloud-auth created; OwnedOnly refuses to touch a mechanism it did not create.
	if err := manager.Delete(ctx, out.Ref, core.DeleteOptions{OwnedOnly: true}); err != nil {
		log.Fatal(err)
	}
}
```

Every provider resolves its own cloud credentials lazily from the ambient environment
(AWS SDK default chain, Google Application Default Credentials, Azure default
credential, `ANTHROPIC_AUTH_TOKEN`). A dry run needs none of them.

## Spec types

| Mechanism | Spec | Provider package | Target |
|---|---|---|---|
| IAM role trusting an OIDC issuer | `core.AWSRoleTrustOIDCSpec` | `provider/aws` | AWS |
| Workload Identity Pool + provider | `core.GCPWorkloadIdentityPoolSpec` | `provider/gcp` | GCP |
| Entra federated identity credential | `core.AzureFederatedCredentialSpec` | `provider/azure` | Azure |
| Kubernetes SA to a cloud identity | `core.K8sServiceAccountFederationSpec` | the target cloud's provider | AWS, GCP, or Azure |
| Claude Platform federation rule | `core.AnthropicFederationSpec` | `provider/anthropic` | Anthropic |
| Vault JWT auth broker | `vault.VaultBrokerSpec` | `provider/vault` | Vault |

Each spec has `Validate()`, called for you by `Setup`, and the manager routes it to the
provider named by its `TargetProvider()`. Blank-import every provider package your
program may need; an unregistered provider is a clear error, not a silent no-op.

A GCP example, with the subject scoped to one external identity:

```go
package main

import (
	"github.com/anirudhbiyani/cloud-auth/core"
	_ "github.com/anirudhbiyani/cloud-auth/provider/gcp"
)

var spec = &core.GCPWorkloadIdentityPoolSpec{
	ProjectID:           "my-project",
	ProjectNumber:       "123456789012",
	PoolID:              "github-pool",
	ProviderID:          "github",
	ProviderType:        "oidc",
	OIDCIssuerURL:       "https://token.actions.githubusercontent.com",
	AllowedAudiences:    []string{"https://github.com/myorg"},
	AttributeMapping:    map[string]string{"google.subject": "assertion.sub"},
	AttributeCondition:  `assertion.sub == "repo:myorg/myrepo:ref:refs/heads/main"`,
	SubjectScope:        "repo:myorg/myrepo:ref:refs/heads/main",
	ServiceAccountEmail: "deploy@my-project.iam.gserviceaccount.com",
	Source:              core.GitHubOIDC,
}

func main() { _ = spec.Validate() }
```

And the Anthropic one, which needs an `org:admin` OAuth token in `ANTHROPIC_AUTH_TOKEN`
and may only create `workspace:developer` or `workspace:inference` rules (the API's
rule for OAuth callers, enforced by `Validate` before any request):

```go
package main

import (
	"github.com/anirudhbiyani/cloud-auth/core"
	_ "github.com/anirudhbiyani/cloud-auth/provider/anthropic"
)

var spec = &core.AnthropicFederationSpec{
	OrganizationID:     "00000000-0000-0000-0000-000000000000",
	ServiceAccountName: "deploy-bot",
	IssuerURL:          "https://token.actions.githubusercontent.com",
	RuleName:           "gha-main-deploy",
	SubjectPrefix:      "repo:myorg/myrepo:ref:refs/heads/main",
	Audience:           "https://api.anthropic.com",
	WorkspaceID:        "wrkspc_01ABCDEFabcdef0123456789XY",
	OAuthScope:         "workspace:inference",
	Source:             core.GitHubOIDC,
}

func main() { _ = spec.Validate() }
```

## State stores

`Setup` records a `core.MechanismRef` so that `Delete` and `List` work later and so
that `OwnedOnly` means something. Three implementations ship:

| Store | Constructor | Use |
|---|---|---|
| File | `core.NewFileStateStore(path)` | one operator, one machine; the CLI default |
| Memory | `core.NewMemoryStateStore()` | tests and ephemeral jobs |
| Object store | `state.New(objects)` with `state.S3Objects` | shared state across a team or CI, with retry and conflict handling |

Anything implementing `core.StateStore` (six methods: `Save`, `Get`, `List`, `Delete`, `Exists`, `UpdateOwnership`) can be passed to
`core.WithStateStore`.

## Listing and reading back

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/anirudhbiyani/cloud-auth/core"
)

func main() {
	ctx := context.Background()
	store, _ := core.NewFileStateStore(core.DefaultStateStorePath())
	manager := core.NewManager(core.WithStateStore(store))

	refs, err := manager.List(ctx, core.ListFilter{Provider: core.AWS})
	if err != nil {
		log.Fatal(err)
	}
	for _, ref := range refs {
		fmt.Printf("%s %s owned=%v %v\n", ref.ID, ref.Type, ref.Owned, ref.ResourceIDs)
	}
}
```
