# Extending

Three interfaces cover every extension point. Each is small enough to implement in an
afternoon, and the existing implementations in `source/`, `target/`, and `provider/`
are the reference.

## A new source runtime

```go
package main

import (
	"context"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// SPIFFE, Vault identity tokens, a cloud not yet covered: anything that can prove who it is with an audience-pinned JWT.
type spiffeSource struct{}

// Detect must answer from the environment alone, with no credential input, and return core.ErrNotThisRuntime when this is not where we are.
func (spiffeSource) Detect(ctx context.Context) (*core.Runtime, error) {
	return &core.Runtime{Cloud: "spiffe", SubRuntime: "workload-api", Federatable: true, Issuer: "https://spiffe.example"}, nil
}

// Mint returns a proof pinned to exactly this audience. Mint fresh every call; callers rely on it for single-use tokens.
func (spiffeSource) Mint(ctx context.Context, audience string) (*core.SourceToken, error) {
	return &core.SourceToken{Kind: core.OIDC, Value: "eyJ...", Issuer: "https://spiffe.example", Subject: "spiffe://example/svc", Audience: audience}, nil
}

var _ core.SourceProvider = spiffeSource{}

func main() {}
```

Register it in a `source.Registry` (`source.NewRegistry(spiffeSource{}, ...)`) and pass
that registry to `broker.New(broker.WithRegistry(r))`. Detection order is the order of
the list.

## A new target

```go
package main

import (
	"context"

	"github.com/anirudhbiyani/cloud-auth/core"
)

type myTarget struct{ Resource string }

func (t myTarget) Cloud() core.Cloud { return "mycloud" }
func (t myTarget) Audience() string  { return "https://sts.mycloud.example" }
func (t myTarget) Validate() error   { return nil }

type myExchanger struct{}

// Exchange trades the proof for native credentials. Check tok.Kind first: refuse proof kinds the target cannot verify with core.ErrNoFirstClassPath, and say what would work.
func (myExchanger) Exchange(ctx context.Context, tok *core.SourceToken, target core.Target) (*core.Credentials, error) {
	return &core.Credentials{Cloud: "mycloud", AccessToken: "..."}, nil
}

var (
	_ core.Target    = myTarget{}
	_ core.Exchanger = myExchanger{}
)

func main() {}
```

Hand the broker a dispatcher that knows the new cloud:
`broker.New(broker.WithExchangerFor(func(c core.Cloud) (core.Exchanger, error) { ... }))`,
falling through to `target.For(c)` for the built-ins.

## A new control-plane provider

```go
package main

import (
	"context"

	"github.com/anirudhbiyani/cloud-auth/core"
)

type myProvider struct{}

func (myProvider) Name() core.Cloud { return "mycloud" }
func (myProvider) Capabilities() []core.Capability {
	return []core.Capability{core.CapabilitySetup, core.CapabilityValidate, core.CapabilityDelete, core.CapabilityDryRun}
}
func (p myProvider) HasCapability(c core.Capability) bool {
	for _, have := range p.Capabilities() {
		if have == c {
			return true
		}
	}
	return false
}

// Setup must be idempotent (a re-run lands on the same resources), honour DryRun without credentials, and roll back what it created when a later step fails (return *core.RollbackError).
func (myProvider) Setup(ctx context.Context, spec core.MechanismSpec, opts core.SetupOptions) (*core.Outputs, error) {
	return &core.Outputs{Ref: core.MechanismRef{ID: "mycloud-x", Provider: "mycloud", ResourceIDs: map[string]string{}}}, nil
}

// Validate reads the live resource and reports per-check evidence; use core.NewCheck and core.RunValidation.
func (myProvider) Validate(ctx context.Context, ref core.MechanismRef, opts core.ValidateOptions) (*core.ValidationReport, error) {
	return core.RunValidation(ctx, ref, nil), nil
}

// Delete removes only what ResourceIDs says this tool created, in dependency order.
func (myProvider) Delete(ctx context.Context, ref core.MechanismRef, opts core.DeleteOptions) error {
	return nil
}

var _ core.LifecycleProvider = myProvider{}

func init() {
	if err := core.Register(myProvider{}); err != nil {
		panic(err)
	}
}

func main() {}
```

A provider that can also enumerate its trusts implements `core.InventorySource`
(`InventoryCloud`, `ListTrustRecords`) and plugs into `core.BuildInventory` unchanged.

## Where the design constraints are written down

The non-obvious rules an extension must respect are enforced in code, and each has a
test that pins it:

| Rule | Where |
|---|---|
| A proof is checked against the target's audience before it is transmitted | `target/te.go` `checkAudienceBinding` |
| Every `Exchange` mints a fresh proof; the source proof is never cached | `broker/broker.go`, pinned by `TestEveryExchangeMintsAFreshProof` |
| Azure targets have no default scope | `core/target.go` `AzureTarget.Validate` |
| Non-federatable runtimes are refused with `ErrNonFederatableSource`, never attempted | `core/federation_interfaces.go`, `source/aws.go`, `source/azure.go` |
| A trust on a shared issuer must scope its subject | `core/specs.go` `validateSubjectScope` |

[Decisions](../design/decisions.md) records the product-level choices (which systems
are deliberately not sources or targets); the [federation matrix](../runtime/matrix.md)
explains the refused runtimes.
