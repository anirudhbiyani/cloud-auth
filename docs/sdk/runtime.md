# Runtime exchange

The runtime half answers one question for a workload: *give me short-lived credentials
for that other cloud, using only what this runtime already proves about me.* No
long-lived secret is read or written at any point.

## One call

`broker.Exchange` detects where it is running, mints a proof pinned to the target's
audience, and exchanges it at the target's token service.

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/anirudhbiyani/cloud-auth/broker"
	"github.com/anirudhbiyani/cloud-auth/core"
)

func main() {
	ctx := context.Background()

	// A GCP workload (GCE, GKE, Cloud Run) obtaining AWS credentials.
	target := core.AWSTarget{
		RoleARN: "arn:aws:iam::123456789012:role/from-gcp",
		// TokenAudience is optional: AWS defaults to sts.amazonaws.com.
	}

	creds, runtime, err := broker.New().Exchange(ctx, target)
	if err != nil {
		log.Fatal(err)
	}

	// runtime says what was detected; creds is redacted when printed.
	fmt.Printf("as %s/%s (%s) -> %s, expires %s\n",
		runtime.Cloud, runtime.SubRuntime, runtime.Subject, creds.Cloud, creds.Expiry)

	// The plaintext is only reachable through Reveal.
	plain := creds.Reveal()
	_ = plain.AccessKeyID
	_ = plain.SecretAccessKey
	_ = plain.SessionToken
}
```

The target types mirror the CLI flags:

| Target | Type | Required fields |
|---|---|---|
| AWS | `core.AWSTarget` | `RoleARN`; optional `SessionName`, `TokenAudience` |
| GCP | `core.GCPTarget` | `WorkloadIdentityPool` (full provider resource name); optional `ImpersonateServiceAccount`, `TokenAudience` |
| Azure | `core.AzureTarget` | `Tenant`, `ClientID`, `Scope` (no default, on purpose); optional `TokenAudience` |
| Anthropic | `core.AnthropicTarget` | `FederationRuleID`, `OrganizationID`, `ServiceAccountID`, `TokenAudience` (no default); optional `WorkspaceID` |
| OpenAI | `core.OpenAITarget` | `IdentityProviderID`, `ServiceAccountID`; `TokenAudience` defaults to `https://api.openai.com/v1` |

`Validate()` on any target rejects an incomplete binding before a network call is
made, and the broker calls it for you.

## Plug into the cloud SDKs

The `adapters` package wraps the same mint-then-exchange flow in each SDK's native
credential interface, with caching and pre-expiry refresh. You detect once, build the
adapter, and the SDK calls it whenever it needs a token.

```go
package main

import (
	"context"
	"log"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/anirudhbiyani/cloud-auth/adapters"
	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/source"
	"github.com/anirudhbiyani/cloud-auth/target"
)

func main() {
	ctx := context.Background()

	// 1. Detect the source runtime once.
	src, _, err := source.Default().Detect(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// 2. Pick the exchanger for the target cloud.
	ex, err := target.For(core.AWS)
	if err != nil {
		log.Fatal(err)
	}

	// 3. The adapter is an aws.CredentialsProvider.
	provider := adapters.NewAWS(src, ex, core.AWSTarget{
		RoleARN: "arn:aws:iam::123456789012:role/from-gke",
	})

	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(provider),
	)
	if err != nil {
		log.Fatal(err)
	}
	_ = s3.NewFromConfig(cfg) // every call exchanges lazily and refreshes before expiry
}
```

The other two adapters follow the same shape:

```go
package main

import (
	"context"
	"log"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"golang.org/x/oauth2"

	"github.com/anirudhbiyani/cloud-auth/adapters"
	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/source"
	"github.com/anirudhbiyani/cloud-auth/target"
)

func main() {
	ctx := context.Background()
	src, _, err := source.Default().Detect(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// GCP: an oauth2.TokenSource, accepted by every Google client via option.WithTokenSource.
	gcpEx, _ := target.For(core.GCP)
	var ts oauth2.TokenSource = adapters.NewGCP(src, gcpEx, core.GCPTarget{
		WorkloadIdentityPool: "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/providers/aws",
	})
	_ = ts

	// Azure: an azcore.TokenCredential, accepted by every armXxx / azblob client.
	azEx, _ := target.For(core.Azure)
	var cred azcore.TokenCredential = adapters.NewAzure(src, azEx, core.AzureTarget{
		Tenant:   "contoso.onmicrosoft.com",
		ClientID: "00000000-0000-0000-0000-000000000000",
		Scope:    "https://storage.azure.com/.default",
	})
	_ = cred
}
```

Adapter options: `adapters.WithBuffer(d)` sets how long before expiry a refresh happens;
`adapters.WithClock` injects a clock for tests. `Invalidate()` drops the cache so the
next call re-exchanges, for example after a 401.

## Anthropic and OpenAI

Both platforms return a bearer token. There is no SDK adapter because their SDKs take
the token as a plain string: put `Reveal().AccessToken` where the API key would go.

```go
package main

import (
	"context"
	"log"
	"os"

	"github.com/anirudhbiyani/cloud-auth/broker"
	"github.com/anirudhbiyani/cloud-auth/core"
)

func main() {
	ctx := context.Background()
	creds, _, err := broker.New().Exchange(ctx, core.AnthropicTarget{
		FederationRuleID: "fdrl_01ABCDEFabcdef0123456789XY",
		OrganizationID:   "00000000-0000-0000-0000-000000000000",
		ServiceAccountID: "svac_01ABCDEFabcdef0123456789XY",
		WorkspaceID:      "wrkspc_01ABCDEFabcdef0123456789XY",
		TokenAudience:    "https://api.anthropic.com",
	})
	if err != nil {
		log.Fatal(err)
	}
	// The Anthropic SDKs read this variable as a bearer token; unset ANTHROPIC_API_KEY, it wins otherwise.
	_ = os.Setenv("ANTHROPIC_AUTH_TOKEN", creds.Reveal().AccessToken)
}
```

Mint a fresh exchange per token lifetime rather than caching the source proof: GitHub
Actions and some Kubernetes issuers put a `jti` on their tokens, and Anthropic accepts
each one exactly once. The broker already mints a new proof on every `Exchange`.

## Restrict which runtime may be detected

Detection probes AWS, then GCP, then Azure, then GitHub Actions. A workload that must
only ever authenticate *as* one specific runtime pins it with a selector, so a
misconfigured pod cannot quietly pick up the node's identity instead of its own.

```go
package main

import (
	"log"

	"github.com/anirudhbiyani/cloud-auth/broker"
	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/source"
)

func main() {
	sel, err := core.ParseSelector("aws/eks-irsa") // or "gcp", "azure/aks-workload-identity", "github"
	if err != nil {
		log.Fatal(err)
	}
	b := broker.New(broker.WithRegistry(source.DefaultRestricted(sel)))
	_ = b // Exchange returns core.ErrRuntimeMismatch if anything else is detected
}
```

## Reuse the CLI's config file

The YAML file `cloud-auth exec --config` reads is a library type too, so a service can
share one config with its operators.

```go
package main

import (
	"context"
	"log"

	"github.com/anirudhbiyani/cloud-auth/broker"
	"github.com/anirudhbiyani/cloud-auth/config"
	"github.com/anirudhbiyani/cloud-auth/source"
)

func main() {
	cfg, err := config.Load("cloud-auth.yaml")
	if err != nil {
		log.Fatal(err)
	}
	target, err := cfg.Target("prod-aws") // a named entry under `targets:`
	if err != nil {
		log.Fatal(err)
	}
	sel, err := cfg.SourceSelector() // `source.detect`, or auto when absent
	if err != nil {
		log.Fatal(err)
	}
	b := broker.New(broker.WithRegistry(source.DefaultRestricted(sel)))
	if _, _, err := b.Exchange(context.Background(), target); err != nil {
		log.Fatal(err)
	}
}
```

## Lower level: mint and exchange yourself

The broker is three calls. Use the pieces directly when you need to inspect the proof,
exchange one proof at several targets, or test an exchanger in isolation.

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/source"
	"github.com/anirudhbiyani/cloud-auth/target"
)

func main() {
	ctx := context.Background()
	tgt := core.GCPTarget{WorkloadIdentityPool: "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/providers/aws"}

	src, rt, err := source.Default().Detect(ctx)
	if err != nil {
		log.Fatal(err)
	}
	if !rt.Federatable {
		log.Fatalf("%s/%s cannot mint a portable proof", rt.Cloud, rt.SubRuntime)
	}

	proof, err := src.Mint(ctx, tgt.Audience()) // audience-pinned; redacted when printed
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("proof kind=%v iss=%s sub=%s\n", proof.Kind, proof.Issuer, proof.Subject)

	ex, err := target.For(tgt.Cloud())
	if err != nil {
		log.Fatal(err)
	}
	creds, err := ex.Exchange(ctx, proof, tgt)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(creds) // "[redacted gcp credentials, expires ...]"
}
```
