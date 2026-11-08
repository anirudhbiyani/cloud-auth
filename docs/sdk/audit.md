# Audit: inventory of federated trust

`cloud-auth audit` is `core.BuildInventory` plus formatting. It enumerates every
identity in each cloud that trusts an external issuer, normalizes them into
`core.TrustRecord`, scores how much each subject condition admits, and checks whether
the namespace it trusts still exists and is yours.

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/anirudhbiyani/cloud-auth/core"
	awsprovider "github.com/anirudhbiyani/cloud-auth/provider/aws"
	azureprovider "github.com/anirudhbiyani/cloud-auth/provider/azure"
	gcpprovider "github.com/anirudhbiyani/cloud-auth/provider/gcp"
	"github.com/anirudhbiyani/cloud-auth/source"
)

func main() {
	ctx := context.Background()

	// Every control-plane provider is also an InventorySource; include the clouds you have credentials for.
	sources := []core.InventorySource{awsprovider.New(), gcpprovider.New(), azureprovider.New()}

	// Resolvers decide whether a trusted namespace is live, unregistered (claimable), or someone else's.
	// Naming your GitHub organisations is what lets "exists" be classified as "ours" versus "a stranger's".
	resolvers := []core.NamespaceResolver{
		source.NewGitHubNamespaceResolver(source.WithOurGitHubOwners("myorg", "myorg-infra")),
	}

	records, failures := core.BuildInventory(ctx, sources, resolvers)
	for _, err := range failures { // one cloud failing does not hide the others
		log.Println("partial:", err)
	}
	for _, r := range records {
		fmt.Printf("%-6s %-40s %s\n  sub=%q breadth=%v liveness=%s severity=%v\n",
			r.Cloud, r.Name, r.Issuer, r.SubjectCondition, r.Breadth, r.Liveness.State, r.Severity())
	}
}
```

What a record tells you:

- `Breadth` is how many identities the subject condition admits, from one exact
  subject up to "any token from this issuer". It is the first thing to sort by.
- `Liveness.State` is `live`, `not_ours`, `unregistered`, or `unknown`. An
  `unregistered` GitHub namespace is the critical case: anyone can register it and
  mint a token whose subject matches the trust exactly.
- `RenameFragile` flags GitHub subjects in the name-based format that break on
  repository rename or transfer.
- `Severity()` combines these into one ranking, the same one the CLI prints.

Set `GITHUB_TOKEN` when auditing private repositories: GitHub answers 404 for both a
private repository and a nonexistent one, and the resolver reports `unknown` rather
than guess when it cannot tell them apart.
