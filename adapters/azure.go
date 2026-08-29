package adapters

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/internal/cache"
)

// AzureProvider satisfies azcore.TokenCredential so it can be passed to any
// Azure SDK client.
type AzureProvider struct {
	cache *cache.Cache
}

// NewAzure builds an AzureProvider.
func NewAzure(src core.SourceProvider, ex core.Exchanger, target core.Target, opts ...Option) *AzureProvider {
	return &AzureProvider{cache: newCache(src, ex, target, resolve(opts))}
}

// GetToken implements azcore.TokenCredential.
func (p *AzureProvider) GetToken(ctx context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	c, err := p.cache.Get(ctx)
	if err != nil {
		return azcore.AccessToken{}, err
	}
	return azcore.AccessToken{
		Token:     c.Reveal().AccessToken,
		ExpiresOn: c.Expiry,
	}, nil
}

// Invalidate discards the cached credentials so the next call re-exchanges.
//
// Expiry cannot express revocation: a session dropped server-side, or a role
// whose policy changed, still looks valid locally until it runs out. A caller
// that has just seen a 403 knows more than the cache does, and this is how it
// says so.
func (p *AzureProvider) Invalidate() { p.cache.Invalidate() }
