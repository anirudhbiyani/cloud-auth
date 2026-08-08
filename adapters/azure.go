package adapters

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
	"github.com/anirudhbiyani/cloud-auth/internal/cache"
)

// AzureProvider satisfies azcore.TokenCredential so it can be passed to any
// Azure SDK client.
type AzureProvider struct {
	cache *cache.Cache
}

// NewAzure builds an AzureProvider.
func NewAzure(src cloudauth.SourceProvider, ex cloudauth.Exchanger, target cloudauth.Target, opts ...Option) *AzureProvider {
	return &AzureProvider{cache: newCache(src, ex, target, resolve(opts))}
}

// GetToken implements azcore.TokenCredential.
func (p *AzureProvider) GetToken(ctx context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	c, err := p.cache.Get(ctx)
	if err != nil {
		return azcore.AccessToken{}, err
	}
	return azcore.AccessToken{
		Token:     c.AccessToken,
		ExpiresOn: c.Expiry,
	}, nil
}
