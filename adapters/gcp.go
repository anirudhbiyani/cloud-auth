package adapters

import (
	"context"

	"golang.org/x/oauth2"

	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/internal/cache"
)

// GCPProvider satisfies oauth2.TokenSource so it plugs into cloud.google.com/go
// clients (option.WithTokenSource).
type GCPProvider struct {
	cache *cache.Cache
}

// NewGCP builds a GCPProvider.
func NewGCP(src core.SourceProvider, ex core.Exchanger, target core.Target, opts ...Option) *GCPProvider {
	return &GCPProvider{cache: newCache(src, ex, target, resolve(opts))}
}

// Token implements oauth2.TokenSource. The oauth2 interface has no context, so
// the exchange uses a background context.
func (p *GCPProvider) Token() (*oauth2.Token, error) {
	c, err := p.cache.Get(context.Background())
	if err != nil {
		return nil, err
	}
	return &oauth2.Token{
		AccessToken: c.Reveal().AccessToken,
		TokenType:   "Bearer",
		Expiry:      c.Expiry,
	}, nil
}

// Invalidate discards the cached credentials so the next call re-exchanges.
//
// Expiry cannot express revocation: a session dropped server-side, or a role
// whose policy changed, still looks valid locally until it runs out. A caller
// that has just seen a 403 knows more than the cache does, and this is how it
// says so.
func (p *GCPProvider) Invalidate() { p.cache.Invalidate() }
