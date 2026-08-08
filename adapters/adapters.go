// Package adapters wraps cloud-auth's mint→exchange flow in each cloud SDK's
// native credential interface, so a workload drops cloud-auth straight into its
// existing SDK config with no glue code. Each adapter caches credentials in
// memory and refreshes them before expiry.
package adapters

import (
	"context"
	"time"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
	"github.com/anirudhbiyani/cloud-auth/internal/cache"
)

// options are shared across adapters.
type options struct {
	clock  cloudauth.Clock
	buffer time.Duration
}

// Option configures an adapter.
type Option func(*options)

// WithClock sets the clock used for cache expiry (defaults to system clock).
func WithClock(c cloudauth.Clock) Option { return func(o *options) { o.clock = c } }

// WithBuffer sets the pre-expiry refresh buffer.
func WithBuffer(d time.Duration) Option { return func(o *options) { o.buffer = d } }

func resolve(opts []Option) options {
	o := options{clock: cloudauth.SystemClock{}, buffer: 5 * time.Minute}
	for _, f := range opts {
		f(&o)
	}
	return o
}

// newCache builds a credential cache whose fetch mints a source proof and
// exchanges it at the target. This is the single mint→exchange pipeline every
// adapter shares.
func newCache(src cloudauth.SourceProvider, ex cloudauth.Exchanger, target cloudauth.Target, o options) *cache.Cache {
	fetch := func(ctx context.Context) (*cloudauth.Credentials, error) {
		tok, err := src.Mint(ctx, target.Audience)
		if err != nil {
			return nil, err
		}
		return ex.Exchange(ctx, tok, target)
	}
	return cache.New(fetch, cache.WithClock(o.clock), cache.WithBuffer(o.buffer))
}
