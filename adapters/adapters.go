// Package adapters wraps cloud-auth's mint→exchange flow in each cloud SDK's native credential interface, so a workload drops cloud-auth straight into its existing SDK config with no glue code.
package adapters

import (
	"context"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/internal/cache"
)

// options are shared across adapters.
type options struct {
	clock  core.Clock
	buffer time.Duration
}

// Option configures an adapter.
type Option func(*options)

// WithClock sets the clock used for cache expiry (defaults to system clock).
func WithClock(c core.Clock) Option { return func(o *options) { o.clock = c } }

// WithBuffer sets the pre-expiry refresh buffer.
func WithBuffer(d time.Duration) Option { return func(o *options) { o.buffer = d } }

func resolve(opts []Option) options {
	o := options{clock: core.SystemClock{}, buffer: 5 * time.Minute}
	for _, f := range opts {
		f(&o)
	}
	return o
}

// newCache builds a credential cache whose fetch mints a source proof and exchanges it at the target.
func newCache(src core.SourceProvider, ex core.Exchanger, target core.Target, o options) *cache.Cache {
	fetch := func(ctx context.Context) (*core.Credentials, error) {
		tok, err := src.Mint(ctx, target.Audience())
		if err != nil {
			return nil, err
		}
		return ex.Exchange(ctx, tok, target)
	}
	return cache.New(fetch, cache.WithClock(o.clock), cache.WithBuffer(o.buffer))
}
