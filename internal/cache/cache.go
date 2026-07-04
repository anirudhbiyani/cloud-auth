// Package cache provides an in-memory credential cache with proactive,
// pre-expiry refresh. Credentials are never written to disk. A mutex around the
// fetch gives single-flight behavior: concurrent callers on a cold or stale
// cache trigger exactly one refresh and share its result.
package cache

import (
	"context"
	"sync"
	"time"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
)

// FetchFunc obtains fresh credentials (typically a Target Exchanger call).
type FetchFunc func(ctx context.Context) (*cloudauth.Credentials, error)

// Cache memoizes credentials and refreshes them before they expire.
type Cache struct {
	fetch  FetchFunc
	buffer time.Duration
	clock  cloudauth.Clock

	mu     sync.Mutex
	cached *cloudauth.Credentials
}

// Option configures a Cache.
type Option func(*Cache)

// WithClock sets the clock (defaults to the system clock).
func WithClock(c cloudauth.Clock) Option { return func(x *Cache) { x.clock = c } }

// WithBuffer sets how long before expiry credentials are proactively refreshed.
func WithBuffer(d time.Duration) Option { return func(x *Cache) { x.buffer = d } }

// New builds a Cache around fetch.
func New(fetch FetchFunc, opts ...Option) *Cache {
	c := &Cache{
		fetch:  fetch,
		buffer: 5 * time.Minute,
		clock:  cloudauth.SystemClock{},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Get returns cached credentials, refreshing them if absent or within the
// refresh buffer of expiry. The returned pointer is a copy the caller may hold.
func (c *Cache) Get(ctx context.Context) (*cloudauth.Credentials, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.clock.Now()
	if c.cached != nil && !c.cached.Expired(now, c.buffer) {
		cp := *c.cached
		return &cp, nil
	}
	fresh, err := c.fetch(ctx)
	if err != nil {
		return nil, err
	}
	c.cached = fresh
	cp := *fresh
	return &cp, nil
}
