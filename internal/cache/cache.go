// Package cache provides an in-memory credential cache with proactive, pre-expiry refresh.
package cache

import (
	"context"
	"errors"
	"math/rand"
	"sync"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// FetchFunc obtains fresh credentials (typically a Target Exchanger call).
type FetchFunc func(ctx context.Context) (*core.Credentials, error)

const (
	// defaultBuffer is how long before expiry a refresh is started.
	defaultBuffer = 5 * time.Minute
	// defaultJitter spreads a fleet's refreshes.
	defaultJitter = 30 * time.Second
	// defaultErrorTTL is how long a failure is remembered.
	defaultErrorTTL = 2 * time.Second
	// defaultFetchTimeout bounds a background refresh.
	defaultFetchTimeout = 30 * time.Second
)

// Cache memoizes credentials and refreshes them before they expire.
type Cache struct {
	fetch        FetchFunc
	buffer       time.Duration
	jitter       time.Duration
	errorTTL     time.Duration
	fetchTimeout time.Duration
	clock        core.Clock

	mu       sync.Mutex
	cached   *core.Credentials
	inflight chan struct{} // non-nil while a refresh is running
	lastErr  error
	errUntil time.Time
	// skew is the jitter drawn for the current credentials.
	skew time.Duration
}

// Option configures a Cache.
type Option func(*Cache)

// WithClock sets the clock (defaults to the system clock).
func WithClock(c core.Clock) Option { return func(x *Cache) { x.clock = c } }

// WithBuffer sets how long before expiry credentials are proactively refreshed.
func WithBuffer(d time.Duration) Option { return func(x *Cache) { x.buffer = d } }

// WithJitter sets how much the refresh buffer varies between refreshes.
func WithJitter(d time.Duration) Option { return func(x *Cache) { x.jitter = d } }

// WithErrorTTL sets how long a fetch failure is remembered before another attempt is made.
func WithErrorTTL(d time.Duration) Option { return func(x *Cache) { x.errorTTL = d } }

// WithFetchTimeout bounds each background refresh.
func WithFetchTimeout(d time.Duration) Option { return func(x *Cache) { x.fetchTimeout = d } }

// New builds a Cache around fetch.
func New(fetch FetchFunc, opts ...Option) *Cache {
	c := &Cache{
		fetch:        fetch,
		buffer:       defaultBuffer,
		jitter:       defaultJitter,
		errorTTL:     defaultErrorTTL,
		fetchTimeout: defaultFetchTimeout,
		clock:        core.SystemClock{},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Get returns cached credentials, refreshing them if absent or expired, and starting a background refresh if they are within the refresh buffer.
func (c *Cache) Get(ctx context.Context) (*core.Credentials, error) {
	c.mu.Lock()
	now := c.clock.Now()

	// Still genuinely valid: return it.
	if creds := c.serveLocked(now); creds != nil {
		if c.cached.Expired(now, c.buffer+c.skew) && c.inflight == nil {
			c.startRefreshLocked()
		}
		c.mu.Unlock()
		return creds, nil
	}

	// Expired or absent, and a recent attempt failed: return that failure rather than piling onto a service that is already down.
	if c.lastErr != nil && now.Before(c.errUntil) {
		err := c.lastErr
		c.mu.Unlock()
		return nil, err
	}

	wait := c.inflight
	if wait == nil {
		wait = c.startRefreshLocked()
	}
	c.mu.Unlock()

	select {
	case <-ctx.Done():
		// This caller's deadline is its own.
		return nil, ctx.Err()
	case <-wait:
	}

	// Take whatever that refresh produced.
	c.mu.Lock()
	defer c.mu.Unlock()

	if creds := c.serveLocked(c.clock.Now()); creds != nil {
		return creds, nil
	}
	if c.lastErr != nil {
		return nil, c.lastErr
	}
	return nil, errNoCredentials
}

// serveLocked returns a copy of the cached credentials if they are usable, or nil.
func (c *Cache) serveLocked(now time.Time) *core.Credentials {
	if c.cached == nil || c.cached.Expired(now, 0) {
		return nil
	}
	cp := *c.cached
	return &cp
}

// Invalidate drops the cached credentials.
func (c *Cache) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cached = nil
	c.lastErr = nil
	c.errUntil = time.Time{}
}

// startRefreshLocked begins one refresh and returns the channel that closes when it finishes.
func (c *Cache) startRefreshLocked() chan struct{} {
	done := make(chan struct{})
	c.inflight = done

	go func() {
		// Detached from any caller's context: a caller that cancels must not abort a refresh the other waiters depend on.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), c.fetchTimeout)
		defer cancel()

		fresh, err := c.fetch(ctx)

		c.mu.Lock()
		now := c.clock.Now()
		switch {
		case err != nil:
			c.storeErrLocked(err, now)
		// A fetch that succeeds but hands back credentials which are already expired — a nil result, or the zero Expiry that Credentials.Expired treats as unusable — must be an error, not a value.
		case fresh == nil:
			c.storeErrLocked(errNoCredentials, now)
		case fresh.Expired(now, 0):
			c.storeErrLocked(&staleFetchError{expiry: fresh.Expiry}, now)
		default:
			c.cached, c.lastErr, c.errUntil = fresh, nil, time.Time{}
			c.skew = c.drawJitter()
		}
		c.inflight = nil
		c.mu.Unlock()

		close(done)
	}()

	return done
}

// drawJitter returns a random offset in [0, jitter) added to the refresh buffer, so instances that started together do not refresh together.
func (c *Cache) drawJitter() time.Duration {
	if c.jitter <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(c.jitter))) // #nosec G404 -- spreading load, not a secret
}

// storeErrLocked records a failure for the negative-cache window.
func (c *Cache) storeErrLocked(err error, now time.Time) {
	c.lastErr = err
	c.errUntil = now.Add(c.errorTTL)
}

// errNoCredentials is returned when a fetch reports success but produces nothing.
var errNoCredentials = errors.New("cloud-auth/cache: fetch returned no credentials and no error")

// staleFetchError reports a fetch that produced credentials already past their usable window.
type staleFetchError struct{ expiry time.Time }

func (e *staleFetchError) Error() string {
	if e.expiry.IsZero() {
		return "cloud-auth/cache: fetch returned credentials with an unknown expiry, which cannot " +
			"be cached; the exchanger should have rejected the STS response that produced them"
	}
	return "cloud-auth/cache: fetch returned credentials that expired at " +
		e.expiry.UTC().Format(time.RFC3339) + "; check this host's clock against the STS endpoint"
}
