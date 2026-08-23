package cache

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// Regression for the audit's probe H: credentials whose expiry never parsed were
// cached forever — advancing a year used to yield exactly one fetch.
//
// They are now refused outright rather than re-fetched. Serving them would mean
// handing out credentials of unknown lifetime; re-fetching them forever would
// spin, because Get loops until it holds something valid. The exchangers already
// reject the STS responses that produce this, so reaching it means a bug
// upstream, and an error naming that beats either alternative.
func TestCredentialsWithUnknownExpiryAreRefused(t *testing.T) {
	var calls int64
	clock := core.NewFakeClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	c := New(func(context.Context) (*core.Credentials, error) {
		atomic.AddInt64(&calls, 1)
		return &core.Credentials{Cloud: core.AWS, AccessKeyID: "ASIA123"}, nil // zero Expiry
	}, WithClock(clock), WithErrorTTL(0))

	creds, err := c.Get(context.Background())
	if err == nil {
		t.Fatalf("want an error, got credentials %v", creds)
	}
	if !strings.Contains(err.Error(), "unknown expiry") {
		t.Errorf("error should name the problem, got %v", err)
	}
	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Errorf("fetches = %d, want 1: the loop must not spin on an unusable result", got)
	}
}

// A fetch reporting success with no credentials at all is the same class of bug.
func TestNilCredentialsAreRefused(t *testing.T) {
	c := New(func(context.Context) (*core.Credentials, error) { return nil, nil }, WithErrorTTL(0))
	if _, err := c.Get(context.Background()); err == nil {
		t.Fatal("want an error when a fetch returns neither credentials nor an error")
	}
}
