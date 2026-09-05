package cache

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
)

func TestGetFetchesThenCaches(t *testing.T) {
	base := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	clk := core.NewFakeClock(base)
	var fetches int32
	fetch := func(ctx context.Context) (*core.Credentials, error) {
		atomic.AddInt32(&fetches, 1)
		return &core.Credentials{AccessToken: "tok", Expiry: base.Add(time.Hour)}, nil
	}
	c := New(fetch, WithClock(clk), WithBuffer(5*time.Minute), WithJitter(0))

	for i := 0; i < 3; i++ {
		got, err := c.Get(context.Background())
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.AccessToken != "tok" {
			t.Errorf("token = %q", got.AccessToken)
		}
	}
	if n := atomic.LoadInt32(&fetches); n != 1 {
		t.Errorf("fetched %d times, want 1 (cached within TTL)", n)
	}
}

func TestGetRefreshesWithinBuffer(t *testing.T) {
	base := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	clk := core.NewFakeClock(base)
	var fetches int32
	fetch := func(ctx context.Context) (*core.Credentials, error) {
		atomic.AddInt32(&fetches, 1)
		return &core.Credentials{
			AccessToken: "tok",
			Expiry:      clk.Now().Add(time.Hour),
		}, nil
	}
	c := New(fetch, WithClock(clk), WithBuffer(5*time.Minute), WithJitter(0))

	if _, err := c.Get(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Advance to within the 5m refresh buffer of the 1h expiry.
	clk.Advance(56 * time.Minute)
	if _, err := c.Get(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !eventually(func() bool { return atomic.LoadInt32(&fetches) == 2 }) {
		t.Errorf("fetched %d times, want 2 (background refresh inside buffer)", atomic.LoadInt32(&fetches))
	}
}

// eventually polls for a condition the background refresh satisfies asynchronously.
func eventually(cond func() bool) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

func TestGetSingleFlightOnColdCache(t *testing.T) {
	base := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	clk := core.NewFakeClock(base)
	var fetches int32
	fetch := func(ctx context.Context) (*core.Credentials, error) {
		atomic.AddInt32(&fetches, 1)
		time.Sleep(20 * time.Millisecond) // widen the race window
		return &core.Credentials{AccessToken: "tok", Expiry: base.Add(time.Hour)}, nil
	}
	c := New(fetch, WithClock(clk), WithBuffer(time.Minute), WithJitter(0))

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Get(context.Background())
		}()
	}
	wg.Wait()
	if n := atomic.LoadInt32(&fetches); n != 1 {
		t.Errorf("fetched %d times under concurrency, want 1 (single-flight)", n)
	}
}
