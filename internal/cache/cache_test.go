package cache

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
)

func TestGetFetchesThenCaches(t *testing.T) {
	base := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	clk := cloudauth.NewFakeClock(base)
	var fetches int32
	fetch := func(ctx context.Context) (*cloudauth.Credentials, error) {
		atomic.AddInt32(&fetches, 1)
		return &cloudauth.Credentials{AccessToken: "tok", Expiry: base.Add(time.Hour)}, nil
	}
	c := New(fetch, WithClock(clk), WithBuffer(5*time.Minute))

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
	clk := cloudauth.NewFakeClock(base)
	var fetches int32
	fetch := func(ctx context.Context) (*cloudauth.Credentials, error) {
		atomic.AddInt32(&fetches, 1)
		return &cloudauth.Credentials{
			AccessToken: "tok",
			Expiry:      clk.Now().Add(time.Hour),
		}, nil
	}
	c := New(fetch, WithClock(clk), WithBuffer(5*time.Minute))

	if _, err := c.Get(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Advance to within the 5m refresh buffer of the 1h expiry.
	clk.Advance(56 * time.Minute)
	if _, err := c.Get(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(&fetches); n != 2 {
		t.Errorf("fetched %d times, want 2 (proactive refresh inside buffer)", n)
	}
}

func TestGetSingleFlightOnColdCache(t *testing.T) {
	base := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	clk := cloudauth.NewFakeClock(base)
	var fetches int32
	fetch := func(ctx context.Context) (*cloudauth.Credentials, error) {
		atomic.AddInt32(&fetches, 1)
		time.Sleep(20 * time.Millisecond) // widen the race window
		return &cloudauth.Credentials{AccessToken: "tok", Expiry: base.Add(time.Hour)}, nil
	}
	c := New(fetch, WithClock(clk), WithBuffer(time.Minute))

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
