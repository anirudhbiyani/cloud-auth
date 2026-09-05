package cache

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
)

func validCreds(clk core.Clock) *core.Credentials {
	return &core.Credentials{Cloud: core.AWS, AccessKeyID: "ASIA", Expiry: clk.Now().Add(time.Hour)}
}

// 100 callers on warm credentials must not trigger any refresh at all.
func TestHundredCallersBeforeExpiry(t *testing.T) {
	clk := core.NewFakeClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	var fetches int64
	c := New(func(context.Context) (*core.Credentials, error) {
		atomic.AddInt64(&fetches, 1)
		return validCreds(clk), nil
	}, WithClock(clk), WithBuffer(time.Minute), WithJitter(0))

	if _, err := c.Get(context.Background()); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Get(context.Background()); err != nil {
				t.Errorf("Get: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt64(&fetches); got != 1 {
		t.Errorf("fetches = %d, want 1: warm credentials must be served without refreshing", got)
	}
}

// 100 callers arriving on a cold cache must collapse into one exchange, and all must receive the same credentials.
func TestHundredCallersDuringRefresh(t *testing.T) {
	clk := core.NewFakeClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	var fetches int64
	release := make(chan struct{})
	c := New(func(context.Context) (*core.Credentials, error) {
		atomic.AddInt64(&fetches, 1)
		<-release // hold every caller in the window
		return validCreds(clk), nil
	}, WithClock(clk), WithBuffer(time.Minute), WithJitter(0))

	var wg sync.WaitGroup
	got := make([]string, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			creds, err := c.Get(context.Background())
			if err != nil {
				t.Errorf("Get: %v", err)
				return
			}
			got[i] = creds.Reveal().AccessKeyID
		}(i)
	}
	time.Sleep(50 * time.Millisecond) // let them all queue
	close(release)
	wg.Wait()

	if n := atomic.LoadInt64(&fetches); n != 1 {
		t.Errorf("fetches = %d, want 1: concurrent callers must share one exchange", n)
	}
	for i, v := range got {
		if v != "ASIA" {
			t.Errorf("caller %d got %q, want the shared result", i, v)
		}
	}
}

// The audit measured 200 STS calls for 200 callers during an outage.
func TestRefreshFailureWithConcurrentWaiters(t *testing.T) {
	clk := core.NewFakeClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	var fetches int64
	boom := errors.New("STS 503")
	c := New(func(context.Context) (*core.Credentials, error) {
		atomic.AddInt64(&fetches, 1)
		time.Sleep(5 * time.Millisecond)
		return nil, boom
	}, WithClock(clk), WithBuffer(time.Minute), WithJitter(0), WithErrorTTL(time.Minute))

	var wg sync.WaitGroup
	var errCount int64
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Get(context.Background()); errors.Is(err, boom) {
				atomic.AddInt64(&errCount, 1)
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt64(&errCount); got != 200 {
		t.Errorf("%d of 200 callers saw the error; every caller must be told", got)
	}
	if got := atomic.LoadInt64(&fetches); got > 2 {
		t.Errorf("fetches = %d for 200 callers during an outage: that is a retry storm", got)
	}
}

// Recovery must not be blocked by the negative cache once its window passes.
func TestRecoveryAfterFailure(t *testing.T) {
	clk := core.NewFakeClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	var fail atomic.Bool
	fail.Store(true)
	c := New(func(context.Context) (*core.Credentials, error) {
		if fail.Load() {
			return nil, errors.New("down")
		}
		return validCreds(clk), nil
	}, WithClock(clk), WithBuffer(time.Minute), WithJitter(0), WithErrorTTL(10*time.Millisecond))

	if _, err := c.Get(context.Background()); err == nil {
		t.Fatal("want the initial failure")
	}
	fail.Store(false)
	clk.Advance(time.Second) // past the error window

	if _, err := c.Get(context.Background()); err != nil {
		t.Fatalf("must recover once the upstream does: %v", err)
	}
}

// A caller's deadline is its own.
func TestCallerCancellationDoesNotAbortTheRefresh(t *testing.T) {
	clk := core.NewFakeClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	release := make(chan struct{})
	var fetches int64
	c := New(func(context.Context) (*core.Credentials, error) {
		atomic.AddInt64(&fetches, 1)
		<-release
		return validCreds(clk), nil
	}, WithClock(clk), WithBuffer(time.Minute), WithJitter(0))

	// A patient caller starts the refresh.
	patient := make(chan error, 1)
	go func() {
		_, err := c.Get(context.Background())
		patient <- err
	}()
	time.Sleep(20 * time.Millisecond)

	// An impatient caller must return on its own deadline, not the refresh's.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.Get(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("want DeadlineExceeded, got %v", err)
	}
	if waited := time.Since(start); waited > 500*time.Millisecond {
		t.Errorf("impatient caller waited %v; its context was ignored", waited)
	}

	// The cancellation must not have aborted the shared refresh.
	close(release)
	if err := <-patient; err != nil {
		t.Errorf("the patient caller's refresh was collateral damage: %v", err)
	}
	if n := atomic.LoadInt64(&fetches); n != 1 {
		t.Errorf("fetches = %d, want 1", n)
	}
}

func TestInvalidateForcesARefresh(t *testing.T) {
	clk := core.NewFakeClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	var fetches int64
	c := New(func(context.Context) (*core.Credentials, error) {
		atomic.AddInt64(&fetches, 1)
		return validCreds(clk), nil
	}, WithClock(clk), WithBuffer(time.Minute), WithJitter(0))

	if _, err := c.Get(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt64(&fetches); n != 1 {
		t.Fatalf("fetches = %d, want 1 before invalidation", n)
	}

	// A caller that saw a 403 knows something the expiry cannot express.
	c.Invalidate()
	if _, err := c.Get(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt64(&fetches); n != 2 {
		t.Errorf("fetches = %d, want 2 after Invalidate", n)
	}
}

// Jitter must stay inside its bound, or a fleet either synchronizes or refreshes far too early.
func TestJitterStaysWithinBounds(t *testing.T) {
	c := New(func(context.Context) (*core.Credentials, error) { return nil, nil },
		WithJitter(30*time.Second))
	for i := 0; i < 1000; i++ {
		if d := c.drawJitter(); d < 0 || d >= 30*time.Second {
			t.Fatalf("drawJitter() = %v, outside [0, 30s)", d)
		}
	}
	zero := New(func(context.Context) (*core.Credentials, error) { return nil, nil }, WithJitter(0))
	if d := zero.drawJitter(); d != 0 {
		t.Errorf("WithJitter(0) must be deterministic, got %v", d)
	}
}
