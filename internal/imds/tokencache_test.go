package imds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A session token per read meant two round trips per metadata field, and Detect alone made four — against a service that rate-limits.
func TestSessionTokenIsReused(t *testing.T) {
	var tokens, gets int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == tokenPath {
			atomic.AddInt64(&tokens, 1)
			_, _ = w.Write([]byte("session-token"))
			return
		}
		atomic.AddInt64(&gets, 1)
		if r.Header.Get(tokenHeader) != "session-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("value"))
	}))
	defer srv.Close()

	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	for i := 0; i < 5; i++ {
		if _, err := c.Get(context.Background(), "/latest/meta-data/instance-id"); err != nil {
			t.Fatalf("Get: %v", err)
		}
	}

	if got := atomic.LoadInt64(&gets); got != 5 {
		t.Errorf("metadata reads = %d, want 5", got)
	}
	if got := atomic.LoadInt64(&tokens); got != 1 {
		t.Errorf("session tokens minted = %d, want 1 for 5 reads", got)
	}
}

// Concurrent readers share one token rather than each minting their own.
func TestSessionTokenMintedOnceUnderConcurrency(t *testing.T) {
	var tokens int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			atomic.AddInt64(&tokens, 1)
			time.Sleep(5 * time.Millisecond)
			_, _ = w.Write([]byte("session-token"))
			return
		}
		_, _ = w.Write([]byte("value"))
	}))
	defer srv.Close()

	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.Get(context.Background(), "/latest/meta-data/instance-id")
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt64(&tokens); got != 1 {
		t.Errorf("session tokens minted = %d under 20 concurrent reads, want 1", got)
	}
}

// An expired token must be renewed rather than reused into a 401.
func TestSessionTokenRenewedAfterTTL(t *testing.T) {
	var tokens int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			atomic.AddInt64(&tokens, 1)
			_, _ = w.Write([]byte("session-token"))
			return
		}
		_, _ = w.Write([]byte("value"))
	}))
	defer srv.Close()

	// A TTL below the 5s early-renewal margin forces a mint on every read.
	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithTokenTTL(time.Second))
	for i := 0; i < 3; i++ {
		if _, err := c.Get(context.Background(), "/x"); err != nil {
			t.Fatalf("Get: %v", err)
		}
	}
	if got := atomic.LoadInt64(&tokens); got != 3 {
		t.Errorf("session tokens minted = %d, want 3: a token past its TTL must not be reused", got)
	}
}
