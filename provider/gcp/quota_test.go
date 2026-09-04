package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// GCP's rate quotas. Unlike the size limits, a rate cannot be checked before a
// single call — one request is never over a per-minute quota — so the two
// things worth doing are pacing a burst so it does not provoke one, and naming
// the quota when the API says no.

type staticToken struct{}

func (staticToken) Token() (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: "t", Expiry: time.Now().Add(time.Hour)}, nil
}

// GCP answers every exhausted quota with RESOURCE_EXHAUSTED, so the raw error
// sends an operator to check storage or CPU. Which quota applies is decided by
// the endpoint, which this layer knows and the caller does not.
func TestQuotaErrorsNameTheQuota(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		code    string
		wantHas string
	}{
		{"429 on a workload identity write", http.StatusTooManyRequests, "RESOURCE_EXHAUSTED",
			"workload identity writes are capped at 60"},
		{"RESOURCE_EXHAUSTED without a 429", http.StatusForbidden, "RESOURCE_EXHAUSTED",
			"workload identity writes are capped at 60"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
					"code": tc.status, "message": "Quota exceeded.", "status": tc.code,
				}})
			}))
			defer srv.Close()

			clients, err := NewClients(context.Background(),
				WithTokenSource(staticToken{}),
				WithEndpoints(srv.URL, srv.URL, srv.URL))
			if err != nil {
				t.Fatalf("NewClients: %v", err)
			}
			c := clients.Workload.(*restClient)
			c.sleep = func(context.Context, time.Duration) error { return nil }

			_, err = c.GetWorkloadIdentityPool(context.Background(),
				"projects/1/locations/global/workloadIdentityPools/p")
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), tc.wantHas) {
				t.Errorf("error does not name the quota: %v", err)
			}

			var apiErr *apiError
			if !errors.As(err, &apiErr) || !apiErr.RateLimited() {
				t.Errorf("RateLimited() is false for %s", tc.code)
			}
		})
	}
}

// A non-quota error must not be annotated: telling someone about a rate limit
// when they have a permissions problem is worse than saying nothing.
func TestNonQuotaErrorsAreNotAnnotated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
			"code": 403, "message": "Permission denied.", "status": "PERMISSION_DENIED",
		}})
	}))
	defer srv.Close()

	clients, _ := NewClients(context.Background(),
		WithTokenSource(staticToken{}), WithEndpoints(srv.URL, srv.URL, srv.URL))
	_, err := clients.Workload.GetWorkloadIdentityPool(context.Background(),
		"projects/1/locations/global/workloadIdentityPools/p")
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), "capped at") {
		t.Errorf("a permissions failure was annotated as a quota problem: %v", err)
	}
}

// Writes are serialized and paced. A setup creating a pool and a provider is two
// writes; a loop over repositories is many, and hitting the quota mid-loop
// leaves a half-built pool behind.
func TestWorkloadIdentityWritesArePaced(t *testing.T) {
	var inFlight, maxInFlight atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "p"})
			return
		}
		n := inFlight.Add(1)
		for {
			old := maxInFlight.Load()
			if n <= old || maxInFlight.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(3 * time.Millisecond)
		inFlight.Add(-1)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "op", "done": true,
			"response": map[string]any{"name": "projects/1/locations/global/workloadIdentityPools/p"},
		})
	}))
	defer srv.Close()

	clients, _ := NewClients(context.Background(),
		WithTokenSource(staticToken{}), WithEndpoints(srv.URL, srv.URL, srv.URL))
	c := clients.Workload.(*restClient)

	var waited []time.Duration
	var mu sync.Mutex
	c.sleep = func(_ context.Context, d time.Duration) error {
		mu.Lock()
		waited = append(waited, d)
		mu.Unlock()
		return nil
	}

	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := c.CreateWorkloadIdentityPool(context.Background(),
				"projects/1/locations/global", "pool", &WorkloadIdentityPool{DisplayName: "p"})
			if err != nil {
				t.Errorf("CreateWorkloadIdentityPool: %v", err)
			}
		}(i)
	}
	wg.Wait()

	if got := maxInFlight.Load(); got > 1 {
		t.Errorf("%d writes were in flight at once; they must be serialized against the "+
			"60-per-minute project quota", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(waited) == 0 {
		t.Error("no pacing delay was applied between writes")
	}
	for _, d := range waited {
		if d > time.Minute/wifWritesPerMinute {
			t.Errorf("waited %s, longer than the %s interval", d, time.Minute/wifWritesPerMinute)
		}
	}
}

// The STS exchange quota is a different number, and the message must say which
// one applies.
func TestSTSQuotaIsNamedSeparately(t *testing.T) {
	err := annotateQuota(&apiError{
		StatusCode: http.StatusTooManyRequests, Status: "RESOURCE_EXHAUSTED",
		Message: "Quota exceeded.",
	}, "https://sts.googleapis.com/v1/token")

	if !strings.Contains(err.Error(), "STS token exchanges are capped at 6000") {
		t.Errorf("the STS quota was not named: %v", err)
	}
	if strings.Contains(err.Error(), "workload identity writes") {
		t.Errorf("the wrong quota was named: %v", err)
	}
}
