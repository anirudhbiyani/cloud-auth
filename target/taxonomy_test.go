package target

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// A caller of Exchange must be able to tell "the network is down" from "the trust is misconfigured" from "we are being throttled" — without matching on message text.
func TestExchangeErrorsCarryACategory(t *testing.T) {
	tests := []struct {
		name         string
		status       int
		body         string
		wantCat      core.ErrorCategory
		wantRetry    bool
		wantSentinel error
	}{
		{"throttled", http.StatusTooManyRequests, "slow down", core.ErrCategoryRateLimit, true, nil},
		{"server error", http.StatusBadGateway, "oops", core.ErrCategoryNetwork, true, nil},
		{
			"trust rejected", http.StatusForbidden, accessDeniedXML,
			core.ErrCategoryAuth, false, core.ErrTrustMissing,
		},
		{"bad request", http.StatusBadRequest, "<Error><Code>ValidationError</Code></Error>",
			core.ErrCategoryValidation, false, nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			_, err := NewAWSExchanger(WithAWSEndpoint(srv.URL), WithAWSMaxRetries(0)).
				Exchange(context.Background(), oidcToken(), awsTarget())
			if err == nil {
				t.Fatal("want an error")
			}
			if got := core.CategoryOf(err); got != tc.wantCat {
				t.Errorf("category = %q, want %q (err: %v)", got, tc.wantCat, err)
			}
			if got := core.IsRetryable(err); got != tc.wantRetry {
				t.Errorf("retryable = %v, want %v", got, tc.wantRetry)
			}
			// The sentinels must survive categorisation, or existing callers break.
			if tc.wantSentinel != nil && !errors.Is(err, tc.wantSentinel) {
				t.Errorf("errors.Is(%v) lost the sentinel", tc.wantSentinel)
			}
		})
	}
}

func TestTransportFailuresAreCategorized(t *testing.T) {
	// Nothing listening: a dial failure, which is retryable network trouble.
	_, err := NewAWSExchanger(WithAWSEndpoint("http://127.0.0.1:1"), WithAWSMaxRetries(0)).
		Exchange(context.Background(), oidcToken(), awsTarget())
	if err == nil {
		t.Fatal("want an error")
	}
	if got := core.CategoryOf(err); got != core.ErrCategoryNetwork {
		t.Errorf("category = %q, want network", got)
	}
	if !core.IsRetryable(err) {
		t.Error("a dial failure should be retryable")
	}

	// A cancelled caller is a timeout, and must NOT be retried: the caller has already given up.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err = NewAWSExchanger(WithAWSEndpoint(srv.URL), WithAWSMaxRetries(0)).
		Exchange(ctx, oidcToken(), awsTarget())
	if err == nil {
		t.Fatal("want an error")
	}
	if got := core.CategoryOf(err); got != core.ErrCategoryTimeout {
		t.Errorf("category = %q, want timeout (err: %v)", got, err)
	}
	if core.IsRetryable(err) {
		t.Error("a cancelled caller must not be retried")
	}
}

// Data-plane sentinels that never reach an HTTP call must still categorize.
func TestSentinelsCategorizeWithoutAnHTTPResponse(t *testing.T) {
	cases := map[error]core.ErrorCategory{
		core.ErrTrustMissing:         core.ErrCategoryAuth,
		core.ErrNotThisRuntime:       core.ErrCategoryValidation,
		core.ErrNonFederatableSource: core.ErrCategoryValidation,
		core.ErrNoFirstClassPath:     core.ErrCategoryValidation,
		core.ErrRuntimeMismatch:      core.ErrCategoryValidation,
	}
	for err, want := range cases {
		if got := core.CategoryOf(err); got != want {
			t.Errorf("CategoryOf(%v) = %q, want %q", err, got, want)
		}
	}
	if got := core.CategoryOf(nil); got != "" {
		t.Errorf("CategoryOf(nil) = %q, want empty", got)
	}
}
