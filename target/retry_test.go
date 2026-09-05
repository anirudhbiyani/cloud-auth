package target

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// 429 used to be a permanent failure, so a brief rate limit surfaced as something that looked like a trust misconfiguration.
func TestExchangeRetries429(t *testing.T) {
	var attempts int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt64(&attempts, 1) < 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("slow down"))
			return
		}
		_, _ = w.Write([]byte(successXML))
	}))
	defer srv.Close()

	creds, err := NewAWSExchanger(WithAWSEndpoint(srv.URL), WithAWSMaxRetries(4)).
		Exchange(context.Background(), oidcToken(), awsTarget())
	if err != nil {
		t.Fatalf("a throttle should be retried, not surfaced: %v", err)
	}
	if creds == nil {
		t.Fatal("no credentials")
	}
	if got := atomic.LoadInt64(&attempts); got != 3 {
		t.Errorf("attempts = %d, want 3", got)
	}
}

// AWS also throttles with a 400 and a code in the body, which no status-code rule can see.
func TestExchangeRetriesThrottlingCodeInA400(t *testing.T) {
	var attempts int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt64(&attempts, 1) < 2 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>Throttling</Code>` +
				`<Message>Rate exceeded</Message></Error></ErrorResponse>`))
			return
		}
		_, _ = w.Write([]byte(successXML))
	}))
	defer srv.Close()

	if _, err := NewAWSExchanger(WithAWSEndpoint(srv.URL), WithAWSMaxRetries(3)).
		Exchange(context.Background(), oidcToken(), awsTarget()); err != nil {
		t.Fatalf("a 400 Throttling should be retried: %v", err)
	}
	if got := atomic.LoadInt64(&attempts); got != 2 {
		t.Errorf("attempts = %d, want 2", got)
	}
}

// A genuine 4xx must still fail immediately.
func TestExchangeDoesNotRetryRealClientErrors(t *testing.T) {
	var attempts int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&attempts, 1)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(accessDeniedXML))
	}))
	defer srv.Close()

	if _, err := NewAWSExchanger(WithAWSEndpoint(srv.URL), WithAWSMaxRetries(4)).
		Exchange(context.Background(), oidcToken(), awsTarget()); err == nil {
		t.Fatal("want an error")
	}
	if got := atomic.LoadInt64(&attempts); got != 1 {
		t.Errorf("attempts = %d, want 1: a rejected trust must fail fast", got)
	}
}

// Retry-After is honoured: guessing is both less polite and less effective.
func TestRetryAfterIsHonoured(t *testing.T) {
	cases := map[string]struct {
		header string
		want   time.Duration
		ok     bool
	}{
		"delay seconds":   {"2", 2 * time.Second, true},
		"zero seconds":    {"0", 0, true},
		"padded":          {"  3 ", 3 * time.Second, true},
		"absent":          {"", 0, false},
		"nonsense":        {"soon", 0, false},
		"negative":        {"-5", 0, false},
		"http date, past": {time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat), 0, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := http.Header{}
			if tc.header != "" {
				h.Set("Retry-After", tc.header)
			}
			got, ok := retryAfter(&httpError{status: 429, header: h})
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && got != tc.want {
				t.Errorf("delay = %v, want %v", got, tc.want)
			}
		})
	}
}

// Full jitter: the wait must vary, and stay inside the window.
func TestBackoffIsJitteredAndCapped(t *testing.T) {
	const base = 100 * time.Millisecond
	seen := map[time.Duration]bool{}
	for i := 0; i < 200; i++ {
		d := backoffFor(base, 3, nil)
		if d < 0 || d > base<<2 {
			t.Fatalf("backoff %v outside [0, %v]", d, base<<2)
		}
		seen[d] = true
	}
	if len(seen) < 10 {
		t.Errorf("only %d distinct delays in 200 draws; jitter is not spreading load", len(seen))
	}

	if d := backoffFor(base, 30, nil); d > maxBackoff {
		t.Errorf("backoff %v exceeds the %v cap at a high attempt count", d, maxBackoff)
	}

	// An explicit Retry-After wins over the computed schedule.
	h := http.Header{}
	h.Set("Retry-After", "1")
	if d := backoffFor(base, 1, &httpError{status: 429, header: h}); d != time.Second {
		t.Errorf("Retry-After should win, got %v", d)
	}
}

func TestRetryableClassification(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   bool
	}{
		{500, "", true},
		{503, "", true},
		{429, "", true},
		{400, "<Code>Throttling</Code>", true},
		{400, "<Code>SlowDown</Code>", true},
		{400, `{"error":"rateLimitExceeded"}`, true},
		{400, "<Code>InvalidIdentityToken</Code>", false},
		{403, "AccessDenied", false},
		{404, "", false},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%d/%s", tc.status, tc.body), func(t *testing.T) {
			he := &httpError{status: tc.status, body: []byte(tc.body)}
			if got := retryable(he); got != tc.want {
				t.Errorf("retryable(%d %q) = %v, want %v", tc.status, tc.body, got, tc.want)
			}
		})
	}
	if !retryable(context.DeadlineExceeded) {
		t.Error("a transport error should be retryable")
	}
	if retryable(nil) {
		t.Error("nil means success and must not be retryable")
	}
}

// A retry must not outlive the caller's context.
func TestRetryRespectsContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := NewAWSExchanger(WithAWSEndpoint(srv.URL), WithAWSMaxRetries(50)).
		Exchange(ctx, oidcToken(), awsTarget())
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "context") && !strings.Contains(err.Error(), "deadline") {
		t.Errorf("error should reflect the cancellation, got %v", err)
	}
}

// A newly created federated identity credential legitimately fails for a few minutes while Entra replicates it.
func TestRetryablePropagationVersusWrongSubject(t *testing.T) {
	entra := func(description string) error {
		return &httpError{
			status: http.StatusUnauthorized,
			body:   []byte(`{"error":"invalid_client","error_description":"` + description + `"}`),
		}
	}

	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "AADSTS70021: the credential has not propagated",
			err:  entra("AADSTS70021: No matching federated identity record found for presented assertion."),
			want: true,
		},
		{
			name: "AADSTS700213: the subject is wrong",
			err:  entra("AADSTS700213: No matching federated identity record found for presented assertion subject."),
			want: false,
		},
		{
			name: "AADSTS700016: no such application",
			err:  entra("AADSTS700016: Application with identifier was not found in the directory."),
			want: false,
		},
		{
			name: "AADSTS700027: the assertion failed signature validation",
			err:  entra("AADSTS700027: Client assertion failed signature validation."),
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := retryable(tc.err); got != tc.want {
				t.Errorf("retryable = %v, want %v — retrying a wrong subject turns a clear "+
					"misconfiguration into a slow one, and not retrying propagation blames the operator "+
					"for Entra's replication delay", got, tc.want)
			}
		})
	}
}
