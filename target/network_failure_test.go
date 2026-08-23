package target

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// The failure modes a token endpoint actually exhibits in production, none of
// which were covered. The invariant throughout: an error, never partial
// credentials, and never a hang.
func TestExchangeHandlesMalformedResponses(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			"empty 200",
			func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) },
		},
		{
			"html error page",
			func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write([]byte("<html><body>502 Bad Gateway</body></html>"))
			},
		},
		{
			"truncated xml",
			func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Cred`))
			},
		},
		{
			"content-length lies",
			func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Length", "4096")
				_, _ = w.Write([]byte("short"))
			},
		},
		{
			"connection reset mid-body",
			func(w http.ResponseWriter, r *http.Request) {
				hj, ok := w.(http.Hijacker)
				if !ok {
					t.Skip("no hijacker")
					return
				}
				conn, _, err := hj.Hijack()
				if err != nil {
					return
				}
				// Write a partial response, then drop the connection.
				_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n<partial>"))
				if tc, ok := conn.(*net.TCPConn); ok {
					_ = tc.SetLinger(0)
				}
				_ = conn.Close()
			},
		},
		{
			"gzip claimed but not sent",
			func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Encoding", "gzip")
				_, _ = w.Write([]byte("definitely not gzip"))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()

			creds, err := NewAWSExchanger(WithAWSEndpoint(srv.URL), WithAWSMaxRetries(0)).
				Exchange(context.Background(), oidcToken(), awsTarget())

			if err == nil {
				t.Fatalf("want an error, got credentials %v", creds)
			}
			if creds != nil {
				t.Errorf("credentials returned alongside an error: %v", creds)
			}
			// The error must be attributable to a category, or a caller cannot
			// decide whether to retry.
			if cat := core.CategoryOf(err); cat == "" {
				t.Errorf("error carries no category: %v", err)
			}
		})
	}
}

// DNS failure is distinct from a refused connection, and both are retryable
// network trouble rather than a trust problem.
func TestExchangeHandlesDNSFailure(t *testing.T) {
	_, err := NewAWSExchanger(
		WithAWSEndpoint("https://this-host-does-not-exist.invalid/"),
		WithAWSMaxRetries(0),
	).Exchange(context.Background(), oidcToken(), awsTarget())

	if err == nil {
		t.Fatal("want an error")
	}
	if got := core.CategoryOf(err); got != core.ErrCategoryNetwork {
		t.Errorf("category = %q, want network for a DNS failure (err: %v)", got, err)
	}
	if !core.IsRetryable(err) {
		t.Error("a DNS failure should be retryable")
	}
}

// A TLS failure must not be reported as a trust misconfiguration: the operator
// would go looking at IAM instead of at their certificate store.
func TestExchangeHandlesTLSFailure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	// The default client does not trust httptest's self-signed certificate.
	_, err := NewAWSExchanger(WithAWSEndpoint(srv.URL), WithAWSMaxRetries(0)).
		Exchange(context.Background(), oidcToken(), awsTarget())

	if err == nil {
		t.Fatal("want an error for an untrusted certificate")
	}
	if got := core.CategoryOf(err); got != core.ErrCategoryNetwork {
		t.Errorf("category = %q, want network (err: %v)", got, err)
	}
	if strings.Contains(strings.ToLower(err.Error()), "trust missing") {
		t.Errorf("a TLS failure must not read as a trust misconfiguration: %v", err)
	}
}

// A body larger than any real STS response must not be buffered without bound.
func TestExchangeHandlesAnEnormousBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		chunk := strings.Repeat("x", 64*1024)
		for i := 0; i < 16; i++ { // ~1 MiB
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	_, err := NewAWSExchanger(WithAWSEndpoint(srv.URL), WithAWSMaxRetries(0)).
		Exchange(context.Background(), oidcToken(), awsTarget())
	if err == nil {
		t.Fatal("want an error")
	}
	// The error is a diagnostic; it must not carry a megabyte of response.
	if n := len(err.Error()); n > 4096 {
		t.Errorf("error is %d bytes; the body should be capped", n)
	}
}

// Every exchanger must behave the same way, or a caller's error handling is
// per-cloud guesswork.
func TestAllExchangersRejectAnEmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	const gcpAud = "//iam.googleapis.com/projects/1/x"
	cases := map[string]func() error{
		"aws": func() error {
			_, err := NewAWSExchanger(WithAWSEndpoint(srv.URL), WithAWSMaxRetries(0)).
				Exchange(context.Background(), oidcToken(), awsTarget())
			return err
		},
		"gcp": func() error {
			_, err := NewGCPExchanger(WithGCPSTSEndpoint(srv.URL)).Exchange(
				context.Background(), oidcTokenFor(gcpAud),
				core.GCPTarget{WorkloadIdentityPool: gcpAud})
			return err
		},
		"azure": func() error {
			_, err := NewAzureExchanger(WithAzureEndpoint(srv.URL)).Exchange(
				context.Background(), oidcTokenFor(core.DefaultAzureAudience),
				core.AzureTarget{
					Tenant:   "11111111-1111-1111-1111-111111111111",
					ClientID: "22222222-2222-2222-2222-222222222222",
					Scope:    "https://storage.azure.com/.default",
				})
			return err
		},
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			err := call()
			if err == nil {
				t.Fatal("an empty 200 must not be treated as success")
			}
			if !strings.Contains(err.Error(), name) {
				t.Errorf("error should name the provider for triage: %v", err)
			}
		})
	}
}
