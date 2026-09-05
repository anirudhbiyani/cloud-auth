package imds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeIMDS emulates IMDSv2: a token must be minted via PUT /latest/api/token (with a TTL header) before any GET, which must carry the token header.
func fakeIMDS(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	const tokenValue = "FAKE-IMDS-TOKEN"
	tokenlessGets := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/latest/api/token":
			if r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Write([]byte(tokenValue))
		case r.Method == http.MethodGet:
			if r.Header.Get("X-aws-ec2-metadata-token") != tokenValue {
				tokenlessGets++
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Write([]byte("i-0123456789abcdef"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &tokenlessGets
}

func TestGetUsesTokenFirst(t *testing.T) {
	srv, tokenlessGets := fakeIMDS(t)
	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))

	body, err := c.Get(context.Background(), "/latest/meta-data/instance-id")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(body) != "i-0123456789abcdef" {
		t.Errorf("body = %q, want instance-id", body)
	}
	if *tokenlessGets != 0 {
		t.Errorf("client made %d tokenless GETs; IMDSv2 requires token-first", *tokenlessGets)
	}
}

func TestNoIMDSv1Fallback(t *testing.T) {
	// Server that refuses to mint tokens (simulates a broken/blocked token endpoint).
	getCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		getCalled = true
		w.Write([]byte("should-never-be-reached"))
	}))
	defer srv.Close()

	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	if _, err := c.Get(context.Background(), "/latest/meta-data/instance-id"); err == nil {
		t.Fatal("expected error when token cannot be minted, got nil")
	}
	if getCalled {
		t.Error("client fell back to a tokenless GET; must fail closed instead")
	}
}

func TestTokenTTLHeaderSent(t *testing.T) {
	var gotTTL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			gotTTL = r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds")
			w.Write([]byte("tok"))
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithTokenTTL(90*time.Second))
	if _, err := c.Get(context.Background(), "/x"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if gotTTL != "90" {
		t.Errorf("TTL header = %q, want 90", gotTTL)
	}
}
