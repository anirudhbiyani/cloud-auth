package aws

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The thumbprint must be computed from the certificate the issuer actually presents.
func TestThumbprintIsComputedFromTheServedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	// httptest serves a self-signed certificate — the same shape as an issuer behind a private CA, which is what WithThumbprintTLSConfig is for.
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	p := New(WithThumbprintTLSConfig(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}))

	got, err := p.oidcThumbprint(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("oidcThumbprint: %v", err)
	}

	// Recompute independently from the server's own certificate.
	chain := srv.TLS.Certificates
	if len(chain) == 0 || len(chain[0].Certificate) == 0 {
		t.Fatal("test server has no certificate")
	}
	sum := sha1.Sum(chain[0].Certificate[len(chain[0].Certificate)-1])
	want := hex.EncodeToString(sum[:])

	if got != want {
		t.Errorf("thumbprint = %s, want %s (the served certificate's SHA-1)", got, want)
	}
	if got == strings.Repeat("0", 40) {
		t.Error("returned the old placeholder")
	}
	if len(got) != 40 {
		t.Errorf("thumbprint should be 40 hex characters, got %d", len(got))
	}
}

// An unreachable or non-TLS issuer is an error, never a placeholder.
func TestThumbprintFailsClosed(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer plain.Close()

	cases := map[string]string{
		"http issuer cannot be pinned": plain.URL,
		"unreachable host":             "https://127.0.0.1:1/",
		"not a url":                    "https://not a host::/",
		"empty":                        "",
	}
	for name, issuer := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := New().oidcThumbprint(context.Background(), issuer)
			if err == nil {
				t.Fatalf("want an error, got thumbprint %q", got)
			}
			if got != "" {
				t.Errorf("must return no thumbprint alongside an error, got %q", got)
			}
		})
	}
}

// The chain is verified by default.
func TestThumbprintVerifiesTheChainByDefault(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	_, err := New().oidcThumbprint(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("an untrusted certificate must not be pinned silently")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Errorf("error should explain the verification failure, got %v", err)
	}
}

func TestThumbprintRespectsContextCancellation(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New().oidcThumbprint(ctx, srv.URL); err == nil {
		t.Fatal("want an error for a cancelled context")
	}
}

// Guard against a future edit weakening the handshake.
func TestThumbprintRequiresModernTLS(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	srv.TLS = &tls.Config{MaxVersion: tls.VersionTLS11}
	srv.StartTLS()
	defer srv.Close()

	if _, err := New().oidcThumbprint(context.Background(), srv.URL); err == nil {
		t.Error("a TLS 1.1-only issuer should be refused")
	}
}
