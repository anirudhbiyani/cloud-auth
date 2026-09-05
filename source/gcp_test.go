package source

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

func gcpJWT(aud string) string {
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	return enc(map[string]any{"alg": "RS256"}) + "." +
		enc(map[string]any{"iss": "https://accounts.google.com", "sub": "sa-unique-id", "aud": aud, "exp": 9999999999}) +
		".sig"
}

func fakeGCPMetadata(t *testing.T, requireFlavor bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requireFlavor && r.Header.Get("Metadata-Flavor") != "Google" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		// The real metadata server echoes this back, and the client now requires it — that round trip is what distinguishes the metadata server from anything else answering on metadata.google.internal.
		w.Header().Set("Metadata-Flavor", "Google")
		switch r.URL.Path {
		case "/computeMetadata/v1/":
			w.Write([]byte("ok"))
		case "/computeMetadata/v1/instance/service-accounts/default/email":
			w.Write([]byte("sa@proj.iam.gserviceaccount.com"))
		case "/computeMetadata/v1/instance/service-accounts/default/identity":
			w.Write([]byte(gcpJWT(r.URL.Query().Get("audience"))))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestGCPDetect(t *testing.T) {
	srv := fakeGCPMetadata(t, true)
	g := NewGCP(WithGCPMetadataURL(srv.URL), WithGCPHTTPClient(srv.Client()),
		WithGCPEnv(func(string) string { return "" }))

	rt, err := g.Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if rt.Cloud != core.GCP || rt.SubRuntime != "gce" {
		t.Errorf("runtime = %+v, want gcp/gce", rt)
	}
	if !rt.Federatable {
		t.Error("GCP runtime must be federatable")
	}
	if rt.Subject != "sa@proj.iam.gserviceaccount.com" {
		t.Errorf("subject = %q", rt.Subject)
	}
}

func TestGCPDetectGKE(t *testing.T) {
	srv := fakeGCPMetadata(t, true)
	g := NewGCP(WithGCPMetadataURL(srv.URL), WithGCPHTTPClient(srv.Client()),
		WithGCPEnv(func(k string) string {
			if k == "KUBERNETES_SERVICE_HOST" {
				return "10.0.0.1"
			}
			return ""
		}))
	rt, err := g.Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if rt.SubRuntime != "gke" {
		t.Errorf("subruntime = %q, want gke", rt.SubRuntime)
	}
}

func TestGCPDetectNotHere(t *testing.T) {
	// A server that 404s the metadata root simulates "not on GCP".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	g := NewGCP(WithGCPMetadataURL(srv.URL), WithGCPHTTPClient(srv.Client()),
		WithGCPEnv(func(string) string { return "" }))
	_, err := g.Detect(context.Background())
	if !errors.Is(err, core.ErrNotThisRuntime) {
		t.Errorf("err = %v, want ErrNotThisRuntime", err)
	}
}

func TestGCPMintPinsAudience(t *testing.T) {
	srv := fakeGCPMetadata(t, true)
	g := NewGCP(WithGCPMetadataURL(srv.URL), WithGCPHTTPClient(srv.Client()),
		WithGCPEnv(func(string) string { return "" }))

	tok, err := g.Mint(context.Background(), "sts.amazonaws.com")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.Kind != core.OIDC {
		t.Errorf("kind = %v, want OIDC", tok.Kind)
	}
	if tok.Audience != "sts.amazonaws.com" {
		t.Errorf("audience = %q, want the pinned audience", tok.Audience)
	}
	if tok.Issuer != "https://accounts.google.com" || tok.Subject != "sa-unique-id" {
		t.Errorf("claims not parsed: iss=%q sub=%q", tok.Issuer, tok.Subject)
	}
	if tok.Value == "" {
		t.Error("token value (the JWT) must be set")
	}
}
