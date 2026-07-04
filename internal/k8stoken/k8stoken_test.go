package k8stoken

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMintPostsTokenRequest(t *testing.T) {
	var gotAuth, gotBody, gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotMethod = r.Method
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":{"token":"minted-jwt","expirationTimestamp":"2026-07-05T00:00:00Z"}}`))
	}))
	defer srv.Close()

	c := New(
		WithBaseURL(srv.URL),
		WithHTTPClient(srv.Client()),
		WithBearerToken("pod-sa-token"),
		WithServiceAccount("ns1", "sa1"),
	)
	tok, err := c.Mint(context.Background(), "https://target.example/aud")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok != "minted-jwt" {
		t.Errorf("token = %q, want minted-jwt", tok)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/v1/namespaces/ns1/serviceaccounts/sa1/token" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth != "Bearer pod-sa-token" {
		t.Errorf("auth = %q, want Bearer pod-sa-token", gotAuth)
	}
	// Body must carry the requested audience and the TokenRequest kind.
	if !strings.Contains(gotBody, "https://target.example/aud") {
		t.Errorf("body missing requested audience: %s", gotBody)
	}
	var tr struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Spec       struct {
			Audiences         []string `json:"audiences"`
			ExpirationSeconds int      `json:"expirationSeconds"`
		} `json:"spec"`
	}
	if err := json.Unmarshal([]byte(gotBody), &tr); err != nil {
		t.Fatalf("body not valid TokenRequest JSON: %v", err)
	}
	if tr.APIVersion != "authentication.k8s.io/v1" || tr.Kind != "TokenRequest" {
		t.Errorf("bad envelope: %+v", tr)
	}
	if len(tr.Spec.Audiences) != 1 || tr.Spec.Audiences[0] != "https://target.example/aud" {
		t.Errorf("audiences = %v", tr.Spec.Audiences)
	}
	if tr.Spec.ExpirationSeconds != 3600 {
		t.Errorf("expirationSeconds = %d, want 3600", tr.Spec.ExpirationSeconds)
	}
}

func TestMintErrorsOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("forbidden"))
	}))
	defer srv.Close()

	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()),
		WithBearerToken("t"), WithServiceAccount("ns", "sa"))
	_, err := c.Mint(context.Background(), "aud")
	if err == nil {
		t.Fatal("expected error on 403, got nil")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error should mention status: %v", err)
	}
}

func TestMintRequiresConfig(t *testing.T) {
	c := New() // no base url / sa
	if _, err := c.Mint(context.Background(), "aud"); err == nil {
		t.Fatal("expected error when unconfigured (not in-cluster)")
	}
}
