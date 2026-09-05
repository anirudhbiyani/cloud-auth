package source

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/internal/k8stoken"
)

func decodeJSON(r *http.Request, v any) error {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// fakeTokenRequestServer returns an httptest server that mints a JWT (via gcpJWT) whose aud is the requested audience.
func fakeTokenRequestServer(t *testing.T, wantPath string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wantPath != "" && r.URL.Path != wantPath {
			t.Errorf("path = %q, want %q", r.URL.Path, wantPath)
		}
		var body struct {
			Spec struct {
				Audiences []string `json:"audiences"`
			} `json:"spec"`
		}
		if err := decodeJSON(r, &body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		aud := ""
		if len(body.Spec.Audiences) > 0 {
			aud = body.Spec.Audiences[0]
		}
		w.Write([]byte(`{"status":{"token":"` + gcpJWT(aud) + `","expirationTimestamp":"2026-07-05T00:00:00Z"}}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAWSMintIRSAFallsBackToTokenRequest(t *testing.T) {
	// The projected token's aud is "sts.amazonaws.com" but the caller wants a GCP target audience.
	dir := t.TempDir()
	tokFile := filepath.Join(dir, "token")
	os.WriteFile(tokFile, []byte(gcpJWT("sts.amazonaws.com")), 0600)

	srv := fakeTokenRequestServer(t, "/api/v1/namespaces/ns/serviceaccounts/sa/token")
	client := k8stoken.New(
		k8stoken.WithBaseURL(srv.URL),
		k8stoken.WithHTTPClient(srv.Client()),
		k8stoken.WithBearerToken("pod-token"),
		k8stoken.WithServiceAccount("ns", "sa"),
	)

	want := "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/aws"
	a := NewAWS(
		WithAWSEnv(envFunc(map[string]string{
			"AWS_WEB_IDENTITY_TOKEN_FILE": tokFile,
			"AWS_ROLE_ARN":                "arn:aws:iam::123:role/pod",
		})),
		WithAWSK8sTokenClient(client),
	)
	tok, err := a.Mint(context.Background(), want)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.Kind != core.OIDC {
		t.Errorf("kind = %v, want OIDC", tok.Kind)
	}
	if tok.Audience != want {
		t.Errorf("audience = %q, want %q", tok.Audience, want)
	}
}

func TestAWSMintIRSAPrefersFileTokenWhenAudienceMatches(t *testing.T) {
	// When the file token already matches, we should NOT call TokenRequest.
	dir := t.TempDir()
	tokFile := filepath.Join(dir, "token")
	os.WriteFile(tokFile, []byte(gcpJWT("sts.amazonaws.com")), 0600)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("TokenRequest should not be called when file token audience matches")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	client := k8stoken.New(k8stoken.WithBaseURL(srv.URL), k8stoken.WithHTTPClient(srv.Client()),
		k8stoken.WithBearerToken("t"), k8stoken.WithServiceAccount("ns", "sa"))

	a := NewAWS(
		WithAWSEnv(envFunc(map[string]string{
			"AWS_WEB_IDENTITY_TOKEN_FILE": tokFile,
			"AWS_ROLE_ARN":                "arn:aws:iam::123:role/pod",
		})),
		WithAWSK8sTokenClient(client),
	)
	tok, err := a.Mint(context.Background(), "sts.amazonaws.com")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.Value != gcpJWT("sts.amazonaws.com") {
		t.Errorf("expected the on-disk file token verbatim")
	}
}

func TestAzureMintAKSFallsBackToTokenRequest(t *testing.T) {
	dir := t.TempDir()
	tokFile := filepath.Join(dir, "token")
	os.WriteFile(tokFile, []byte(azureJWT("api://AzureADTokenExchange")), 0600)

	srv := fakeTokenRequestServer(t, "/api/v1/namespaces/ns/serviceaccounts/sa/token")
	client := k8stoken.New(
		k8stoken.WithBaseURL(srv.URL),
		k8stoken.WithHTTPClient(srv.Client()),
		k8stoken.WithBearerToken("pod-token"),
		k8stoken.WithServiceAccount("ns", "sa"),
	)

	a := NewAzure(
		WithAzureEnv(envFunc(map[string]string{
			"AZURE_FEDERATED_TOKEN_FILE": tokFile,
			"KUBERNETES_SERVICE_HOST":    "10.0.0.1",
		})),
		WithAzureK8sTokenClient(client),
	)
	tok, err := a.Mint(context.Background(), "sts.amazonaws.com")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.Audience != "sts.amazonaws.com" {
		t.Errorf("audience = %q, want sts.amazonaws.com", tok.Audience)
	}
}

func TestAWSMintIRSAStillFailsClosedWithoutTokenRequest(t *testing.T) {
	// No k8s client injected and not in-cluster => keep the fail-closed error.
	dir := t.TempDir()
	tokFile := filepath.Join(dir, "token")
	os.WriteFile(tokFile, []byte(gcpJWT("sts.amazonaws.com")), 0600)

	a := NewAWS(WithAWSEnv(envFunc(map[string]string{
		"AWS_WEB_IDENTITY_TOKEN_FILE": tokFile,
		"AWS_ROLE_ARN":                "arn:aws:iam::123:role/pod",
	})))
	_, err := a.Mint(context.Background(), "some-other-audience")
	if err == nil {
		t.Fatal("expected fail-closed error when TokenRequest is unavailable")
	}
}
