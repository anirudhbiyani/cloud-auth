package sip

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
)

func azureJWT(aud string) string {
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	return enc(map[string]any{"alg": "RS256"}) + "." +
		enc(map[string]any{"iss": "https://oidc.aks/cluster", "sub": "system:serviceaccount:ns:sa", "aud": aud, "exp": 9999999999}) +
		".sig"
}

func envFunc(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestAzureDetectAKSWorkloadIdentity(t *testing.T) {
	dir := t.TempDir()
	tokFile := filepath.Join(dir, "token")
	os.WriteFile(tokFile, []byte(azureJWT("api://AzureADTokenExchange")), 0600)

	a := NewAzure(WithAzureEnv(envFunc(map[string]string{
		"AZURE_FEDERATED_TOKEN_FILE": tokFile,
		"AZURE_CLIENT_ID":            "client-abc",
		"KUBERNETES_SERVICE_HOST":    "10.0.0.1",
	})))

	rt, err := a.Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if rt.Cloud != cloudauth.Azure || rt.SubRuntime != "aks-workload-identity" {
		t.Errorf("runtime = %+v, want azure/aks-workload-identity", rt)
	}
	if !rt.Federatable {
		t.Error("AKS workload identity must be federatable")
	}
}

func TestAzureMintAKSReadsProjectedToken(t *testing.T) {
	dir := t.TempDir()
	tokFile := filepath.Join(dir, "token")
	os.WriteFile(tokFile, []byte(azureJWT("api://AzureADTokenExchange")), 0600)

	a := NewAzure(WithAzureEnv(envFunc(map[string]string{
		"AZURE_FEDERATED_TOKEN_FILE": tokFile,
		"KUBERNETES_SERVICE_HOST":    "10.0.0.1",
	})))

	tok, err := a.Mint(context.Background(), "api://AzureADTokenExchange")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.Kind != cloudauth.OIDC {
		t.Errorf("kind = %v, want OIDC", tok.Kind)
	}
	if tok.Issuer != "https://oidc.aks/cluster" {
		t.Errorf("issuer = %q", tok.Issuer)
	}
}

func TestAzureDetectVMViaIMDS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata") != "true" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/metadata/instance":
			w.Write([]byte(`{"compute":{"vmId":"abc"}}`))
		case "/metadata/identity/oauth2/token":
			w.Write([]byte(`{"access_token":"` + azureJWT(r.URL.Query().Get("resource")) + `","expires_on":"9999999999"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	a := NewAzure(WithAzureIMDSURL(srv.URL), WithAzureHTTPClient(srv.Client()),
		WithAzureEnv(envFunc(nil)))

	rt, err := a.Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if rt.SubRuntime != "vm" {
		t.Errorf("subruntime = %q, want vm", rt.SubRuntime)
	}
	tok, err := a.Mint(context.Background(), "https://management.azure.com/")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.Value == "" {
		t.Error("VM mint should return the IMDS access token")
	}
}
