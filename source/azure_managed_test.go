package source

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
)

func TestAzureDetectContainerApps(t *testing.T) {
	a := NewAzure(WithAzureEnv(envFunc(map[string]string{
		"CONTAINER_APP_NAME": "my-app",
		"IDENTITY_ENDPOINT":  "http://localhost/token",
		"IDENTITY_HEADER":    "secret",
	})))
	rt, err := a.Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if rt.Cloud != cloudauth.Azure || rt.SubRuntime != "container-apps" {
		t.Errorf("runtime = %+v, want azure/container-apps", rt)
	}
	if !rt.Federatable {
		t.Error("container apps must be federatable")
	}
}

func TestAzureDetectAppService(t *testing.T) {
	a := NewAzure(WithAzureEnv(envFunc(map[string]string{
		"WEBSITE_SITE_NAME": "my-site",
		"IDENTITY_ENDPOINT": "http://localhost/token",
		"IDENTITY_HEADER":   "secret",
	})))
	rt, err := a.Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if rt.SubRuntime != "app-service" {
		t.Errorf("subruntime = %q, want app-service", rt.SubRuntime)
	}
}

func TestAzureMintFromIdentityEndpoint(t *testing.T) {
	var gotHeader, gotResource, gotAPIVersion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-IDENTITY-HEADER")
		gotResource = r.URL.Query().Get("resource")
		gotAPIVersion = r.URL.Query().Get("api-version")
		w.Write([]byte(`{"access_token":"` + azureJWT(gotResource) + `","expires_on":"9999999999"}`))
	}))
	defer srv.Close()

	a := NewAzure(WithAzureHTTPClient(srv.Client()), WithAzureEnv(envFunc(map[string]string{
		"CONTAINER_APP_NAME": "my-app",
		"IDENTITY_ENDPOINT":  srv.URL,
		"IDENTITY_HEADER":    "the-secret",
	})))

	tok, err := a.Mint(context.Background(), "api://target")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.Kind != cloudauth.OIDC || tok.Value == "" {
		t.Errorf("token = %+v", tok)
	}
	if tok.Audience != "api://target" {
		t.Errorf("audience = %q", tok.Audience)
	}
	if gotHeader != "the-secret" {
		t.Errorf("X-IDENTITY-HEADER = %q, want the-secret", gotHeader)
	}
	if gotResource != "api://target" {
		t.Errorf("resource = %q, want api://target", gotResource)
	}
	if gotAPIVersion != "2019-08-01" {
		t.Errorf("api-version = %q, want 2019-08-01", gotAPIVersion)
	}
}

// AKS Workload Identity (env AZURE_FEDERATED_TOKEN_FILE) must still take
// precedence over the managed-identity endpoint hints.
func TestAzureWorkloadIdentityPreferredOverManaged(t *testing.T) {
	a := NewAzure(WithAzureEnv(envFunc(map[string]string{
		"AZURE_FEDERATED_TOKEN_FILE": "/var/run/secrets/token",
		"CONTAINER_APP_NAME":         "my-app",
		"IDENTITY_ENDPOINT":          "http://localhost/token",
		"IDENTITY_HEADER":            "secret",
	})))
	rt, err := a.Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if rt.SubRuntime != "aks-workload-identity" {
		t.Errorf("subruntime = %q, want aks-workload-identity", rt.SubRuntime)
	}
}
