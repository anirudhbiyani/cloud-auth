package source

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
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
	if rt.Cloud != core.Azure || rt.SubRuntime != "container-apps" {
		t.Errorf("runtime = %+v, want azure/container-apps", rt)
	}
	// Managed identity vends Entra access tokens, not assertions another cloud can verify.
	if rt.Federatable {
		t.Error("container apps managed identity is NOT a federation source")
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

// Mint must refuse: the caller is asking for a cross-cloud proof, and this runtime cannot produce one.
func TestAzureMintRefusesManagedIdentity(t *testing.T) {
	a := NewAzure(WithAzureEnv(envFunc(map[string]string{
		"CONTAINER_APP_NAME": "my-app",
		"IDENTITY_ENDPOINT":  "http://localhost/token",
		"IDENTITY_HEADER":    "secret",
	})))
	_, err := a.Mint(context.Background(), "api://target")
	if !errors.Is(err, core.ErrNonFederatableSource) {
		t.Fatalf("want ErrNonFederatableSource, got %v", err)
	}
	if !strings.Contains(err.Error(), "AKS Workload Identity") {
		t.Errorf("error should name the path that does work, got %v", err)
	}
}

// The token endpoint still works for same-cloud use and for doctor's reporting.
func TestAzureManagedIdentityTokenPassesClientID(t *testing.T) {
	var gotHeader, gotResource, gotAPIVersion, gotClientID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-IDENTITY-HEADER")
		gotResource = r.URL.Query().Get("resource")
		gotAPIVersion = r.URL.Query().Get("api-version")
		gotClientID = r.URL.Query().Get("client_id")
		w.Write([]byte(`{"access_token":"` + azureJWT(gotResource) + `","expires_on":"9999999999"}`))
	}))
	defer srv.Close()

	a := NewAzure(WithAzureHTTPClient(srv.Client()), WithAzureEnv(envFunc(map[string]string{
		"CONTAINER_APP_NAME": "my-app",
		"IDENTITY_ENDPOINT":  srv.URL,
		"IDENTITY_HEADER":    "the-secret",
		"AZURE_CLIENT_ID":    "the-uami-client-id",
	})))

	tok, err := a.mintFromIdentityEndpoint(context.Background(), "api://target")
	if err != nil {
		t.Fatalf("mintFromIdentityEndpoint: %v", err)
	}
	if tok.Kind != core.OIDC || tok.Value == "" {
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
	// Without client_id, a host with several user-assigned identities returns whichever the platform considers default — so Detect would report one identity while Mint authenticated as another.
	if gotClientID != "the-uami-client-id" {
		t.Errorf("client_id = %q, want the identity Detect reported", gotClientID)
	}
}

// The IDENTITY_HEADER secret must never leave the host.
func TestAzureRefusesRemoteIdentityEndpoint(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the secret reached a remote host: %s", r.Header.Get("X-IDENTITY-HEADER"))
	}))
	defer remote.Close()

	a := NewAzure(WithAzureHTTPClient(remote.Client()), WithAzureEnv(envFunc(map[string]string{
		"CONTAINER_APP_NAME": "my-app",
		"IDENTITY_ENDPOINT":  "http://attacker.example.com/token",
		"IDENTITY_HEADER":    "the-secret",
	})))
	if _, err := a.mintFromIdentityEndpoint(context.Background(), "api://target"); err == nil {
		t.Fatal("want a refusal for a non-local IDENTITY_ENDPOINT")
	} else if !strings.Contains(err.Error(), "non-local host") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLocalIdentityEndpoint(t *testing.T) {
	ok := []string{
		"http://localhost:42356/msi/token",
		"http://127.0.0.1:8081/msi/token",
		"http://169.254.169.254/metadata/identity/oauth2/token",
		"https://[::1]:8081/msi/token",
	}
	bad := []string{
		"", "   ",
		"http://attacker.example.com/token",
		"https://10.0.0.5/token",
		"file:///etc/passwd",
		"http://8.8.8.8/token",
		"not a url at all::",
	}
	for _, u := range ok {
		if _, err := localIdentityEndpoint(u); err != nil {
			t.Errorf("localIdentityEndpoint(%q) = %v, want nil", u, err)
		}
	}
	for _, u := range bad {
		if _, err := localIdentityEndpoint(u); err == nil {
			t.Errorf("localIdentityEndpoint(%q) = nil, want an error", u)
		}
	}
}

// AKS Workload Identity (env AZURE_FEDERATED_TOKEN_FILE) must still take precedence over the managed-identity endpoint hints.
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
