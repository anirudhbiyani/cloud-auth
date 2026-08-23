package source

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/internal/httpx"
	"github.com/anirudhbiyani/cloud-auth/internal/jwt"
)

// DefaultAzureIMDSURL is the Azure Instance Metadata Service base.
const DefaultAzureIMDSURL = "http://169.254.169.254"

// Azure is the Source Identity Provider for Azure VMs/VMSS and AKS Workload
// Identity. On AKS Workload Identity it uses the projected OIDC token (the
// portable, cross-cloud-federatable proof); on a VM it uses the Entra token
// from IMDS.
type Azure struct {
	imdsURL    string
	httpClient *http.Client
	getenv     func(string) string
	readFile   func(string) ([]byte, error)
	k8sClient  k8sTokenMinter // injected for tests; nil => derive in-cluster
}

// AzureOption configures an Azure provider.
type AzureOption func(*Azure)

func WithAzureIMDSURL(u string) AzureOption          { return func(a *Azure) { a.imdsURL = u } }
func WithAzureHTTPClient(h *http.Client) AzureOption { return func(a *Azure) { a.httpClient = h } }
func WithAzureEnv(f func(string) string) AzureOption { return func(a *Azure) { a.getenv = f } }
func WithAzureFileReader(f func(string) ([]byte, error)) AzureOption {
	return func(a *Azure) { a.readFile = f }
}

// WithAzureK8sTokenClient injects a Kubernetes TokenRequest client used by the
// AKS Workload Identity mint path to dynamically re-mint a projected token for a
// requested audience. When unset, the client is derived from the in-cluster
// environment.
func WithAzureK8sTokenClient(c k8sTokenMinter) AzureOption {
	return func(a *Azure) { a.k8sClient = c }
}

// NewAzure builds an Azure provider with defaults.
func NewAzure(opts ...AzureOption) *Azure {
	a := &Azure{
		imdsURL:    DefaultAzureIMDSURL,
		httpClient: httpx.NewMetadataClient(2 * time.Second),
		getenv:     os.Getenv,
		readFile:   os.ReadFile,
	}
	for _, o := range opts {
		o(a)
	}
	return a
}

// usesWorkloadIdentity reports whether the AKS Workload Identity projected
// token is available (the preferred cross-cloud source path).
func (a *Azure) usesWorkloadIdentity() bool {
	return a.getenv("AZURE_FEDERATED_TOKEN_FILE") != ""
}

// managedIdentitySubRuntime reports the App Service / Container Apps sub-runtime
// when the managed-identity token endpoint (IDENTITY_ENDPOINT + IDENTITY_HEADER)
// is present, or "" otherwise. Container Apps and App Service both expose that
// endpoint instead of IMDS.
func (a *Azure) managedIdentitySubRuntime() string {
	if a.getenv("IDENTITY_ENDPOINT") == "" || a.getenv("IDENTITY_HEADER") == "" {
		return ""
	}
	switch {
	case a.getenv("CONTAINER_APP_NAME") != "":
		return "container-apps"
	case a.getenv("WEBSITE_SITE_NAME") != "":
		return "app-service"
	default:
		return ""
	}
}

func (a *Azure) imdsGet(ctx context.Context, path, rawQuery string) ([]byte, error) {
	u := a.imdsURL + path
	if rawQuery != "" {
		u += "?" + rawQuery
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Metadata", "true")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("azure imds %s: status %d", path, resp.StatusCode)
	}
	return body, nil
}

// localIdentityEndpoint validates IDENTITY_ENDPOINT before the IDENTITY_HEADER
// secret is sent to it.
//
// The variable is a URL taken verbatim from the environment, and the request
// carries the header secret that authenticates to the local token service.
// Anything that can influence the environment — a container spec, an operator
// with a compromised deployment pipeline — could otherwise point it at a remote
// host and collect both the secret and a managed-identity token on every mint.
// The real endpoint is always loopback or link-local, so requiring that costs
// nothing and closes the exfiltration path.
func localIdentityEndpoint(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("IDENTITY_ENDPOINT is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("IDENTITY_ENDPOINT %q is not a URL: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("IDENTITY_ENDPOINT %q must be http or https", raw)
	}
	host := u.Hostname()
	if host == "localhost" {
		return raw, nil
	}
	ip := net.ParseIP(host)
	if ip != nil && (ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
		return raw, nil
	}
	return "", fmt.Errorf("refusing to send the IDENTITY_HEADER secret to non-local host %q: "+
		"the managed-identity endpoint is always loopback or link-local", u.Host)
}

// Detect resolves AKS Workload Identity (via env) or a VM/VMSS (via IMDS).
func (a *Azure) Detect(ctx context.Context) (*core.Runtime, error) {
	if a.usesWorkloadIdentity() {
		return &core.Runtime{
			Cloud:       core.Azure,
			SubRuntime:  "aks-workload-identity",
			Federatable: true,
			Subject:     a.getenv("AZURE_CLIENT_ID"),
		}, nil
	}
	// Managed identity — App Service, Container Apps, a bare VM — vends Entra
	// ACCESS tokens, which are bearer credentials for a named Azure resource,
	// not audience-pinned assertions about this workload. They are not a
	// federation source, and saying so here is what lets `cloud-auth doctor`
	// tell an operator the truth before they build on it.
	if sub := a.managedIdentitySubRuntime(); sub != "" {
		return &core.Runtime{
			Cloud:       core.Azure,
			SubRuntime:  sub,
			Federatable: false,
			Subject:     a.getenv("AZURE_CLIENT_ID"),
		}, nil
	}
	if _, err := a.imdsGet(ctx, "/metadata/instance", "api-version=2021-02-01"); err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrNotThisRuntime, err)
	}
	return &core.Runtime{
		Cloud:       core.Azure,
		SubRuntime:  "vm",
		Federatable: false,
	}, nil
}

// Mint returns the projected OIDC token (AKS WI) or an IMDS Entra token (VM).
func (a *Azure) Mint(ctx context.Context, audience string) (*core.SourceToken, error) {
	if audience == "" {
		return nil, fmt.Errorf("azure: audience is required")
	}
	if a.usesWorkloadIdentity() {
		return a.mintFromFile(ctx, audience)
	}
	// Everything below this point vends an Entra access token, and an access
	// token is not a proof of identity that another cloud's STS can verify — it
	// is a live bearer credential for whatever resource was named in the
	// request. Handing one to a third-party STS discloses a working Azure
	// credential and still fails the exchange, because the token's aud is an
	// Azure resource rather than the target's audience.
	if sub := a.managedIdentitySubRuntime(); sub != "" {
		return nil, fmt.Errorf("%w: Azure managed identity on %s vends Entra access tokens, not "+
			"audience-pinned assertions; use AKS Workload Identity (AZURE_FEDERATED_TOKEN_FILE) "+
			"for cross-cloud federation", core.ErrNonFederatableSource, sub)
	}
	return nil, fmt.Errorf("%w: an Azure VM's IMDS vends Entra access tokens, not audience-pinned "+
		"assertions; run the workload on AKS with Workload Identity enabled, or bridge this "+
		"identity through an OIDC issuer", core.ErrNonFederatableSource)
}

// mintManagedIdentityToken obtains an Entra access token for resource.
//
// This is NOT a federation source — see Mint, which refuses those paths. It
// exists for same-cloud use and for `cloud-auth doctor`, which reports what the
// runtime can and cannot do. Both callers are local to this process, so the
// token never crosses a trust boundary.
func (a *Azure) mintManagedIdentityToken(ctx context.Context, resource string) (*core.SourceToken, error) {
	if a.managedIdentitySubRuntime() != "" {
		return a.mintFromIdentityEndpoint(ctx, resource)
	}
	return a.mintFromIMDS(ctx, resource)
}

func (a *Azure) mintFromFile(ctx context.Context, audience string) (*core.SourceToken, error) {
	raw, err := a.readFile(a.getenv("AZURE_FEDERATED_TOKEN_FILE"))
	if err != nil {
		return nil, fmt.Errorf("azure: reading projected token: %w", err)
	}
	claims, err := jwt.ParseUnverified(string(raw))
	if err != nil {
		return nil, fmt.Errorf("azure: parsing projected token: %w", err)
	}
	// Fast path: the on-disk projected token already carries the requested aud.
	if claims.HasAudience(audience) {
		return &core.SourceToken{
			Kind:     core.OIDC,
			Value:    string(raw),
			Issuer:   claims.Issuer,
			Subject:  claims.Subject,
			Audience: audience,
			Expiry:   claims.Expiry,
		}, nil
	}
	// The projected token's aud is fixed by the AKS Workload Identity webhook
	// (default api://AzureADTokenExchange). When running in-cluster, mint a fresh
	// token carrying the requested audience via the Kubernetes TokenRequest API
	// rather than failing closed.
	if token, available, err := mintDynamicAudienceToken(ctx, a.k8sClient, a.getenv, a.readFile, claims, audience); available {
		if err != nil {
			return nil, fmt.Errorf("azure: %w", err)
		}
		minted, _ := jwt.ParseUnverified(token)
		return &core.SourceToken{
			Kind:     core.OIDC,
			Value:    token,
			Issuer:   minted.Issuer,
			Subject:  minted.Subject,
			Audience: audience,
			Expiry:   minted.Expiry,
		}, nil
	}
	// Not in-cluster (or TokenRequest unavailable): fail closed with guidance.
	return nil, fmt.Errorf(
		"azure: projected AKS token audience %v does not include the requested audience %q; "+
			"reconfigure the service account's projected-token audience to match the target "+
			"(via the azure.workload.identity/... annotation) or point --audience at the projected value",
		claims.Audiences, audience)
}

// mintFromIdentityEndpoint mints a managed-identity token via the App Service /
// Container Apps local token endpoint (IDENTITY_ENDPOINT), authenticated with
// the IDENTITY_HEADER secret rather than the IMDS Metadata header.
func (a *Azure) mintFromIdentityEndpoint(ctx context.Context, audience string) (*core.SourceToken, error) {
	endpoint, err := localIdentityEndpoint(a.getenv("IDENTITY_ENDPOINT"))
	if err != nil {
		return nil, fmt.Errorf("azure: %w", err)
	}
	q := url.Values{"resource": {audience}, "api-version": {"2019-08-01"}}
	// Bind the request to the identity Detect reported. Without this, a host with
	// several user-assigned identities returns whichever one the platform
	// considers default, so the SDK would report one identity and authenticate
	// as another.
	if id := a.getenv("AZURE_CLIENT_ID"); id != "" {
		q.Set("client_id", id)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-IDENTITY-HEADER", a.getenv("IDENTITY_HEADER"))
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("azure: minting managed-identity token: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("azure: managed-identity endpoint status %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("azure: decoding managed-identity token: %w", err)
	}
	claims, _ := jwt.ParseUnverified(out.AccessToken)
	return &core.SourceToken{
		Kind:     core.OIDC,
		Value:    out.AccessToken,
		Issuer:   claims.Issuer,
		Subject:  claims.Subject,
		Audience: audience,
		Expiry:   claims.Expiry,
	}, nil
}

func (a *Azure) mintFromIMDS(ctx context.Context, audience string) (*core.SourceToken, error) {
	q := url.Values{"api-version": {"2018-02-01"}, "resource": {audience}}
	// Same reason as the identity-endpoint path: name the identity, or a
	// multi-identity VM silently authenticates as a different one.
	if id := a.getenv("AZURE_CLIENT_ID"); id != "" {
		q.Set("client_id", id)
	}
	body, err := a.imdsGet(ctx, "/metadata/identity/oauth2/token", q.Encode())
	if err != nil {
		return nil, fmt.Errorf("azure: minting IMDS token: %w", err)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("azure: decoding IMDS token: %w", err)
	}
	claims, _ := jwt.ParseUnverified(out.AccessToken)
	return &core.SourceToken{
		Kind:     core.OIDC,
		Value:    out.AccessToken,
		Issuer:   claims.Issuer,
		Subject:  claims.Subject,
		Audience: audience,
		Expiry:   claims.Expiry,
	}, nil
}
