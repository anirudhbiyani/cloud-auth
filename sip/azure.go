package sip

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
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
}

// AzureOption configures an Azure provider.
type AzureOption func(*Azure)

func WithAzureIMDSURL(u string) AzureOption          { return func(a *Azure) { a.imdsURL = u } }
func WithAzureHTTPClient(h *http.Client) AzureOption { return func(a *Azure) { a.httpClient = h } }
func WithAzureEnv(f func(string) string) AzureOption { return func(a *Azure) { a.getenv = f } }
func WithAzureFileReader(f func(string) ([]byte, error)) AzureOption {
	return func(a *Azure) { a.readFile = f }
}

// NewAzure builds an Azure provider with defaults.
func NewAzure(opts ...AzureOption) *Azure {
	a := &Azure{
		imdsURL:    DefaultAzureIMDSURL,
		httpClient: &http.Client{Timeout: 2 * time.Second},
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

// Detect resolves AKS Workload Identity (via env) or a VM/VMSS (via IMDS).
func (a *Azure) Detect(ctx context.Context) (*cloudauth.Runtime, error) {
	if a.usesWorkloadIdentity() {
		return &cloudauth.Runtime{
			Cloud:       cloudauth.Azure,
			SubRuntime:  "aks-workload-identity",
			Federatable: true,
			Subject:     a.getenv("AZURE_CLIENT_ID"),
		}, nil
	}
	if _, err := a.imdsGet(ctx, "/metadata/instance", "api-version=2021-02-01"); err != nil {
		return nil, fmt.Errorf("%w: %v", cloudauth.ErrNotThisRuntime, err)
	}
	return &cloudauth.Runtime{
		Cloud:       cloudauth.Azure,
		SubRuntime:  "vm",
		Federatable: true,
	}, nil
}

// Mint returns the projected OIDC token (AKS WI) or an IMDS Entra token (VM).
func (a *Azure) Mint(ctx context.Context, audience string) (*cloudauth.SourceToken, error) {
	if audience == "" {
		return nil, fmt.Errorf("azure: audience is required")
	}
	if a.usesWorkloadIdentity() {
		return a.mintFromFile(audience)
	}
	return a.mintFromIMDS(ctx, audience)
}

func (a *Azure) mintFromFile(audience string) (*cloudauth.SourceToken, error) {
	raw, err := a.readFile(a.getenv("AZURE_FEDERATED_TOKEN_FILE"))
	if err != nil {
		return nil, fmt.Errorf("azure: reading projected token: %w", err)
	}
	claims, err := jwt.ParseUnverified(string(raw))
	if err != nil {
		return nil, fmt.Errorf("azure: parsing projected token: %w", err)
	}
	return &cloudauth.SourceToken{
		Kind:     cloudauth.OIDC,
		Value:    string(raw),
		Issuer:   claims.Issuer,
		Subject:  claims.Subject,
		Audience: audience,
		Expiry:   claims.Expiry,
	}, nil
}

func (a *Azure) mintFromIMDS(ctx context.Context, audience string) (*cloudauth.SourceToken, error) {
	q := url.Values{"api-version": {"2018-02-01"}, "resource": {audience}}.Encode()
	body, err := a.imdsGet(ctx, "/metadata/identity/oauth2/token", q)
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
	return &cloudauth.SourceToken{
		Kind:     cloudauth.OIDC,
		Value:    out.AccessToken,
		Issuer:   claims.Issuer,
		Subject:  claims.Subject,
		Audience: audience,
		Expiry:   claims.Expiry,
	}, nil
}
