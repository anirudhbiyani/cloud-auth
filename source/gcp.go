package source

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
	"github.com/anirudhbiyani/cloud-auth/internal/jwt"
)

// DefaultGCPMetadataURL is the GCE/GKE metadata server base.
const DefaultGCPMetadataURL = "http://metadata.google.internal"

const gcpMetadataFlavor = "Google"

// GCP is the Source Identity Provider for GCE, GKE, Cloud Run, and Cloud
// Functions. It mints Google-signed OIDC ID tokens from the metadata server.
type GCP struct {
	metadataURL string
	httpClient  *http.Client
	getenv      func(string) string
}

// GCPOption configures a GCP provider.
type GCPOption func(*GCP)

func WithGCPMetadataURL(u string) GCPOption      { return func(g *GCP) { g.metadataURL = u } }
func WithGCPHTTPClient(h *http.Client) GCPOption { return func(g *GCP) { g.httpClient = h } }
func WithGCPEnv(f func(string) string) GCPOption { return func(g *GCP) { g.getenv = f } }

// NewGCP builds a GCP provider with defaults.
func NewGCP(opts ...GCPOption) *GCP {
	g := &GCP{
		metadataURL: DefaultGCPMetadataURL,
		httpClient:  &http.Client{Timeout: 2 * time.Second},
		getenv:      os.Getenv,
	}
	for _, o := range opts {
		o(g)
	}
	return g
}

func (g *GCP) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.metadataURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Metadata-Flavor", gcpMetadataFlavor)
	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gcp metadata %s: status %d", path, resp.StatusCode)
	}
	return body, nil
}

// Detect probes the metadata server. Presence of KUBERNETES_SERVICE_HOST marks
// the sub-runtime as GKE, otherwise GCE.
func (g *GCP) Detect(ctx context.Context) (*cloudauth.Runtime, error) {
	if _, err := g.get(ctx, "/computeMetadata/v1/"); err != nil {
		return nil, fmt.Errorf("%w: %v", cloudauth.ErrNotThisRuntime, err)
	}
	// Env hints resolve the sub-runtime; GKE takes precedence over the
	// serverless hints, then Cloud Run, then Cloud Functions, else bare GCE.
	sub := "gce"
	switch {
	case g.getenv("KUBERNETES_SERVICE_HOST") != "":
		sub = "gke"
	case g.getenv("K_SERVICE") != "":
		sub = "cloud-run"
	case g.getenv("FUNCTION_TARGET") != "":
		sub = "cloud-functions"
	}
	email, _ := g.get(ctx, "/computeMetadata/v1/instance/service-accounts/default/email")
	return &cloudauth.Runtime{
		Cloud:       cloudauth.GCP,
		SubRuntime:  sub,
		Federatable: true,
		Subject:     string(email),
	}, nil
}

// Mint fetches a Google-signed OIDC ID token pinned to audience.
func (g *GCP) Mint(ctx context.Context, audience string) (*cloudauth.SourceToken, error) {
	if audience == "" {
		return nil, fmt.Errorf("gcp: audience is required")
	}
	path := "/computeMetadata/v1/instance/service-accounts/default/identity?" +
		url.Values{"audience": {audience}, "format": {"full"}}.Encode()
	body, err := g.get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("gcp: minting identity token: %w", err)
	}
	claims, err := jwt.ParseUnverified(string(body))
	if err != nil {
		return nil, fmt.Errorf("gcp: parsing minted token: %w", err)
	}
	return &cloudauth.SourceToken{
		Kind:     cloudauth.OIDC,
		Value:    string(body),
		Issuer:   claims.Issuer,
		Subject:  claims.Subject,
		Audience: audience,
		Expiry:   claims.Expiry,
	}, nil
}
