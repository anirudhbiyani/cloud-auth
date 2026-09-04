// Package k8stoken mints a projected service-account OIDC token carrying a
// caller-chosen audience via the Kubernetes TokenRequest API.
//
// A pod's projected service-account token has its aud fixed at projection time.
// When a workload needs a token for a different audience (e.g. a specific
// cross-cloud STS target), it can call the API server's TokenRequest endpoint to
// mint a fresh token bound to the requested audience, using the pod's own
// service-account token as the bearer credential.
package k8stoken

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/anirudhbiyani/cloud-auth/internal/httpx"
)

// In-cluster credential/config file locations, exported so callers can reuse
// them when bootstrapping a Client from the mounted service-account volume.
const (
	TokenFile     = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	CACertFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	NamespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// Client mints tokens via the Kubernetes TokenRequest API. All fields are
// injectable so it is unit-testable against an httptest fake API server.
type Client struct {
	baseURL     string
	httpClient  *http.Client
	bearerToken string
	namespace   string
	serviceAcct string
	expirySecs  int
}

// Option configures a Client.
type Option func(*Client)

func WithBaseURL(u string) Option          { return func(c *Client) { c.baseURL = u } }
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.httpClient = h } }
func WithBearerToken(t string) Option      { return func(c *Client) { c.bearerToken = t } }
func WithServiceAccount(ns, sa string) Option {
	return func(c *Client) { c.namespace, c.serviceAcct = ns, sa }
}

// New builds a Client with defaults. It is not usable until a base URL and a
// service account are configured (see the source package for in-cluster wiring).
func New(opts ...Option) *Client {
	c := &Client{
		httpClient: httpx.NewSTSClient(5 * time.Second),
		expirySecs: 3600,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Mint requests a fresh projected service-account token bound to audience.
func (c *Client) Mint(ctx context.Context, audience string) (string, error) {
	if c.baseURL == "" || c.namespace == "" || c.serviceAcct == "" || c.bearerToken == "" {
		return "", fmt.Errorf("k8stoken: not configured for TokenRequest (base url, namespace, service account, and bearer token are required)")
	}
	reqBody, err := json.Marshal(tokenRequest{
		APIVersion: "authentication.k8s.io/v1",
		Kind:       "TokenRequest",
		Spec: tokenRequestSpec{
			Audiences:         []string{audience},
			ExpirationSeconds: c.expirySecs,
		},
	})
	if err != nil {
		return "", fmt.Errorf("k8stoken: marshaling request: %w", err)
	}

	// PathEscape both: the caller derives them from a JWT it did not verify, and
	// source/k8stoken validates them as DNS labels — but this package is exported
	// and cannot assume that happened.
	u := fmt.Sprintf("%s/api/v1/namespaces/%s/serviceaccounts/%s/token",
		c.baseURL, url.PathEscape(c.namespace), url.PathEscape(c.serviceAcct))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.bearerToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("k8stoken: calling TokenRequest API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("k8stoken: TokenRequest returned status %d: %s", resp.StatusCode, string(body))
	}

	var out tokenResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("k8stoken: decoding TokenRequest response: %w", err)
	}
	if out.Status.Token == "" {
		return "", fmt.Errorf("k8stoken: TokenRequest response contained no token")
	}
	return out.Status.Token, nil
}

type tokenRequest struct {
	APIVersion string           `json:"apiVersion"`
	Kind       string           `json:"kind"`
	Spec       tokenRequestSpec `json:"spec"`
}

type tokenRequestSpec struct {
	Audiences         []string `json:"audiences"`
	ExpirationSeconds int      `json:"expirationSeconds"`
}

type tokenResponse struct {
	Status struct {
		Token               string `json:"token"`
		ExpirationTimestamp string `json:"expirationTimestamp"`
	} `json:"status"`
}
