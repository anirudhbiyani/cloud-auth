// Package imds is an IMDSv2-only client for the AWS Instance Metadata Service.
package imds

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/anirudhbiyani/cloud-auth/internal/httpx"
)

// DefaultBaseURL is the link-local IMDS endpoint.
const DefaultBaseURL = "http://169.254.169.254"

const (
	tokenPath       = "/latest/api/token"
	tokenTTLHeader  = "X-aws-ec2-metadata-token-ttl-seconds"
	tokenHeader     = "X-aws-ec2-metadata-token"
	defaultTokenTTL = 60 * time.Second
	defaultTimeout  = 2 * time.Second
)

// Client reads instance metadata over IMDSv2.
type Client struct {
	baseURL    string
	httpClient *http.Client
	tokenTTL   time.Duration

	// The session token is cached for its TTL.
	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

// Option configures a Client.
type Option func(*Client)

// WithBaseURL overrides the IMDS endpoint (used in tests).
func WithBaseURL(u string) Option { return func(c *Client) { c.baseURL = u } }

// WithHTTPClient sets the underlying HTTP client.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.httpClient = h } }

// WithTokenTTL sets the session-token TTL requested from IMDS.
func WithTokenTTL(d time.Duration) Option { return func(c *Client) { c.tokenTTL = d } }

// New builds a Client with sensible defaults (short timeout, 60s token TTL).
func New(opts ...Option) *Client {
	c := &Client{
		baseURL:    DefaultBaseURL,
		httpClient: httpx.NewMetadataClient(defaultTimeout),
		tokenTTL:   defaultTokenTTL,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// sessionToken returns a cached session token, minting one if none is valid.
func (c *Client) sessionToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Renew a little early: a token that expires mid-request is a failed read.
	if c.token != "" && time.Now().Before(c.tokenExp.Add(-5*time.Second)) {
		return c.token, nil
	}
	tok, err := c.mintToken(ctx)
	if err != nil {
		return "", err
	}
	c.token, c.tokenExp = tok, time.Now().Add(c.tokenTTL)
	return tok, nil
}

// mintToken mints a fresh IMDSv2 session token.
func (c *Client) mintToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+tokenPath, nil)
	if err != nil {
		return "", err
	}
	ttl := int(c.tokenTTL.Seconds())
	if ttl < 1 {
		ttl = 1
	}
	req.Header.Set(tokenTTLHeader, strconv.Itoa(ttl))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("imds: minting session token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("imds: token endpoint returned %d (IMDSv2 required, not falling back to v1)", resp.StatusCode)
	}
	if len(body) == 0 {
		return "", fmt.Errorf("imds: token endpoint returned an empty token")
	}
	return string(body), nil
}

// Get reads a metadata path over IMDSv2. It mints a token first and never issues a token-less request.
func (c *Client) Get(ctx context.Context, path string) ([]byte, error) {
	tok, err := c.sessionToken(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(tokenHeader, tok)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("imds: GET %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("imds: reading %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("imds: GET %s returned %d: %s", path, resp.StatusCode, body)
	}
	return body, nil
}
