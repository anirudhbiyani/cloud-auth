// Package anthropic manages Claude Platform workload identity federation through the Admin API.
package anthropic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/anirudhbiyani/cloud-auth/internal/httpx"
)

// DefaultBaseURL is the Admin API host.
const DefaultBaseURL = "https://api.anthropic.com"

// Client is a thin Admin API client: the federation endpoints are five resource shapes and one pagination scheme, which does not justify an SDK dependency.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// ClientOption configures a Client.
type ClientOption func(*Client)

// WithBaseURL overrides the API host. For tests.
func WithBaseURL(u string) ClientOption { return func(c *Client) { c.baseURL = u } }

// WithToken sets the org:admin OAuth bearer token. Defaults to $ANTHROPIC_AUTH_TOKEN.
func WithToken(t string) ClientOption { return func(c *Client) { c.token = t } }

// WithHTTPClient overrides the HTTP client.
func WithHTTPClient(h *http.Client) ClientOption { return func(c *Client) { c.http = h } }

// NewClient builds a client; the token comes from ANTHROPIC_AUTH_TOKEN unless given.
func NewClient(opts ...ClientOption) *Client {
	c := &Client{baseURL: DefaultBaseURL, token: os.Getenv("ANTHROPIC_AUTH_TOKEN"), http: httpx.NewSTSClient(30 * time.Second)}
	for _, o := range opts {
		o(c)
	}
	return c
}

// HasToken reports whether a bearer token is configured.
func (c *Client) HasToken() bool { return c.token != "" }

// ServiceAccount is the non-human identity a federated token acts as.
type ServiceAccount struct {
	ID               string  `json:"id"`
	Name             string  `json:"name"`
	OrganizationRole string  `json:"organization_role"`
	ArchivedAt       *string `json:"archived_at,omitempty"`
}

// Issuer is a registered OIDC provider.
type Issuer struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	IssuerURL  string         `json:"issuer_url"`
	JWKS       map[string]any `json:"jwks,omitempty"`
	ArchivedAt *string        `json:"archived_at,omitempty"`
}

// RuleMatch is what a token must satisfy; every populated field ANDs.
type RuleMatch struct {
	SubjectPrefix string            `json:"subject_prefix,omitempty"`
	Audience      string            `json:"audience,omitempty"`
	Claims        map[string]string `json:"claims,omitempty"`
	Condition     string            `json:"condition,omitempty"`
}

// RuleTarget is the identity a matching token acts as.
type RuleTarget struct {
	Type             string `json:"type"`
	ServiceAccountID string `json:"service_account_id"`
}

// Rule binds an issuer to a service account.
type Rule struct {
	ID                     string     `json:"id,omitempty"`
	Name                   string     `json:"name"`
	IssuerID               string     `json:"issuer_id"`
	Match                  RuleMatch  `json:"match"`
	Target                 RuleTarget `json:"target"`
	WorkspaceID            string     `json:"workspace_id,omitempty"`
	AppliesToAllWorkspaces bool       `json:"applies_to_all_workspaces,omitempty"`
	OAuthScope             string     `json:"oauth_scope,omitempty"`
	TokenLifetimeSeconds   int        `json:"token_lifetime_seconds,omitempty"`
	ArchivedAt             *string    `json:"archived_at,omitempty"`
}

// APIError is a non-2xx Admin API response.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("anthropic admin api: HTTP %d: %s", e.Status, e.Body)
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("authorization", "Bearer "+c.token)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("accept", "application/json")
	if in != nil {
		req.Header.Set("content-type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("anthropic admin api: %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &APIError{Status: resp.StatusCode, Body: string(raw)}
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// list walks every page of a collection endpoint.
func list[T any](ctx context.Context, c *Client, path string, query url.Values) ([]T, error) {
	var all []T
	page := ""
	for {
		q := url.Values{}
		for k, v := range query {
			q[k] = v
		}
		q.Set("limit", "100")
		if page != "" {
			q.Set("page", page)
		}
		var out struct {
			Data     []T    `json:"data"`
			NextPage string `json:"next_page"`
		}
		if err := c.do(ctx, http.MethodGet, path+"?"+q.Encode(), nil, &out); err != nil {
			return nil, err
		}
		all = append(all, out.Data...)
		if out.NextPage == "" {
			return all, nil
		}
		page = out.NextPage
	}
}

// ListServiceAccounts returns the live service accounts.
func (c *Client) ListServiceAccounts(ctx context.Context) ([]ServiceAccount, error) {
	return list[ServiceAccount](ctx, c, "/v1/organizations/service_accounts", nil)
}

// CreateServiceAccount creates a developer-role service account.
func (c *Client) CreateServiceAccount(ctx context.Context, name string) (*ServiceAccount, error) {
	var out ServiceAccount
	err := c.do(ctx, http.MethodPost, "/v1/organizations/service_accounts", map[string]string{"name": name, "organization_role": "developer"}, &out)
	return &out, err
}

// GetServiceAccount reads one service account.
func (c *Client) GetServiceAccount(ctx context.Context, id string) (*ServiceAccount, error) {
	var out ServiceAccount
	err := c.do(ctx, http.MethodGet, "/v1/organizations/service_accounts/"+url.PathEscape(id), nil, &out)
	return &out, err
}

// ArchiveServiceAccount soft-deletes; idempotent, 400 while a live rule targets it.
func (c *Client) ArchiveServiceAccount(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/v1/organizations/service_accounts/"+url.PathEscape(id)+"/archive", nil, nil)
}

// ListIssuers returns the live issuers.
func (c *Client) ListIssuers(ctx context.Context) ([]Issuer, error) {
	return list[Issuer](ctx, c, "/v1/organizations/federation_issuers", nil)
}

// CreateIssuer registers an issuer; jwks is the discriminated union ({"type":"discovery"} or explicit_url).
func (c *Client) CreateIssuer(ctx context.Context, name, issuerURL string, jwks map[string]any) (*Issuer, error) {
	var out Issuer
	err := c.do(ctx, http.MethodPost, "/v1/organizations/federation_issuers", map[string]any{"name": name, "issuer_url": issuerURL, "jwks": jwks}, &out)
	return &out, err
}

// GetIssuer reads one issuer.
func (c *Client) GetIssuer(ctx context.Context, id string) (*Issuer, error) {
	var out Issuer
	err := c.do(ctx, http.MethodGet, "/v1/organizations/federation_issuers/"+url.PathEscape(id), nil, &out)
	return &out, err
}

// ArchiveIssuer soft-deletes; 400 while a live rule references it.
func (c *Client) ArchiveIssuer(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/v1/organizations/federation_issuers/"+url.PathEscape(id)+"/archive", nil, nil)
}

// ListRules returns the live rules, optionally for one issuer.
func (c *Client) ListRules(ctx context.Context, issuerID string) ([]Rule, error) {
	q := url.Values{}
	if issuerID != "" {
		q.Set("issuer_id", issuerID)
	}
	return list[Rule](ctx, c, "/v1/organizations/federation_rules", q)
}

// CreateRule creates a federation rule.
func (c *Client) CreateRule(ctx context.Context, r Rule) (*Rule, error) {
	var out Rule
	err := c.do(ctx, http.MethodPost, "/v1/organizations/federation_rules", r, &out)
	return &out, err
}

// GetRule reads one rule.
func (c *Client) GetRule(ctx context.Context, id string) (*Rule, error) {
	var out Rule
	err := c.do(ctx, http.MethodGet, "/v1/organizations/federation_rules/"+url.PathEscape(id), nil, &out)
	return &out, err
}

// ArchiveRule soft-deletes a rule; idempotent.
func (c *Client) ArchiveRule(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/v1/organizations/federation_rules/"+url.PathEscape(id)+"/archive", nil, nil)
}
