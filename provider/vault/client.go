package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/anirudhbiyani/cloud-auth/internal/httpx"
	"github.com/anirudhbiyani/cloud-auth/internal/redact"
)

// This file is the concrete client behind VaultClient.

const (
	// requestTimeout bounds a single API call.
	requestTimeout = 30 * time.Second
	// errorBodyLimit caps a retained upstream error body.
	errorBodyLimit = 512

	// tokenHeader carries the caller's Vault token.
	tokenHeader = "X-Vault-Token"
	// namespaceHeader selects a Vault Enterprise namespace.
	namespaceHeader = "X-Vault-Namespace"
)

// apiError is a Vault API failure with its status and messages preserved.
type apiError struct {
	StatusCode int
	Errors     []string
	Path       string
}

func (e *apiError) Error() string {
	msg := strings.Join(e.Errors, "; ")
	if msg == "" {
		msg = http.StatusText(e.StatusCode)
	}
	if e.Path != "" {
		return fmt.Sprintf("vault: %d on %s: %s", e.StatusCode, e.Path, msg)
	}
	return fmt.Sprintf("vault: %d: %s", e.StatusCode, msg)
}

// NotFound reports absence.
func (e *apiError) NotFound() bool { return e.StatusCode == http.StatusNotFound }

// Forbidden reports a permission failure — explicitly NOT absence.
func (e *apiError) Forbidden() bool { return e.StatusCode == http.StatusForbidden }

// Sealed reports that Vault is sealed or standby.
func (e *apiError) Sealed() bool {
	return e.StatusCode == http.StatusServiceUnavailable
}

// restClient implements VaultClient over Vault's HTTP API.
type restClient struct {
	http      *http.Client
	address   string
	token     string
	namespace string
}

// ClientOption configures the Vault client.
type ClientOption func(*restClient)

// WithHTTPClient overrides the HTTP client.
func WithHTTPClient(c *http.Client) ClientOption {
	return func(r *restClient) { r.http = c }
}

// WithAddress sets the Vault address, overriding VAULT_ADDR.
func WithAddress(addr string) ClientOption {
	return func(r *restClient) { r.address = strings.TrimRight(addr, "/") }
}

// WithToken sets the Vault token, overriding VAULT_TOKEN.
func WithToken(token string) ClientOption {
	return func(r *restClient) { r.token = token }
}

// WithNamespace sets a Vault Enterprise namespace, overriding VAULT_NAMESPACE.
func WithNamespace(ns string) ClientOption {
	return func(r *restClient) { r.namespace = ns }
}

// NewClient builds a Vault client from the environment.
func NewClient(opts ...ClientOption) (VaultClient, error) {
	c := &restClient{
		http:      httpx.NewSTSClient(requestTimeout),
		address:   strings.TrimRight(os.Getenv("VAULT_ADDR"), "/"),
		token:     os.Getenv("VAULT_TOKEN"),
		namespace: os.Getenv("VAULT_NAMESPACE"),
	}
	for _, o := range opts {
		o(c)
	}

	if c.address == "" {
		return nil, errors.New("vault: VAULT_ADDR is not set")
	}
	u, err := url.Parse(c.address)
	if err != nil {
		return nil, fmt.Errorf("vault: VAULT_ADDR %q is not a URL: %w", c.address, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("vault: VAULT_ADDR %q must be http or https", c.address)
	}
	if c.token == "" {
		return nil, errors.New("vault: VAULT_TOKEN is not set")
	}
	return c, nil
}

// secret is Vault's response envelope.
type secret struct {
	RequestID     string          `json:"request_id"`
	LeaseID       string          `json:"lease_id"`
	LeaseDuration int             `json:"lease_duration"`
	Renewable     bool            `json:"renewable"`
	Data          json.RawMessage `json:"data"`
	Auth          *struct {
		ClientToken   string   `json:"client_token"`
		Accessor      string   `json:"accessor"`
		Policies      []string `json:"policies"`
		LeaseDuration int      `json:"lease_duration"`
		Renewable     bool     `json:"renewable"`
	} `json:"auth"`
}

// decodeData unmarshals the envelope's data field into out.
func (s *secret) decodeData(out any) error {
	if len(s.Data) == 0 {
		return errors.New("vault: response carried no data")
	}
	if err := json.Unmarshal(s.Data, out); err != nil {
		return fmt.Errorf("vault: decoding response data: %w", err)
	}
	return nil
}

// do performs one authenticated call against /v1/<path>.
func (c *restClient) do(ctx context.Context, method, path string, body any, out *secret) error {
	endpoint := c.address + "/v1/" + strings.TrimLeft(path, "/")

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("vault: encoding request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return fmt.Errorf("vault: building request: %w", err)
	}
	req.Header.Set(tokenHeader, c.token)
	if c.namespace != "" {
		req.Header.Set(namespaceHeader, c.namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("vault: %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("vault: reading response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return parseAPIError(resp.StatusCode, raw, path)
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("vault: decoding response: %w", err)
	}
	return nil
}

// parseAPIError decodes Vault's {"errors": [...]} envelope.
func parseAPIError(status int, raw []byte, path string) error {
	e := &apiError{StatusCode: status, Path: path}

	var envelope struct {
		Errors []string `json:"errors"`
	}
	if err := json.Unmarshal(raw, &envelope); err == nil {
		for _, msg := range envelope.Errors {
			// Vault echoes request material into some errors, and a token present in one is a live credential.
			e.Errors = append(e.Errors, redact.Body(msg, errorBodyLimit))
		}
		return e
	}
	if trimmed := strings.TrimSpace(string(raw)); trimmed != "" {
		e.Errors = []string{redact.Body(trimmed, errorBodyLimit)}
	}
	return e
}

// urlQueryEscape escapes a query value.
func urlQueryEscape(v string) string { return url.QueryEscape(v) }

// sortStrings sorts in place. Kept local so the helpers file needs no import.
func sortStrings(in []string) { slices.Sort(in) }
