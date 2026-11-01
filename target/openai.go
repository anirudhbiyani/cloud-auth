package target

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/internal/httpx"
	"github.com/anirudhbiyani/cloud-auth/internal/redact"
)

// The OpenAI API platform as a federation target.

const (
	// DefaultOpenAIEndpoint is OpenAI's workload identity token endpoint (JWT mode; X.509 uses mtls.auth.openai.com).
	DefaultOpenAIEndpoint = "https://auth.openai.com/oauth/token"

	// tokenExchangeGrant is the RFC 8693 grant type.
	tokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange"
	jwtTokenType       = "urn:ietf:params:oauth:token-type:jwt"
)

// OpenAIExchanger trades an OIDC proof for an OpenAI API access token.
type OpenAIExchanger struct {
	endpoint   string
	httpClient *http.Client
	maxRetries int
	backoff    time.Duration
}

// OpenAIOption configures the exchanger.
type OpenAIOption func(*OpenAIExchanger)

// WithOpenAIEndpoint overrides the token endpoint.
func WithOpenAIEndpoint(url string) OpenAIOption {
	return func(e *OpenAIExchanger) { e.endpoint = url }
}

// WithOpenAIHTTPClient overrides the HTTP client.
func WithOpenAIHTTPClient(c *http.Client) OpenAIOption {
	return func(e *OpenAIExchanger) { e.httpClient = c }
}

// NewOpenAIExchanger builds the exchanger.
func NewOpenAIExchanger(opts ...OpenAIOption) *OpenAIExchanger {
	e := &OpenAIExchanger{
		endpoint:   DefaultOpenAIEndpoint,
		httpClient: httpx.NewSTSClient(defaultExchangeTimeout),
		maxRetries: defaultMaxRetries,
		backoff:    defaultBackoff,
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Exchange performs the RFC 8693 token exchange against OpenAI.
func (e *OpenAIExchanger) Exchange(ctx context.Context, tok *core.SourceToken, target core.Target) (*core.Credentials, error) {
	if tok == nil {
		return nil, fmt.Errorf("openai: a source proof is required")
	}
	if tok.Kind != core.OIDC {
		return nil, fmt.Errorf("%w: OpenAI verifies a signed JWT against the registered provider's "+
			"JWKS, but the source produced a %s proof. On AWS, enable outbound identity federation "+
			"(iam:EnableOutboundWebIdentityFederation) so EC2, ECS and Lambda can mint a real OIDC "+
			"token; failing that, use an OIDC-native source such as EKS IRSA or GitHub Actions",
			core.ErrNoFirstClassPath, tok.Kind)
	}
	t, ok := target.(core.OpenAITarget)
	if !ok {
		return nil, fmt.Errorf("openai: expected an OpenAITarget, got %T", target)
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	if err := checkAudienceBinding(tok, t.Audience()); err != nil {
		return nil, fmt.Errorf("openai: %w", err)
	}

	// JSON, not form-encoded. A scope in the request grants nothing: permissions come from the mapping.
	encoded, err := json.Marshal(map[string]string{
		"grant_type":           tokenExchangeGrant,
		"subject_token_type":   jwtTokenType,
		"subject_token":        tok.Reveal(),
		"identity_provider_id": t.IdentityProviderID,
		"service_account_id":   t.ServiceAccountID,
	})
	if err != nil {
		return nil, fmt.Errorf("openai: encoding the exchange request: %w", err)
	}

	raw, _, err := doWithRetry(ctx, e.httpClient, e.maxRetries, e.backoff,
		func() (*http.Request, error) {
			req, rerr := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, strings.NewReader(string(encoded)))
			if rerr != nil {
				return nil, rerr
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json")
			return req, nil
		})
	if err != nil {
		return nil, annotateOpenAIError(err)
	}

	var out struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		ExpiresAt   int64  `json:"expires_at"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("openai: decoding the exchange response: %w", err)
	}
	if out.AccessToken == "" {
		return nil, fmt.Errorf("openai: the token endpoint returned no access_token")
	}
	// expires_at is the token's own exp claim; expires_in counts from issuance and loses transit time, so prefer the absolute one.
	expiry := time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	if out.ExpiresAt > 0 {
		expiry = time.Unix(out.ExpiresAt, 0)
	}
	return &core.Credentials{Cloud: core.OpenAI, AccessToken: out.AccessToken, Expiry: expiry}, nil
}

// annotateOpenAIError names the two documented error codes, which point at different configuration.
func annotateOpenAIError(err error) error {
	var he *httpError
	if !errors.As(err, &he) {
		return err
	}
	body := string(he.body)
	scrubbed := redact.Body(body, 512)
	switch {
	case strings.Contains(body, "invalid_grant"):
		return fmt.Errorf("openai: the provider or mapping rejected this identity (invalid_grant). "+
			"The mapping for this provider and service account must exist, be enabled, and its "+
			"attribute conditions must match the token's claims (sub is the usual key): %s", scrubbed)
	case strings.Contains(body, "invalid_subject_token"):
		return fmt.Errorf("openai: the identity token was rejected (invalid_subject_token). Check "+
			"iss and aud against the Workload Identity Provider (aud is normally %s), that the JWT "+
			"carries kid and alg, and that the provider's JWKS covers the signing key: %s",
			core.DefaultOpenAIAudience, scrubbed)
	case he.status == http.StatusUnauthorized, he.status == http.StatusForbidden:
		return fmt.Errorf("openai: the token endpoint refused the proof (HTTP %d): %s", he.status, scrubbed)
	default:
		return fmt.Errorf("openai: token exchange failed: %w", err)
	}
}
