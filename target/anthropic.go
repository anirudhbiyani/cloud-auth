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

// The Claude Platform as a federation target.

const (
	// DefaultAnthropicEndpoint is the Claude Platform token endpoint.
	DefaultAnthropicEndpoint = "https://api.anthropic.com/v1/oauth/token"

	// jwtBearerGrant is the RFC 7523 grant type.
	jwtBearerGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

// AnthropicExchanger trades an OIDC proof for a Claude Platform access token.
type AnthropicExchanger struct {
	endpoint   string
	httpClient *http.Client
	maxRetries int
	backoff    time.Duration
}

// AnthropicOption configures the exchanger.
type AnthropicOption func(*AnthropicExchanger)

// WithAnthropicEndpoint overrides the token endpoint.
func WithAnthropicEndpoint(url string) AnthropicOption {
	return func(e *AnthropicExchanger) { e.endpoint = url }
}

// WithAnthropicHTTPClient overrides the HTTP client.
func WithAnthropicHTTPClient(c *http.Client) AnthropicOption {
	return func(e *AnthropicExchanger) { e.httpClient = c }
}

// NewAnthropicExchanger builds the exchanger.
func NewAnthropicExchanger(opts ...AnthropicOption) *AnthropicExchanger {
	e := &AnthropicExchanger{
		endpoint:   DefaultAnthropicEndpoint,
		httpClient: httpx.NewSTSClient(defaultExchangeTimeout),
		maxRetries: defaultMaxRetries,
		backoff:    defaultBackoff,
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Exchange performs the jwt-bearer grant against the Claude Platform.
func (e *AnthropicExchanger) Exchange(ctx context.Context, tok *core.SourceToken, target core.Target) (*core.Credentials, error) {
	if tok == nil {
		return nil, fmt.Errorf("anthropic: a source proof is required")
	}
	if tok.Kind != core.OIDC {
		return nil, fmt.Errorf("%w: the Claude Platform verifies a signed JWT against an issuer's "+
			"JWKS, but the source produced a %s proof. On AWS, enable outbound identity federation "+
			"for the account (iam:EnableOutboundWebIdentityFederation) so EC2, ECS and Lambda can "+
			"mint a real OIDC token via sts:GetWebIdentityToken; failing that, use an OIDC-native "+
			"source such as EKS IRSA or GitHub Actions", core.ErrNoFirstClassPath, tok.Kind)
	}
	t, ok := target.(core.AnthropicTarget)
	if !ok {
		return nil, fmt.Errorf("anthropic: expected an AnthropicTarget, got %T", target)
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}

	// The proof must be pinned to the audience this target names, checked before it leaves the process.
	if err := checkAudienceBinding(tok, t.Audience()); err != nil {
		return nil, fmt.Errorf("anthropic: %w", err)
	}

	// JSON, not form-encoded.
	body := map[string]string{
		"grant_type":         jwtBearerGrant,
		"assertion":          tok.Reveal(),
		"federation_rule_id": t.FederationRuleID,
		"organization_id":    t.OrganizationID,
		"service_account_id": t.ServiceAccountID,
	}
	if t.WorkspaceID != "" {
		body["workspace_id"] = t.WorkspaceID
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("anthropic: encoding the exchange request: %w", err)
	}

	raw, status, err := doWithRetry(ctx, e.httpClient, e.maxRetries, e.backoff,
		func() (*http.Request, error) {
			req, rerr := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint,
				strings.NewReader(string(encoded)))
			if rerr != nil {
				return nil, rerr
			}
			// JSON, not form-encoded.
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json")
			return req, nil
		})
	if err != nil {
		return nil, annotateAnthropicError(err)
	}
	_ = status

	// RFC 6749 §5.1.
	var out struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("anthropic: decoding the exchange response: %w", err)
	}
	if out.AccessToken == "" {
		return nil, fmt.Errorf("anthropic: the token endpoint returned no access_token")
	}

	return &core.Credentials{
		Cloud: core.Anthropic,
		// The bearer-token field, as GCP and Azure use: the credential IS the token and goes in an Authorization header, not an access-key triple.
		AccessToken: out.AccessToken,
		Expiry:      time.Now().Add(time.Duration(out.ExpiresIn) * time.Second),
	}, nil
}

// annotateAnthropicError names the failures that are not guessable from the raw response, and that an operator will actually hit.
func annotateAnthropicError(err error) error {
	var he *httpError
	if !errors.As(err, &he) {
		return err
	}
	scrubbed := redact.Body(string(he.body), 512)

	// A JWT carrying a jti is single-use by default: re-presenting one fails.
	if strings.Contains(string(he.body), "jti_reused") {
		return fmt.Errorf("anthropic: this identity token was already exchanged (jti_reused). "+
			"Identity tokens carrying a jti claim are single-use, so every exchange needs a FRESH "+
			"JWT — a retry loop or a cached proof is the usual cause. cloud-auth mints one per "+
			"exchange; if you are caching the source proof yourself, stop: %w", err)
	}

	switch he.status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("anthropic: the token endpoint refused the proof (HTTP %d). The "+
			"federation rule is matched by ID and never searched, so check that THIS rule's "+
			"conditions accept this token's issuer, subject and audience: %s",
			he.status, scrubbed)
	case http.StatusNotFound:
		return fmt.Errorf("anthropic: the federation rule or service account was not found "+
			"(HTTP %d). Both are named by id, and a rule id from another organization reads "+
			"exactly the same way: %s", he.status, scrubbed)
	default:
		return fmt.Errorf("anthropic: token exchange failed: %w", err)
	}
}
