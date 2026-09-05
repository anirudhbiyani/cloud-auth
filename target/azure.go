package target

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/internal/httpx"
	"github.com/anirudhbiyani/cloud-auth/internal/redact"
)

// DefaultAzureEndpoint is the Entra (Azure AD) login authority base.
const DefaultAzureEndpoint = "https://login.microsoftonline.com"

// AzureExchanger exchanges an OIDC JWT for an Entra access token via the client-credentials grant with a federated client assertion.
type AzureExchanger struct {
	endpoint   string
	httpClient *http.Client
	maxRetries int
	backoff    time.Duration
}

// AzureExchangerOption configures an AzureExchanger.
type AzureExchangerOption func(*AzureExchanger)

func WithAzureEndpoint(u string) AzureExchangerOption {
	return func(e *AzureExchanger) { e.endpoint = u }
}
func WithAzureHTTPClient(h *http.Client) AzureExchangerOption {
	return func(e *AzureExchanger) { e.httpClient = h }
}

// NewAzureExchanger builds an AzureExchanger with defaults.
func NewAzureExchanger(opts ...AzureExchangerOption) *AzureExchanger {
	e := &AzureExchanger{
		endpoint:   DefaultAzureEndpoint,
		httpClient: httpx.NewSTSClient(defaultExchangeTimeout),
		maxRetries: defaultMaxRetries,
		backoff:    defaultBackoff,
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Exchange performs the Entra client-credentials grant with a client assertion.
func (e *AzureExchanger) Exchange(ctx context.Context, tok *core.SourceToken, target core.Target) (*core.Credentials, error) {
	if tok.Kind != core.OIDC {
		return nil, fmt.Errorf("%w: Azure Entra accepts only RS256 OIDC JWTs, but the source produced a "+
			"%s proof. On AWS, enable outbound identity federation for the account "+
			"(iam:EnableOutboundWebIdentityFederation) so EC2, ECS and Lambda can mint a real OIDC "+
			"token via sts:GetWebIdentityToken; failing that, use an OIDC-native source such as EKS "+
			"IRSA, or a self-hosted OIDC broker", core.ErrNoFirstClassPath, tok.Kind)
	}
	t, ok := target.(core.AzureTarget)
	if !ok {
		return nil, fmt.Errorf("azure: expected an AzureTarget, got %T", target)
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	// The default Azure audience, api://AzureADTokenExchange, is not bound to a tenant: any tenant holding a federated credential for this issuer and subject will accept the same assertion.
	if err := checkAudienceBinding(tok, t.Audience()); err != nil {
		return nil, fmt.Errorf("azure: %w", err)
	}
	endpoint := strings.TrimRight(e.endpoint, "/") + "/" + url.PathEscape(t.Tenant) + "/oauth2/v2.0/token"
	// The scope comes from the target, which requires it.
	scope := t.Scope
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {t.ClientID},
		"scope":                 {scope},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {tok.Reveal()},
	}
	body, status, err := doWithRetry(ctx, e.httpClient, e.maxRetries, e.backoff, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req, nil
	})
	if err != nil {
		return nil, categorize(err, e.classify(status, err))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("azure: parsing token response: %w", err)
	}
	if out.AccessToken == "" {
		return nil, fmt.Errorf("azure: token endpoint returned %d with no access_token in the body",
			status)
	}
	if out.ExpiresIn <= 0 {
		return nil, fmt.Errorf("azure: token endpoint returned no usable expires_in (%d); refusing "+
			"to cache a token of unknown lifetime", out.ExpiresIn)
	}
	return &core.Credentials{
		Cloud:       core.Azure,
		AccessToken: out.AccessToken,
		Expiry:      time.Now().Add(time.Duration(out.ExpiresIn) * time.Second),
	}, nil
}

func (e *AzureExchanger) classify(status int, err error) error {
	var he *httpError
	if !asHTTPError(err, &he) {
		return fmt.Errorf("azure: exchange failed: %w", err)
	}
	if status == http.StatusBadRequest || status == http.StatusUnauthorized {
		// Entra returns 400/401 for issuer/subject/audience mismatch (matched case-sensitively) and missing federated credentials.
		return fmt.Errorf("azure: Entra rejected the assertion (status %d): %s "+
			"(check case-sensitive issuer/subject/audience match and the federated identity credential): %w",
			status, redact.Body(string(he.body), maxErrorBody), core.ErrTrustMissing)
	}
	return fmt.Errorf("azure: token endpoint error (status %d): %s", status,
		redact.Body(string(he.body), maxErrorBody))
}
