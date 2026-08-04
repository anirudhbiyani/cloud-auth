package target

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
)

// DefaultAzureEndpoint is the Entra (Azure AD) login authority base.
const DefaultAzureEndpoint = "https://login.microsoftonline.com"

// DefaultAzureScope is the resource scope requested when none is configured.
const DefaultAzureScope = "https://management.azure.com/.default"

// AzureExchanger exchanges an OIDC JWT for an Entra access token via the
// client-credentials grant with a federated client assertion. Azure accepts
// only RS256 OIDC JWTs, so a SigV4 proof (AWS EC2/ECS) has no first-class path
// and is rejected with actionable OIDC-bridge guidance.
type AzureExchanger struct {
	endpoint   string
	scope      string
	httpClient *http.Client
	maxRetries int
	backoff    time.Duration
}

// AzureExchangerOption configures an AzureExchanger.
type AzureExchangerOption func(*AzureExchanger)

func WithAzureEndpoint(u string) AzureExchangerOption {
	return func(e *AzureExchanger) { e.endpoint = u }
}
func WithAzureScope(s string) AzureExchangerOption { return func(e *AzureExchanger) { e.scope = s } }
func WithAzureHTTPClient(h *http.Client) AzureExchangerOption {
	return func(e *AzureExchanger) { e.httpClient = h }
}

// NewAzureExchanger builds an AzureExchanger with defaults.
func NewAzureExchanger(opts ...AzureExchangerOption) *AzureExchanger {
	e := &AzureExchanger{
		endpoint:   DefaultAzureEndpoint,
		scope:      DefaultAzureScope,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		maxRetries: 2,
		backoff:    100 * time.Millisecond,
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Exchange performs the Entra client-credentials grant with a client assertion.
func (e *AzureExchanger) Exchange(ctx context.Context, tok *cloudauth.SourceToken, target cloudauth.Target) (*cloudauth.Credentials, error) {
	if tok.Kind != cloudauth.OIDC {
		return nil, fmt.Errorf("%w: Azure Entra accepts only RS256 OIDC JWTs, but the source produced a "+
			"%s proof. Bridge the AWS EC2/ECS identity to OIDC via one of: Amazon Cognito, an EKS/IRSA "+
			"OIDC source, or a self-hosted OIDC broker", cloudauth.ErrNoFirstClassPath, tok.Kind)
	}
	if target.Tenant == "" || target.ClientID == "" {
		return nil, fmt.Errorf("azure: target tenant and client_id are required")
	}
	endpoint := strings.TrimRight(e.endpoint, "/") + "/" + target.Tenant + "/oauth2/v2.0/token"
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {target.ClientID},
		"scope":                 {e.scope},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {tok.Value},
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
		return nil, e.classify(status, err)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("azure: parsing token response: %w", err)
	}
	return &cloudauth.Credentials{
		Cloud:       cloudauth.Azure,
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
		// Entra returns 400/401 for issuer/subject/audience mismatch (matched
		// case-sensitively) and missing federated credentials.
		return fmt.Errorf("azure: Entra rejected the assertion (status %d): %s "+
			"(check case-sensitive issuer/subject/audience match and the federated identity credential): %w",
			status, he.body, cloudauth.ErrTrustMissing)
	}
	return fmt.Errorf("azure: token endpoint error (status %d): %s", status, he.body)
}
