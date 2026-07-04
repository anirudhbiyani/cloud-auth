package te

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

const (
	// DefaultGCPSTSEndpoint is the GCP Security Token Service (RFC 8693).
	DefaultGCPSTSEndpoint = "https://sts.googleapis.com/v1/token"
	// DefaultGCPIAMEndpoint is the IAM Credentials API for SA impersonation.
	DefaultGCPIAMEndpoint = "https://iamcredentials.googleapis.com"

	gcpScope             = "https://www.googleapis.com/auth/cloud-platform"
	subjectTypeJWT       = "urn:ietf:params:oauth:token-type:jwt"
	subjectTypeAWS4      = "urn:ietf:params:aws:token-type:aws4_request"
	grantTypeTokenExch   = "urn:ietf:params:oauth:grant-type:token-exchange"
	requestedTokenAccess = "urn:ietf:params:oauth:token-type:access_token"
)

// GCPExchanger exchanges a source proof for GCP credentials via Workload
// Identity Federation. It defaults to direct resource access (the returned
// federated token is used directly) and only performs service-account
// impersonation when Target.ImpersonateServiceAccount is set.
type GCPExchanger struct {
	stsEndpoint string
	iamEndpoint string
	httpClient  *http.Client
	maxRetries  int
	backoff     time.Duration
}

// GCPExchangerOption configures a GCPExchanger.
type GCPExchangerOption func(*GCPExchanger)

func WithGCPSTSEndpoint(u string) GCPExchangerOption {
	return func(e *GCPExchanger) { e.stsEndpoint = u }
}
func WithGCPIAMEndpoint(u string) GCPExchangerOption {
	return func(e *GCPExchanger) { e.iamEndpoint = u }
}
func WithGCPHTTPClient(h *http.Client) GCPExchangerOption {
	return func(e *GCPExchanger) { e.httpClient = h }
}

// NewGCPExchanger builds a GCPExchanger with defaults.
func NewGCPExchanger(opts ...GCPExchangerOption) *GCPExchanger {
	e := &GCPExchanger{
		stsEndpoint: DefaultGCPSTSEndpoint,
		iamEndpoint: DefaultGCPIAMEndpoint,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
		maxRetries:  2,
		backoff:     100 * time.Millisecond,
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

func subjectTokenType(k cloudauth.Kind) string {
	if k == cloudauth.AWSSigV4 {
		return subjectTypeAWS4
	}
	return subjectTypeJWT
}

// Exchange performs the RFC 8693 token exchange, then optional impersonation.
func (e *GCPExchanger) Exchange(ctx context.Context, tok *cloudauth.SourceToken, target cloudauth.Target) (*cloudauth.Credentials, error) {
	audience := target.Audience
	if audience == "" {
		audience = target.WorkloadIdentityPool
	}
	form := url.Values{
		"grant_type":           {grantTypeTokenExch},
		"audience":             {audience},
		"scope":                {gcpScope},
		"requested_token_type": {requestedTokenAccess},
		"subject_token":        {tok.Value},
		"subject_token_type":   {subjectTokenType(tok.Kind)},
	}
	body, status, err := doWithRetry(ctx, e.httpClient, e.maxRetries, e.backoff, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.stsEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req, nil
	})
	if err != nil {
		return nil, e.classify(status, err)
	}

	var sts struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &sts); err != nil {
		return nil, fmt.Errorf("gcp: parsing STS response: %w", err)
	}
	federated := &cloudauth.Credentials{
		Cloud:       cloudauth.GCP,
		AccessToken: sts.AccessToken,
		Expiry:      time.Now().Add(time.Duration(sts.ExpiresIn) * time.Second),
	}
	if target.ImpersonateServiceAccount == "" {
		return federated, nil // direct resource access (recommended default)
	}
	return e.impersonate(ctx, sts.AccessToken, target.ImpersonateServiceAccount)
}

// impersonate exchanges the federated token for a service-account access token.
func (e *GCPExchanger) impersonate(ctx context.Context, federatedToken, sa string) (*cloudauth.Credentials, error) {
	endpoint := fmt.Sprintf("%s/v1/projects/-/serviceAccounts/%s:generateAccessToken", e.iamEndpoint, sa)
	reqBody := fmt.Sprintf(`{"scope":[%q]}`, gcpScope)
	body, status, err := doWithRetry(ctx, e.httpClient, e.maxRetries, e.backoff, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(reqBody))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+federatedToken)
		return req, nil
	})
	if err != nil {
		return nil, e.classify(status, err)
	}
	var out struct {
		AccessToken string `json:"accessToken"`
		ExpireTime  string `json:"expireTime"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("gcp: parsing generateAccessToken response: %w", err)
	}
	exp, _ := time.Parse(time.RFC3339, out.ExpireTime)
	return &cloudauth.Credentials{Cloud: cloudauth.GCP, AccessToken: out.AccessToken, Expiry: exp}, nil
}

func (e *GCPExchanger) classify(status int, err error) error {
	var he *httpError
	if !asHTTPError(err, &he) {
		return fmt.Errorf("gcp: exchange failed: %w", err)
	}
	if status == http.StatusBadRequest || status == http.StatusUnauthorized || status == http.StatusForbidden {
		return fmt.Errorf("gcp: STS rejected the exchange (status %d): %s: %w", status, he.body, cloudauth.ErrTrustMissing)
	}
	return fmt.Errorf("gcp: STS error (status %d): %s", status, he.body)
}
