package target

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
)

// DefaultAWSSTSEndpoint is the global AWS STS endpoint.
const DefaultAWSSTSEndpoint = "https://sts.amazonaws.com"

// AWSExchanger exchanges an OIDC JWT for AWS credentials via
// sts:AssumeRoleWithWebIdentity.
type AWSExchanger struct {
	endpoint   string
	httpClient *http.Client
	maxRetries int
	backoff    time.Duration
}

// AWSExchangerOption configures an AWSExchanger.
type AWSExchangerOption func(*AWSExchanger)

func WithAWSEndpoint(u string) AWSExchangerOption { return func(e *AWSExchanger) { e.endpoint = u } }
func WithAWSHTTPClient(h *http.Client) AWSExchangerOption {
	return func(e *AWSExchanger) { e.httpClient = h }
}
func WithAWSMaxRetries(n int) AWSExchangerOption { return func(e *AWSExchanger) { e.maxRetries = n } }

// NewAWSExchanger builds an AWSExchanger with defaults.
func NewAWSExchanger(opts ...AWSExchangerOption) *AWSExchanger {
	e := &AWSExchanger{
		endpoint:   DefaultAWSSTSEndpoint,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		maxRetries: 2,
		backoff:    100 * time.Millisecond,
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

type stsCredsXML struct {
	AccessKeyID     string `xml:"AssumeRoleWithWebIdentityResult>Credentials>AccessKeyId"`
	SecretAccessKey string `xml:"AssumeRoleWithWebIdentityResult>Credentials>SecretAccessKey"`
	SessionToken    string `xml:"AssumeRoleWithWebIdentityResult>Credentials>SessionToken"`
	Expiration      string `xml:"AssumeRoleWithWebIdentityResult>Credentials>Expiration"`
	RequestID       string `xml:"ResponseMetadata>RequestId"`
}

type stsErrorXML struct {
	Code      string `xml:"Error>Code"`
	Message   string `xml:"Error>Message"`
	RequestID string `xml:"RequestId"`
}

// Exchange performs sts:AssumeRoleWithWebIdentity.
func (e *AWSExchanger) Exchange(ctx context.Context, tok *cloudauth.SourceToken, target cloudauth.Target) (*cloudauth.Credentials, error) {
	if tok.Kind != cloudauth.OIDC {
		return nil, fmt.Errorf("aws: AssumeRoleWithWebIdentity accepts only OIDC tokens, got %s "+
			"(a SigV4 proof cannot be exchanged at AWS)", tok.Kind)
	}
	if target.Role == "" {
		return nil, fmt.Errorf("aws: target role ARN is required")
	}
	form := url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"Version":          {"2011-06-15"},
		"RoleArn":          {target.Role},
		"RoleSessionName":  {"cloud-auth"},
		"WebIdentityToken": {tok.Value},
	}
	body, status, err := doWithRetry(ctx, e.httpClient, e.maxRetries, e.backoff, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/xml")
		return req, nil
	})
	if err != nil {
		return nil, e.classify(status, err)
	}

	var out stsCredsXML
	if err := xml.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("aws: parsing STS response: %w", err)
	}
	exp, _ := time.Parse(time.RFC3339, out.Expiration)
	return &cloudauth.Credentials{
		Cloud:           cloudauth.AWS,
		AccessKeyID:     out.AccessKeyID,
		SecretAccessKey: out.SecretAccessKey,
		SessionToken:    out.SessionToken,
		Expiry:          exp,
		STSRequestID:    out.RequestID,
	}, nil
}

// classify maps STS error responses to the shared error taxonomy.
func (e *AWSExchanger) classify(status int, err error) error {
	var he *httpError
	if !asHTTPError(err, &he) {
		return fmt.Errorf("aws: exchange failed: %w", err)
	}
	var se stsErrorXML
	_ = xml.Unmarshal(he.body, &se)
	switch se.Code {
	case "AccessDenied", "InvalidIdentityToken", "IDPRejectedClaim", "ExpiredTokenException":
		return fmt.Errorf("aws: %s: %s (request-id %s): %w", se.Code, se.Message, se.RequestID, cloudauth.ErrTrustMissing)
	default:
		return fmt.Errorf("aws: STS error %s: %s (status %d)", se.Code, se.Message, status)
	}
}
