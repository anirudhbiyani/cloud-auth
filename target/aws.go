package target

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/internal/httpx"
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
		httpClient: httpx.NewSTSClient(10 * time.Second),
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
func (e *AWSExchanger) Exchange(ctx context.Context, tok *core.SourceToken, target core.Target) (*core.Credentials, error) {
	// The concrete type carries only AWS's fields, so a caller cannot hand this
	// exchanger an Azure tenant and have it silently ignored.
	t, ok := target.(core.AWSTarget)
	if !ok {
		return nil, fmt.Errorf("aws: expected an AWSTarget, got %T", target)
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	if tok.Kind != core.OIDC {
		return nil, fmt.Errorf("aws: AssumeRoleWithWebIdentity accepts only OIDC tokens, got %s "+
			"(a SigV4 proof cannot be exchanged at AWS)", tok.Kind)
	}
	// AssumeRoleWithWebIdentity carries no audience parameter — the aud claim
	// lives inside the token and IAM checks it against the role's trust policy.
	// That is a check we can also make before the token leaves the process.
	if err := checkAudienceBinding(tok, t.Audience()); err != nil {
		return nil, fmt.Errorf("aws: %w", err)
	}

	form := url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"Version":          {"2011-06-15"},
		"RoleArn":          {t.RoleARN},
		"RoleSessionName":  {sessionName(t, tok)},
		"WebIdentityToken": {tok.Reveal()},
	}
	if t.DurationSeconds != 0 {
		form.Set("DurationSeconds", strconv.Itoa(int(t.DurationSeconds)))
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
		return nil, categorize(err, e.classify(status, err))
	}

	var out stsCredsXML
	if err := xml.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("aws: parsing STS response: %w", err)
	}
	// A 2xx is not proof of credentials. An unexpected body shape unmarshals
	// happily into zero values, and returning those as success hands the caller
	// an empty key that fails much later, somewhere unrelated.
	if out.AccessKeyID == "" || out.SecretAccessKey == "" || out.SessionToken == "" {
		return nil, fmt.Errorf("aws: STS returned %d with no credentials in the body "+
			"(request-id %q)", status, out.RequestID)
	}
	exp, err := time.Parse(time.RFC3339, out.Expiration)
	if err != nil {
		return nil, fmt.Errorf("aws: STS returned an unparseable Expiration %q (request-id %q): %w",
			out.Expiration, out.RequestID, err)
	}
	return &core.Credentials{
		Cloud:           core.AWS,
		AccessKeyID:     out.AccessKeyID,
		SecretAccessKey: out.SecretAccessKey,
		SessionToken:    out.SessionToken,
		Expiry:          exp,
		STSRequestID:    out.RequestID,
	}, nil
}

// sessionName resolves sts:RoleSessionName.
//
// It was previously the constant "cloud-auth", which made every federated
// session in a fleet indistinguishable in CloudTrail and rendered useless the
// common defence of constraining sts:RoleSessionName in the trust policy.
// Deriving it from the proof's subject makes the session attributable to the
// workload that requested it.
func sessionName(t core.AWSTarget, tok *core.SourceToken) string {
	if t.SessionName != "" {
		return sanitizeSessionName(t.SessionName)
	}
	if tok.Subject != "" {
		return sanitizeSessionName(tok.Subject)
	}
	return "cloud-auth"
}

// sanitizeSessionName reduces a value to what AWS accepts for a session name:
// [\w+=,.@-]{2,64}.
func sanitizeSessionName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_' || r == '+' || r == '=' || r == ',' || r == '.' || r == '@' || r == '-':
			b.WriteRune(r)
		default:
			// Subjects are full of ':' and '/'; collapse rather than drop, so
			// distinct subjects do not collide into the same session name.
			b.WriteRune('-')
		}
	}
	out := b.String()
	if len(out) > 64 {
		// Keep the tail: for "repo:org/repo:ref:refs/heads/main" the distinguishing
		// part is at the end.
		out = out[len(out)-64:]
	}
	if len(out) < 2 {
		return "cloud-auth"
	}
	return out
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
		return fmt.Errorf("aws: %s: %s (request-id %s): %w", se.Code, se.Message, se.RequestID, core.ErrTrustMissing)
	default:
		return fmt.Errorf("aws: STS error %s: %s (status %d)", se.Code, se.Message, status)
	}
}
