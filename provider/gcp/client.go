package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/anirudhbiyani/cloud-auth/internal/httpx"
	"github.com/anirudhbiyani/cloud-auth/internal/redact"
)

// This file is the concrete client behind provider/gcp's three interfaces.
// Without it the provider could plan what it would do and never do it: every
// non-dry-run setup, validate and delete stopped at "client not configured".
//
// It speaks the IAM v1, STS and IAM Credentials REST APIs directly rather than
// through google.golang.org/api. Those are plain JSON endpoints, the surface
// used here is nine calls wide, and the generated client would pull a large
// dependency tree in for it. Application Default Credentials is the one part
// NOT hand-rolled — service-account key signing, the refresh-token flow, the
// metadata server and impersonation chains are a credential path, and
// x/oauth2/google (already a dependency of this module) implements it correctly.

const (
	// iamEndpoint serves workload identity pools, providers and service accounts.
	iamEndpoint = "https://iam.googleapis.com/v1"
	// stsEndpoint exchanges an external token for a federated access token.
	stsEndpoint = "https://sts.googleapis.com/v1"
	// credentialsEndpoint mints tokens as a service account.
	credentialsEndpoint = "https://iamcredentials.googleapis.com/v1"

	// cloudPlatformScope is the scope the admin calls need.
	cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"

	// requestTimeout bounds a single API call.
	requestTimeout = 30 * time.Second
	// operationTimeout bounds the wait for a long-running operation to finish.
	// Pool and provider creation are LROs; they normally settle in seconds.
	operationTimeout = 2 * time.Minute
	// operationPollInterval is how often a pending operation is re-read.
	operationPollInterval = time.Second

	// errorBodyLimit caps an upstream error body kept for diagnostics. Matches
	// target/te.go's cap: an error is a diagnostic, not a transcript.
	errorBodyLimit = 512
)

// GCP's documented limits on a workload identity pool provider. Checked before
// the call rather than after the rejection: the API's own message names a number
// without saying which of your mappings pushed you past it.
const (
	// maxAttributeMappings is the ceiling on custom attribute mappings.
	maxAttributeMappings = 50
	// maxAttributeMappingBytes is the ceiling on the total mapping expression.
	maxAttributeMappingBytes = 8192
	// maxMappedSubjectBytes is the ceiling on the resolved google.subject. It
	// cannot be checked statically — the value is produced at exchange time by a
	// CEL expression over a token this code has not seen — but a literal mapping
	// can be, and GitHub's immutable subject claims made overflow materially
	// more likely.
	maxMappedSubjectBytes = 127
)

// apiError is a GCP API failure with its status preserved.
//
// isNotFoundError's doc comment records that this package's clients had no typed
// errors, so absence had to be recovered by string matching. This closes that:
// NotFound() is exact, and the category flows into core.CategoryOf.
type apiError struct {
	StatusCode int
	Status     string // GCP's canonical code, e.g. "NOT_FOUND", "ALREADY_EXISTS"
	Message    string
	Resource   string
}

func (e *apiError) Error() string {
	if e.Resource != "" {
		return fmt.Sprintf("gcp: %s on %s: %s", e.statusName(), e.Resource, e.Message)
	}
	return fmt.Sprintf("gcp: %s: %s", e.statusName(), e.Message)
}

func (e *apiError) statusName() string {
	if e.Status != "" {
		return e.Status
	}
	return http.StatusText(e.StatusCode)
}

// NotFound reports absence. isNotFoundError checks for this interface before it
// falls back to matching strings.
func (e *apiError) NotFound() bool {
	return e.StatusCode == http.StatusNotFound || e.Status == "NOT_FOUND"
}

// AlreadyExists reports that the resource is already there, which Setup treats
// as success rather than failure when it was creating idempotently.
func (e *apiError) AlreadyExists() bool {
	return e.StatusCode == http.StatusConflict || e.Status == "ALREADY_EXISTS"
}

// Clients bundles the three interfaces a fully wired GCP provider needs.
type Clients struct {
	IAM      IAMClient
	Workload WorkloadIdentityClient
	STS      STSClient
}

// restClient implements all three interfaces over the REST APIs.
type restClient struct {
	http   *http.Client
	tokens oauth2.TokenSource

	// Endpoints are fields rather than constants so tests can point them at an
	// httptest server. Nothing outside this package sets them.
	iamURL         string
	stsURL         string
	credentialsURL string

	// pollInterval is the LRO poll cadence, shortened by tests.
	pollInterval time.Duration
}

// ClientOption configures the REST client.
type ClientOption func(*restClient)

// WithHTTPClient overrides the HTTP client.
func WithHTTPClient(c *http.Client) ClientOption {
	return func(r *restClient) { r.http = c }
}

// WithTokenSource overrides credential resolution, skipping ADC.
func WithTokenSource(ts oauth2.TokenSource) ClientOption {
	return func(r *restClient) { r.tokens = ts }
}

// WithEndpoints points the client at alternative bases. For tests.
func WithEndpoints(iam, sts, credentials string) ClientOption {
	return func(r *restClient) {
		r.iamURL, r.stsURL, r.credentialsURL = iam, sts, credentials
	}
}

// NewClients resolves Application Default Credentials and returns clients for
// the IAM, Workload Identity and STS surfaces.
func NewClients(ctx context.Context, opts ...ClientOption) (*Clients, error) {
	c := &restClient{
		// Proxy-respecting and redirect-refusing: these are ordinary internet
		// calls a corporate egress proxy legitimately handles, but a redirect
		// from an admin endpoint carrying a bearer token is not something to
		// follow.
		http:           httpx.NewSTSClient(requestTimeout),
		iamURL:         iamEndpoint,
		stsURL:         stsEndpoint,
		credentialsURL: credentialsEndpoint,
		pollInterval:   operationPollInterval,
	}
	for _, o := range opts {
		o(c)
	}

	if c.tokens == nil {
		creds, err := google.FindDefaultCredentials(ctx, cloudPlatformScope)
		if err != nil {
			return nil, fmt.Errorf("gcp: resolving application default credentials: %w", err)
		}
		c.tokens = creds.TokenSource
	}
	return &Clients{IAM: c, Workload: c, STS: c}, nil
}

// do performs one authenticated JSON call and decodes the result into out.
//
// out may be nil for calls whose body is not needed. A non-2xx is turned into
// *apiError with GCP's canonical status preserved, so callers can ask NotFound()
// rather than grep the message.
func (c *restClient) do(ctx context.Context, method, endpoint string, body, out any, resource string) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("gcp: encoding request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return fmt.Errorf("gcp: building request: %w", err)
	}
	tok, err := c.tokens.Token()
	if err != nil {
		return fmt.Errorf("gcp: obtaining an access token: %w", err)
	}
	tok.SetAuthHeader(req)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("gcp: %s %s: %w", method, redactedPath(endpoint), err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Cap the read: an error body is diagnostics, not a payload, and a
	// misdirected endpoint should not be able to stream into memory.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("gcp: reading response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return parseAPIError(resp.StatusCode, raw, resource)
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("gcp: decoding response: %w", err)
	}
	return nil
}

// postUnauthenticated posts JSON without a bearer header.
//
// The STS token endpoint takes no caller credential: the subject token in the
// body IS the proof. Sending an unrelated ADC bearer alongside it would attach a
// second, more privileged identity to a request that does not need one.
func (c *restClient) postUnauthenticated(ctx context.Context, endpoint string, body, out any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("gcp: encoding request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("gcp: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("gcp: POST %s: %w", redactedPath(endpoint), err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("gcp: reading response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// The request body carried an assertion, and STS error bodies echo parts
		// of it back. Scrub before this reaches a log.
		return parseAPIError(resp.StatusCode, []byte(redact.Body(string(raw), errorBodyLimit)), "")
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("gcp: decoding response: %w", err)
	}
	return nil
}

// redactedPath keeps the host and path for diagnostics and drops the query,
// which on these APIs carries resource ids supplied by the operator.
func redactedPath(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "(unparseable url)"
	}
	return u.Scheme + "://" + u.Host + u.Path
}

// parseAPIError turns a non-2xx body into *apiError, falling back to the status
// line when the body is not the shape GCP documents.
func parseAPIError(status int, raw []byte, resource string) error {
	var envelope struct {
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Status  string `json:"status"`
		} `json:"error"`
	}
	e := &apiError{StatusCode: status, Resource: resource}
	if err := json.Unmarshal(raw, &envelope); err == nil && envelope.Error.Message != "" {
		e.Message = envelope.Error.Message
		e.Status = envelope.Error.Status
		return e
	}
	e.Message = strings.TrimSpace(string(raw))
	if e.Message == "" {
		e.Message = http.StatusText(status)
	}
	return e
}

// operation is the long-running-operation envelope the IAM API returns for pool
// and provider mutations.
type operation struct {
	Name  string          `json:"name"`
	Done  bool            `json:"done"`
	Error *operationError `json:"error,omitempty"`
	// Response is the created resource once Done. Left raw so each caller
	// decodes its own type.
	Response json.RawMessage `json:"response,omitempty"`
}

type operationError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

// await polls a long-running operation to completion and decodes its response.
//
// Returning as soon as the API accepts the request would be wrong here: Setup's
// next step binds IAM to the pool it just asked for, and a pool that is still
// being created is not yet a valid principal set. The failure would surface as a
// confusing permission error one call later.
func (c *restClient) await(ctx context.Context, op *operation, out any) error {
	deadline := time.Now().Add(operationTimeout)
	// Poll the name from the FIRST response throughout. A poll response is only
	// ever the same operation, so following a name out of a later body would let
	// one malformed or truncated reply redirect the wait somewhere else.
	name := op.Name
	for {
		if op.Done {
			if op.Error != nil {
				return &apiError{
					StatusCode: http.StatusInternalServerError,
					Status:     op.Error.Status,
					Message:    op.Error.Message,
				}
			}
			if out != nil && len(op.Response) > 0 {
				if err := json.Unmarshal(op.Response, out); err != nil {
					return fmt.Errorf("gcp: decoding operation response: %w", err)
				}
			}
			return nil
		}
		if name == "" {
			return errors.New("gcp: operation is not done and carries no name to poll")
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("gcp: operation %s did not complete within %s", name, operationTimeout)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(c.pollInterval):
		}

		var next operation
		if err := c.do(ctx, http.MethodGet, c.iamURL+"/"+name, nil, &next, name); err != nil {
			return err
		}
		op = &next
	}
}
