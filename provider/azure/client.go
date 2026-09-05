package azure

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
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/anirudhbiyani/cloud-auth/internal/httpx"
	"github.com/anirudhbiyani/cloud-auth/internal/redact"
)

// This file is the concrete client behind provider/azure's interfaces.

const (
	// graphEndpoint is the Microsoft Graph v1.0 base.
	graphEndpoint = "https://graph.microsoft.com/v1.0"
	// armEndpoint is the Azure Resource Manager base.
	armEndpoint = "https://management.azure.com"

	// graphScope and armScope are the token audiences for each surface.
	graphScope = "https://graph.microsoft.com/.default"
	armScope   = "https://management.azure.com/.default"

	// armAPIVersion for user-assigned managed identities and their federated identity credentials.
	armIdentityAPIVersion = "2023-01-31"
	// armRoleAPIVersion for role assignments.
	armRoleAPIVersion = "2022-04-01"

	// requestTimeout bounds a single API call.
	requestTimeout = 30 * time.Second
	// errorBodyLimit caps a retained upstream error body.
	errorBodyLimit = 512
)

// Azure's documented limits on federated identity credentials.
const (
	// maxFederatedCredentials is the hard cap per application object or per user-assigned managed identity.
	maxFederatedCredentials = 20

	// ficCreateInterval is the minimum gap between federated-credential creations on the same resource.
	ficCreateInterval = 4 * time.Second
)

// apiError is a Graph or ARM failure with its status and Entra code preserved.
type apiError struct {
	StatusCode int
	Code       string // e.g. "Request_ResourceNotFound", "AADSTS70021"
	Message    string
	Resource   string
}

func (e *apiError) Error() string {
	name := e.Code
	if name == "" {
		name = http.StatusText(e.StatusCode)
	}
	if e.Resource != "" {
		return fmt.Sprintf("azure: %s on %s: %s", name, e.Resource, e.Message)
	}
	return fmt.Sprintf("azure: %s: %s", name, e.Message)
}

// NotFound reports absence, so Setup's create-or-update decision and the rollback do not have to recover it by matching strings.
func (e *apiError) NotFound() bool {
	return e.StatusCode == http.StatusNotFound ||
		e.Code == "Request_ResourceNotFound" || e.Code == "ResourceNotFound"
}

// Conflict reports that the resource already exists, or that a concurrent create on the same identity lost.
func (e *apiError) Conflict() bool { return e.StatusCode == http.StatusConflict }

// Clients bundles the interfaces a fully wired Azure provider needs.
type Clients struct {
	Graph GraphClient
	ARM   ARMClient
	Token TokenClient
}

// restClient implements the Graph and ARM interfaces.
type restClient struct {
	http       *http.Client
	credential azcore.TokenCredential

	graphURL string
	armURL   string

	// ficPace serializes federated-credential creation.
	ficMu       sync.Mutex
	lastFIC     time.Time
	ficInterval time.Duration

	// now and sleep are injectable so the pacing can be tested without spending real seconds.
	now   func() time.Time
	sleep func(context.Context, time.Duration) error
}

// ClientOption configures the REST client.
type ClientOption func(*restClient)

// WithHTTPClient overrides the HTTP client.
func WithHTTPClient(c *http.Client) ClientOption {
	return func(r *restClient) { r.http = c }
}

// WithCredential overrides credential resolution, skipping DefaultAzureCredential.
func WithCredential(cred azcore.TokenCredential) ClientOption {
	return func(r *restClient) { r.credential = cred }
}

// WithClientEndpoints points the client at alternative bases. For tests.
func WithClientEndpoints(graph, arm string) ClientOption {
	return func(r *restClient) { r.graphURL, r.armURL = graph, arm }
}

// NewClients resolves Azure credentials and returns Graph and ARM clients.
func NewClients(_ context.Context, opts ...ClientOption) (*Clients, error) {
	c := &restClient{
		http:        httpx.NewSTSClient(requestTimeout),
		graphURL:    graphEndpoint,
		armURL:      armEndpoint,
		ficInterval: ficCreateInterval,
		now:         time.Now,
		sleep:       sleepCtx,
	}
	for _, o := range opts {
		o(c)
	}

	if c.credential == nil {
		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("azure: resolving credentials: %w", err)
		}
		c.credential = cred
	}
	return &Clients{Graph: c, ARM: c, Token: c}, nil
}

// sleepCtx waits for d, or until ctx is done.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// do performs one authenticated JSON call against Graph or ARM.
func (c *restClient) do(ctx context.Context, method, endpoint, scope string, body, out any, resource string) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("azure: encoding request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return fmt.Errorf("azure: building request: %w", err)
	}

	tok, err := c.credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{scope}})
	if err != nil {
		return fmt.Errorf("azure: obtaining an access token for %s: %w", scope, err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("azure: %s %s: %w", method, redactedPath(endpoint), err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("azure: reading response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return parseAPIError(resp.StatusCode, raw, resource)
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("azure: decoding response: %w", err)
	}
	return nil
}

// redactedPath keeps scheme, host and path and drops the query.
func redactedPath(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "(unparseable url)"
	}
	return u.Scheme + "://" + u.Host + u.Path
}

// parseAPIError decodes the two error envelopes Azure uses.
func parseAPIError(status int, raw []byte, resource string) error {
	e := &apiError{StatusCode: status, Resource: resource}

	var nested struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &nested); err == nil && (nested.Error.Code != "" || nested.Error.Message != "") {
		e.Code = nested.Error.Code
		e.Message = redact.Body(nested.Error.Message, errorBodyLimit)
		return e
	}

	var oauth struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal(raw, &oauth); err == nil && oauth.Error != "" {
		e.Code = oauth.Error
		e.Message = redact.Body(oauth.Description, errorBodyLimit)
		// Entra puts the actionable identifier inside the description, not the code: every failure here is "invalid_client" or "invalid_request" until you read the AADSTS number.
		if aadsts := extractAADSTS(oauth.Description); aadsts != "" {
			e.Code = aadsts
		}
		return e
	}

	e.Message = redact.Body(strings.TrimSpace(string(raw)), errorBodyLimit)
	if e.Message == "" {
		e.Message = http.StatusText(status)
	}
	return e
}

// extractAADSTS pulls the AADSTSnnnnn identifier out of an Entra description.
func extractAADSTS(description string) string {
	i := strings.Index(description, "AADSTS")
	if i < 0 {
		return ""
	}
	rest := description[i:]
	end := len("AADSTS")
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == len("AADSTS") {
		return ""
	}
	return rest[:end]
}

// readLimited reads a capped response body.
func readLimited(resp *http.Response) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("azure: reading response: %w", err)
	}
	return raw, nil
}

// jsonUnmarshal decodes a response body, wrapping the error with context.
func jsonUnmarshal(raw []byte, out any) error {
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("azure: decoding response: %w", err)
	}
	return nil
}

// asAPIError unwraps err into an *apiError if present.
func asAPIError(err error, target **apiError) bool { return errors.As(err, target) }
