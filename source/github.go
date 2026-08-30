package source

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/internal/httpx"
	"github.com/anirudhbiyani/cloud-auth/internal/jwt"
)

// GitHub Actions as a source of identity.
//
// Detection covered eleven CLOUD runtimes and zero CI platforms, so
// `cloud-auth exchange` inside a GitHub Actions runner probed AWS, GCP and
// Azure metadata, failed all three, and reported "no supported runtime
// detected" — for the use case this project's README opens with.
//
// CI→cloud is the overwhelming majority of observable demand for this category.
// The cloud→cloud case the runtime half was built for is real, and narrow.

const (
	// requestURLEnv and requestTokenEnv are injected by the Actions runner when
	// a workflow or job grants `id-token: write`. Both are present or neither
	// is; the runner does not set one alone.
	requestURLEnv   = "ACTIONS_ID_TOKEN_REQUEST_URL"
	requestTokenEnv = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"

	// githubMintTimeout bounds the token request. The endpoint is on the
	// runner's own network path and answers in milliseconds.
	githubMintTimeout = 10 * time.Second
)

// GitHub mints OIDC tokens from the Actions runner's token endpoint.
type GitHub struct {
	httpClient *http.Client
	getenv     func(string) string
}

// GitHubOption configures a GitHub provider.
type GitHubOption func(*GitHub)

// WithGitHubHTTPClient overrides the HTTP client.
func WithGitHubHTTPClient(c *http.Client) GitHubOption {
	return func(g *GitHub) { g.httpClient = c }
}

// WithGitHubEnv overrides environment lookup.
func WithGitHubEnv(f func(string) string) GitHubOption {
	return func(g *GitHub) { g.getenv = f }
}

// NewGitHub builds the GitHub Actions source provider.
func NewGitHub(opts ...GitHubOption) *GitHub {
	g := &GitHub{
		// The STS client, NOT the metadata client. This endpoint is a normal
		// internet address that a corporate egress proxy legitimately handles —
		// the metadata client sets Proxy: nil deliberately, because a metadata
		// address must never be proxied, and that reasoning does not apply here.
		httpClient: httpx.NewSTSClient(githubMintTimeout),
		getenv:     os.Getenv,
	}
	for _, o := range opts {
		o(g)
	}
	return g
}

// Name identifies the provider.
func (g *GitHub) Name() string { return "github-actions" }

// Detect reports whether this process is a GitHub Actions job that may request
// an OIDC token.
//
// Both variables or neither. GITHUB_ACTIONS alone is not enough: it is set in
// every workflow, including the ones without `id-token: write`, and detecting
// on it would claim a runtime this provider then cannot mint for — turning a
// clear "permission not granted" into "detection succeeded, mint failed".
func (g *GitHub) Detect(_ context.Context) (*core.Runtime, error) {
	requestURL := strings.TrimSpace(g.getenv(requestURLEnv))
	requestToken := strings.TrimSpace(g.getenv(requestTokenEnv))

	if requestURL == "" || requestToken == "" {
		if g.getenv("GITHUB_ACTIONS") == "true" && requestURL == "" && requestToken == "" {
			// Running in Actions, but the token endpoint was not injected. Say
			// which permission is missing rather than "not this runtime": this
			// is the single most common setup mistake, and the raw failure is
			// opaque.
			return nil, fmt.Errorf("%w: this is a GitHub Actions job, but %s is not set — the "+
				"workflow or job needs `permissions: id-token: write`. A workflow that sets any "+
				"`permissions:` block must list id-token explicitly, because naming any permission "+
				"drops every default",
				core.ErrRuntimeNotConfigured, requestURLEnv)
		}
		return nil, fmt.Errorf("%w: %s and %s are not both set",
			core.ErrNotThisRuntime, requestURLEnv, requestTokenEnv)
	}

	rt := &core.Runtime{
		Cloud: core.GitHubOIDC,
		// "actions", not "github-actions": source.detect splits cloud from
		// sub-runtime on "-", so the operator writes "github-actions" and the
		// selector holds {github, actions}. Naming the sub-runtime
		// "github-actions" would make the config value "github-github-actions".
		SubRuntime:  "actions",
		Federatable: true,
		Issuer:      "https://token.actions.githubusercontent.com",
		Subject:     g.subjectFromEnv(),
	}
	return rt, nil
}

// subjectFromEnv reconstructs the sub claim from the runner's environment.
//
// Best-effort and advisory only: doctor shows it before any token is minted, so
// an operator can compare it against a trust policy without granting anything.
// The authoritative value is the one in the minted token, and Mint overwrites
// this from the token it actually receives.
//
// GitHub's sub is a POSITIONAL concatenation, and environment REPLACES ref
// rather than joining it — the trap detectExplain names.
func (g *GitHub) subjectFromEnv() string {
	repo := g.getenv("GITHUB_REPOSITORY")
	if repo == "" {
		return ""
	}
	if env := g.getenv("GITHUB_ENVIRONMENT"); env != "" {
		return fmt.Sprintf("repo:%s:environment:%s", repo, env)
	}
	if ref := g.getenv("GITHUB_REF"); ref != "" {
		return fmt.Sprintf("repo:%s:ref:%s", repo, ref)
	}
	return "repo:" + repo
}

// Mint requests an OIDC token for the given audience.
func (g *GitHub) Mint(ctx context.Context, audience string) (*core.SourceToken, error) {
	if audience == "" {
		return nil, fmt.Errorf("github: audience is required")
	}
	requestURL := strings.TrimSpace(g.getenv(requestURLEnv))
	requestToken := strings.TrimSpace(g.getenv(requestTokenEnv))
	if requestURL == "" || requestToken == "" {
		return nil, fmt.Errorf("%w: %s and %s are not both set",
			core.ErrNotThisRuntime, requestURLEnv, requestTokenEnv)
	}

	// The runner supplies the URL with its own query already attached, so the
	// audience is appended rather than replacing what is there.
	endpoint, err := appendAudience(requestURL, audience)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("github: building the token request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+requestToken)
	req.Header.Set("Accept", "application/json; api-version=2.0")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: requesting an OIDC token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("github: reading the token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, mintHTTPError(resp.StatusCode)
	}

	var payload struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("github: decoding the token response: %w", err)
	}
	if payload.Value == "" {
		return nil, fmt.Errorf("github: the token endpoint returned an empty token")
	}

	claims, err := jwt.ParseUnverified(payload.Value)
	if err != nil {
		// Fail closed. A token this code cannot read is one whose audience it
		// cannot check, and handing it onward unchecked is exactly the
		// disclosure the audience binding exists to prevent.
		return nil, fmt.Errorf("github: parsing the minted token: %w", err)
	}
	if !claims.HasAudience(audience) {
		return nil, fmt.Errorf("github: refusing to use a token minted for %v, not %q; "+
			"transmitting a proof to a party it was not bound to is a disclosure whether or not "+
			"the exchange succeeds", claims.Audiences, audience)
	}

	return &core.SourceToken{
		Kind:     core.OIDC,
		Value:    payload.Value,
		Issuer:   claims.Issuer,
		Subject:  claims.Subject,
		Audience: audience,
		Expiry:   claims.Expiry,
	}, nil
}

// appendAudience adds the audience to the runner-supplied URL.
func appendAudience(raw, audience string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("github: %s is not a URL: %w", requestURLEnv, err)
	}
	q := u.Query()
	q.Set("audience", audience)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// mintHTTPError turns the endpoint's status into something actionable.
//
// The raw failure is opaque, and the overwhelmingly common cause of each of
// these is a specific, fixable mistake.
func mintHTTPError(status int) error {
	switch status {
	case http.StatusForbidden, http.StatusUnauthorized:
		return fmt.Errorf("github: the token endpoint refused the request (HTTP %d) — the workflow "+
			"or job needs `permissions: id-token: write`. A workflow that sets any `permissions:` "+
			"block must list id-token explicitly, because naming any permission drops every "+
			"default", status)
	case http.StatusBadRequest:
		return fmt.Errorf("github: the token endpoint rejected the request (HTTP %d) — most often "+
			"an audience the workflow is not allowed to request", status)
	default:
		return fmt.Errorf("github: the token endpoint returned HTTP %d", status)
	}
}
