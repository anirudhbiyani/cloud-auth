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

const (
	// requestURLEnv and requestTokenEnv are injected by the Actions runner when a workflow or job grants `id-token: write`.
	requestURLEnv   = "ACTIONS_ID_TOKEN_REQUEST_URL"
	requestTokenEnv = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"

	// githubMintTimeout bounds the token request.
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
		// The STS client, NOT the metadata client.
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

// Detect reports whether this process is a GitHub Actions job that may request an OIDC token.
func (g *GitHub) Detect(_ context.Context) (*core.Runtime, error) {
	requestURL := strings.TrimSpace(g.getenv(requestURLEnv))
	requestToken := strings.TrimSpace(g.getenv(requestTokenEnv))

	if requestURL == "" || requestToken == "" {
		if g.getenv("GITHUB_ACTIONS") == "true" && requestURL == "" && requestToken == "" {
			// Running in Actions, but the token endpoint was not injected.
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
		// "actions", not "github-actions": source.detect splits cloud from sub-runtime on "-", so the operator writes "github-actions" and the selector holds {github, actions}.
		SubRuntime:  "actions",
		Federatable: true,
		Issuer:      "https://token.actions.githubusercontent.com",
		Subject:     g.subjectFromEnv(),
	}
	return rt, nil
}

// subjectFromEnv reconstructs the sub claim from the runner's environment.
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

	// The runner supplies the URL with its own query already attached, so the audience is appended rather than replacing what is there.
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
		// Fail closed.
		return nil, fmt.Errorf("github: parsing the minted token: %w", err)
	}
	if !claims.HasAudience(audience) {
		return nil, fmt.Errorf("github: refusing to use a token minted for %v, not %q; "+
			"transmitting a proof to a party it was not bound to is a disclosure whether or not "+
			"the exchange succeeds", claims.Audiences, audience)
	}

	return oidcToken(payload.Value, claims, audience), nil
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
