package source

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/internal/httpx"
)

// GitHub namespace liveness.

const (
	githubAPI            = "https://api.github.com"
	githubResolveTimeout = 10 * time.Second
)

// GitHubNamespaceResolver classifies GitHub org/repo namespaces.
type GitHubNamespaceResolver struct {
	http    *http.Client
	baseURL string
	token   string
	// ourOwners are the organisations and users this operator controls.
	ourOwners map[string]bool
}

// GitHubNamespaceOption configures the resolver.
type GitHubNamespaceOption func(*GitHubNamespaceResolver)

// WithGitHubAPI overrides the API base. For tests.
func WithGitHubAPI(base string) GitHubNamespaceOption {
	return func(r *GitHubNamespaceResolver) { r.baseURL = strings.TrimRight(base, "/") }
}

// WithGitHubNamespaceHTTPClient overrides the HTTP client.
func WithGitHubNamespaceHTTPClient(c *http.Client) GitHubNamespaceOption {
	return func(r *GitHubNamespaceResolver) { r.http = c }
}

// WithGitHubToken sets the API token.
func WithGitHubToken(t string) GitHubNamespaceOption {
	return func(r *GitHubNamespaceResolver) { r.token = t }
}

// WithOurGitHubOwners names the organisations and users this operator controls.
func WithOurGitHubOwners(owners ...string) GitHubNamespaceOption {
	return func(r *GitHubNamespaceResolver) {
		r.ourOwners = map[string]bool{}
		for _, o := range owners {
			r.ourOwners[strings.ToLower(o)] = true
		}
	}
}

// NewGitHubNamespaceResolver builds the resolver.
func NewGitHubNamespaceResolver(opts ...GitHubNamespaceOption) *GitHubNamespaceResolver {
	r := &GitHubNamespaceResolver{
		http:    httpx.NewSTSClient(githubResolveTimeout),
		baseURL: githubAPI,
		token:   os.Getenv("GITHUB_TOKEN"),
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Issuer implements core.NamespaceResolver.
func (r *GitHubNamespaceResolver) Issuer() string {
	return "https://token.actions.githubusercontent.com"
}

// Resolve classifies a "<owner>/<repo>" or "<owner>" namespace.
func (r *GitHubNamespaceResolver) Resolve(ctx context.Context, namespace string) (core.NamespaceState, string, error) {
	// An immutable subject carries numeric ids: myorg@123456/myrepo@456789. Those are not resolvable names, and they are also the format that CANNOT be silently re-registered — the id is what makes it immutable.
	if strings.Contains(namespace, "@") {
		return core.NamespaceUnknown,
			"immutable subject: the numeric ids pin this to one repository, which is what makes " +
				"re-registration impossible", nil
	}

	path := "/repos/" + namespace
	if !strings.Contains(namespace, "/") {
		path = "/orgs/" + namespace
	}

	status, err := r.head(ctx, path)
	if err != nil {
		return core.NamespaceUnknown, "", err
	}

	switch status {
	case http.StatusNotFound:
		return core.NamespaceUnregistered,
			"this namespace does not exist on GitHub: anyone can register it and mint a token " +
				"whose sub matches this trust exactly", nil
	case http.StatusOK:
		owner, _, _ := strings.Cut(namespace, "/")
		if len(r.ourOwners) == 0 {
			return core.NamespaceUnknown,
				"exists, but whether it is yours was not checked — pass --github-owner to " +
					"distinguish your namespaces from a stranger's", nil
		}
		if r.ourOwners[strings.ToLower(owner)] {
			return core.NamespaceLive, "", nil
		}
		return core.NamespaceNotOurs,
			fmt.Sprintf("%q is not one of your organisations: whoever controls it can mint a token "+
				"this trust accepts", owner), nil
	case http.StatusForbidden, http.StatusUnauthorized:
		// A private repository of somebody else's is indistinguishable from a nonexistent one without access, so this must not read as either.
		return core.NamespaceUnknown,
			"the GitHub API refused the lookup: set GITHUB_TOKEN, or this namespace is private", nil
	default:
		return core.NamespaceUnknown, fmt.Sprintf("GitHub API returned HTTP %d", status), nil
	}
}

// head issues a HEAD request and returns the status.
func (r *GitHubNamespaceResolver) head(ctx context.Context, path string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, r.baseURL+path, nil)
	if err != nil {
		return 0, fmt.Errorf("github: building the lookup: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}

	resp, err := r.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("github: resolving %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, nil
}
