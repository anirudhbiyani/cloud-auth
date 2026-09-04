package source

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// `cloud-auth exchange` inside a GitHub Actions runner probed AWS, GCP and
// Azure metadata, failed all three, and reported "no supported runtime
// detected" — for the use case the README opens with.

// githubJWT builds a token carrying the given audience and subject.
func githubJWT(aud, sub string) string {
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	return enc(map[string]any{"alg": "RS256"}) + "." +
		enc(map[string]any{
			"iss": "https://token.actions.githubusercontent.com",
			"sub": sub, "aud": aud, "exp": 9999999999,
		}) + ".sig"
}

// runnerEndpoint stands in for the Actions token endpoint.
type runnerEndpoint struct {
	server   *httptest.Server
	gotAuth  string
	gotQuery string
	status   int
	token    string
}

func newRunnerEndpoint(t *testing.T, token string) *runnerEndpoint {
	t.Helper()
	r := &runnerEndpoint{status: http.StatusOK, token: token}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.gotAuth = req.Header.Get("Authorization")
		r.gotQuery = req.URL.RawQuery
		if r.status != http.StatusOK {
			w.WriteHeader(r.status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": r.token})
	}))
	t.Cleanup(r.server.Close)
	return r
}

// runnerEnv is the environment the Actions runner injects.
func runnerEnv(url string, extra map[string]string) map[string]string {
	env := map[string]string{
		"ACTIONS_ID_TOKEN_REQUEST_URL":   url,
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "runner-bearer-token",
		"GITHUB_ACTIONS":                 "true",
		"GITHUB_REPOSITORY":              "myorg/myrepo",
		"GITHUB_REF":                     "refs/heads/main",
	}
	for k, v := range extra {
		env[k] = v
	}
	return env
}

func TestGitHubDetect(t *testing.T) {
	t.Run("both variables present", func(t *testing.T) {
		g := NewGitHub(WithGitHubEnv(envFunc(runnerEnv("https://runner.example/token", nil))))
		rt, err := g.Detect(context.Background())
		if err != nil {
			t.Fatalf("Detect: %v", err)
		}
		if rt.Cloud != core.GitHubOIDC {
			t.Errorf("Cloud = %q, want %q", rt.Cloud, core.GitHubOIDC)
		}
		// "actions", not "github-actions": source.detect splits cloud from
		// sub-runtime on "-", so the config value is "github-actions" and
		// naming the sub-runtime that would make it "github-github-actions".
		if rt.SubRuntime != "actions" {
			t.Errorf("SubRuntime = %q, want actions", rt.SubRuntime)
		}
		if !rt.Federatable {
			t.Error("a GitHub Actions job with id-token:write is federatable")
		}
		if rt.Subject != "repo:myorg/myrepo:ref:refs/heads/main" {
			t.Errorf("Subject = %q", rt.Subject)
		}
	})

	t.Run("environment replaces ref, it does not join it", func(t *testing.T) {
		// GitHub's sub is a positional concatenation. Reconstructing it as
		// repo:…:ref:…:environment:… would show an operator a subject that no
		// token ever carries.
		g := NewGitHub(WithGitHubEnv(envFunc(runnerEnv("https://runner.example/token",
			map[string]string{"GITHUB_ENVIRONMENT": "production"}))))
		rt, err := g.Detect(context.Background())
		if err != nil {
			t.Fatalf("Detect: %v", err)
		}
		if rt.Subject != "repo:myorg/myrepo:environment:production" {
			t.Errorf("Subject = %q, want the environment form with no ref segment", rt.Subject)
		}
	})

	t.Run("not GitHub Actions at all", func(t *testing.T) {
		g := NewGitHub(WithGitHubEnv(envFunc(map[string]string{})))
		_, err := g.Detect(context.Background())
		if !errors.Is(err, core.ErrNotThisRuntime) {
			t.Fatalf("want ErrNotThisRuntime, got %v", err)
		}
	})

	// The single most common setup mistake, and the raw failure is opaque.
	t.Run("in Actions but id-token:write was not granted", func(t *testing.T) {
		g := NewGitHub(WithGitHubEnv(envFunc(map[string]string{
			"GITHUB_ACTIONS":    "true",
			"GITHUB_REPOSITORY": "myorg/myrepo",
		})))
		_, err := g.Detect(context.Background())
		if !errors.Is(err, core.ErrNotThisRuntime) {
			t.Fatalf("want ErrNotThisRuntime, got %v", err)
		}
		if !strings.Contains(err.Error(), "id-token: write") {
			t.Errorf("the error does not name the missing permission: %v", err)
		}
	})

	// GITHUB_ACTIONS alone must not claim the runtime: it is set in every
	// workflow, including ones without id-token:write, and detecting on it
	// turns "permission not granted" into "detection succeeded, mint failed".
	t.Run("only one of the two variables", func(t *testing.T) {
		g := NewGitHub(WithGitHubEnv(envFunc(map[string]string{
			"ACTIONS_ID_TOKEN_REQUEST_URL": "https://runner.example/token",
		})))
		if _, err := g.Detect(context.Background()); !errors.Is(err, core.ErrNotThisRuntime) {
			t.Fatalf("want ErrNotThisRuntime, got %v", err)
		}
	})
}

func TestGitHubMint(t *testing.T) {
	const audience = "sts.amazonaws.com"
	const subject = "repo:myorg/myrepo:ref:refs/heads/main"

	r := newRunnerEndpoint(t, githubJWT(audience, subject))
	g := NewGitHub(
		WithGitHubHTTPClient(r.server.Client()),
		WithGitHubEnv(envFunc(runnerEnv(r.server.URL+"?api-version=2.0", nil))),
	)

	tok, err := g.Mint(context.Background(), audience)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.Kind != core.OIDC {
		t.Errorf("Kind = %v, want OIDC", tok.Kind)
	}
	if tok.Audience != audience || tok.Subject != subject {
		t.Errorf("token = aud %q sub %q", tok.Audience, tok.Subject)
	}
	if tok.Issuer != "https://token.actions.githubusercontent.com" {
		t.Errorf("Issuer = %q", tok.Issuer)
	}
	if r.gotAuth != "Bearer runner-bearer-token" {
		t.Errorf("Authorization = %q", r.gotAuth)
	}
	// The runner supplies a URL with its own query attached; the audience is
	// appended, not substituted for it.
	if !strings.Contains(r.gotQuery, "audience=sts.amazonaws.com") {
		t.Errorf("query = %q, want the audience in it", r.gotQuery)
	}
	if !strings.Contains(r.gotQuery, "api-version=2.0") {
		t.Errorf("query = %q — the runner's own parameters were dropped", r.gotQuery)
	}
}

// Fail closed. A token bound to a different audience is a proof for somebody
// else, and transmitting it is a disclosure whether or not the exchange
// succeeds — the same rule target/te.go enforces on the way out.
func TestGitHubMintRefusesAnAudienceMismatch(t *testing.T) {
	r := newRunnerEndpoint(t, githubJWT("api://AzureADTokenExchange", "repo:myorg/myrepo:ref:refs/heads/main"))
	g := NewGitHub(
		WithGitHubHTTPClient(r.server.Client()),
		WithGitHubEnv(envFunc(runnerEnv(r.server.URL, nil))),
	)

	_, err := g.Mint(context.Background(), "sts.amazonaws.com")
	if err == nil {
		t.Fatal("want a refusal for a token minted for another audience")
	}
	if !strings.Contains(err.Error(), "disclosure") {
		t.Errorf("the refusal does not explain why it matters: %v", err)
	}
}

// An unparseable token is one whose audience cannot be checked, and handing it
// onward unchecked defeats the check entirely.
func TestGitHubMintFailsClosedOnAnUnreadableToken(t *testing.T) {
	r := newRunnerEndpoint(t, "not-a-jwt")
	g := NewGitHub(
		WithGitHubHTTPClient(r.server.Client()),
		WithGitHubEnv(envFunc(runnerEnv(r.server.URL, nil))),
	)
	if _, err := g.Mint(context.Background(), "sts.amazonaws.com"); err == nil {
		t.Fatal("want an error for a token that cannot be parsed")
	}
}

func TestGitHubMintHTTPErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		errHas string
	}{
		{"forbidden names the permission", http.StatusForbidden, "id-token: write"},
		{"unauthorized names the permission", http.StatusUnauthorized, "id-token: write"},
		{"bad request suggests the audience", http.StatusBadRequest, "audience"},
		{"anything else reports the status", http.StatusInternalServerError, "HTTP 500"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRunnerEndpoint(t, "")
			r.status = tc.status
			g := NewGitHub(
				WithGitHubHTTPClient(r.server.Client()),
				WithGitHubEnv(envFunc(runnerEnv(r.server.URL, nil))),
			)
			_, err := g.Mint(context.Background(), "sts.amazonaws.com")
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), tc.errHas) {
				t.Errorf("error = %q, want it to contain %q", err, tc.errHas)
			}
		})
	}
}

func TestGitHubMintRequiresAnAudience(t *testing.T) {
	g := NewGitHub(WithGitHubEnv(envFunc(runnerEnv("https://runner.example/token", nil))))
	if _, err := g.Mint(context.Background(), ""); err == nil {
		t.Fatal("want an error: a proof must be pinned to something")
	}
}

// GitHub is probed FIRST. Its detection is two environment reads, while the
// cloud probes reach for a metadata endpoint — and a hosted runner IS a virtual
// machine in somebody's cloud, so probing IMDS first spends a timeout on every
// exchange before reaching the answer that was in the environment all along.
func TestGitHubIsProbedFirst(t *testing.T) {
	r := Default()
	if len(r.providers) == 0 {
		t.Fatal("the default registry is empty")
	}
	if _, ok := r.providers[0].(*GitHub); !ok {
		t.Errorf("first provider is %T, want *GitHub", r.providers[0])
	}
}

// source.detect must be able to name it, or an operator cannot pin the runtime
// most workloads actually run in.
func TestSourceDetectAcceptsGitHub(t *testing.T) {
	for _, in := range []string{"github", "github-actions", "github_oidc"} {
		t.Run(in, func(t *testing.T) {
			sel, err := core.ParseSelector(in)
			if err != nil {
				t.Fatalf("ParseSelector(%q): %v", in, err)
			}
			if sel.Cloud != core.GitHubOIDC {
				t.Errorf("Cloud = %q, want %q", sel.Cloud, core.GitHubOIDC)
			}
			// And it must match what Detect actually reports.
			rt := &core.Runtime{Cloud: core.GitHubOIDC, SubRuntime: "actions"}
			if err := sel.Match(rt); err != nil {
				t.Errorf("a selector parsed from %q does not match the detected runtime: %v", in, err)
			}
		})
	}

	t.Run("an unknown sub-runtime is still rejected", func(t *testing.T) {
		if _, err := core.ParseSelector("github-jenkins"); err == nil {
			t.Error("want an error for a sub-runtime this package cannot report")
		}
	})
}

// "You are on this platform and it is switched off" is a different answer from
// "you are not here", and it was being discarded: every provider's reason looked
// alike to the registry's probe loop, so the most actionable one in the tree
// came out as "no supported runtime detected".
func TestRegistryPreservesTheNotConfiguredReason(t *testing.T) {
	inActionsWithoutPermission := envFunc(map[string]string{
		"GITHUB_ACTIONS":    "true",
		"GITHUB_REPOSITORY": "myorg/myrepo",
	})

	// Only the GitHub provider, so nothing else can detect and the fallback
	// message is what gets returned.
	r := NewRegistry(NewGitHub(WithGitHubEnv(inActionsWithoutPermission)))
	_, _, err := r.Detect(context.Background())
	if err == nil {
		t.Fatal("want an error")
	}
	if !errors.Is(err, core.ErrRuntimeNotConfigured) {
		t.Errorf("error does not carry ErrRuntimeNotConfigured: %v", err)
	}
	// It still wraps ErrNotThisRuntime, so the probe loop keeps going: the same
	// host may legitimately have another identity.
	if !errors.Is(err, core.ErrNotThisRuntime) {
		t.Errorf("ErrRuntimeNotConfigured must wrap ErrNotThisRuntime, or probing stops: %v", err)
	}
	if !strings.Contains(err.Error(), "id-token: write") {
		t.Errorf("the actionable detail was lost: %v", err)
	}
}

// A provider that genuinely detects still wins; the preserved reason is a
// fallback, not a short circuit.
func TestNotConfiguredDoesNotPreemptARealDetection(t *testing.T) {
	r := newRunnerEndpoint(t, githubJWT("sts.amazonaws.com", "repo:o/r:ref:refs/heads/main"))

	notConfigured := NewGitHub(WithGitHubEnv(envFunc(map[string]string{
		"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "myorg/myrepo",
	})))
	configured := NewGitHub(
		WithGitHubHTTPClient(r.server.Client()),
		WithGitHubEnv(envFunc(runnerEnv(r.server.URL, nil))),
	)

	_, rt, err := NewRegistry(notConfigured, configured).Detect(context.Background())
	if err != nil {
		t.Fatalf("a later provider detected, so Detect should succeed: %v", err)
	}
	if rt.Cloud != core.GitHubOIDC || rt.SubRuntime != "actions" {
		t.Errorf("runtime = %s/%s", rt.Cloud, rt.SubRuntime)
	}
}
