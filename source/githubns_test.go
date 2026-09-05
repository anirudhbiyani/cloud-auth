package source

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// GitHub runs ONE issuer across every account and permits namespace reuse: delete an org, someone re-registers the name, mints a token whose sub is character-for-character identical, and assumes a role still sitting there trusting it.

func newGitHubAPI(t *testing.T, status map[string]int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if code, ok := status[r.URL.Path]; ok {
			w.WriteHeader(code)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestGitHubNamespaceResolve(t *testing.T) {
	srv := newGitHubAPI(t, map[string]int{
		"/repos/myorg/myrepo":    http.StatusOK,
		"/repos/stranger/theirs": http.StatusOK,
		"/orgs/myorg":            http.StatusOK,
		"/repos/private/hidden":  http.StatusForbidden,
	})

	for _, tc := range []struct {
		name      string
		namespace string
		owners    []string
		want      core.NamespaceState
		detailHas string
	}{
		{
			name: "ours", namespace: "myorg/myrepo", owners: []string{"myorg"},
			want: core.NamespaceLive,
		},
		{
			name: "exists but is somebody else's", namespace: "stranger/theirs", owners: []string{"myorg"},
			want: core.NamespaceNotOurs, detailHas: "not one of your organisations",
		},
		{
			name: "unregistered and claimable right now", namespace: "deletedorg/gone", owners: []string{"myorg"},
			want: core.NamespaceUnregistered, detailHas: "anyone can register it",
		},
		{
			// Without knowing which orgs are ours, "it exists" says nothing about who controls it — and claiming it is fine would be the dangerous half of the guess.
			name: "exists, ownership not checked", namespace: "myorg/myrepo",
			want: core.NamespaceUnknown, detailHas: "--github-owner",
		},
		{
			// A private repo of somebody else's is indistinguishable from a nonexistent one without access, so this must read as neither.
			name: "forbidden is not absence", namespace: "private/hidden", owners: []string{"myorg"},
			want: core.NamespaceUnknown, detailHas: "GITHUB_TOKEN",
		},
		{
			// The numeric ids are what make an immutable subject immutable: there is nothing to re-register.
			name: "immutable subject", namespace: "myorg@123456/myrepo@456789", owners: []string{"myorg"},
			want: core.NamespaceUnknown, detailHas: "immutable",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := []GitHubNamespaceOption{
				WithGitHubAPI(srv.URL),
				WithGitHubNamespaceHTTPClient(srv.Client()),
				WithGitHubToken(""),
			}
			if len(tc.owners) > 0 {
				opts = append(opts, WithOurGitHubOwners(tc.owners...))
			}
			r := NewGitHubNamespaceResolver(opts...)

			state, detail, err := r.Resolve(context.Background(), tc.namespace)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if state != tc.want {
				t.Errorf("state = %q, want %q (detail: %s)", state, tc.want, detail)
			}
			if tc.detailHas != "" && !strings.Contains(detail, tc.detailHas) {
				t.Errorf("detail = %q, want it to mention %q", detail, tc.detailHas)
			}
		})
	}
}

// Owner matching is case-insensitive: GitHub org names are.
func TestGitHubOwnerMatchIsCaseInsensitive(t *testing.T) {
	srv := newGitHubAPI(t, map[string]int{"/repos/MyOrg/MyRepo": http.StatusOK})
	r := NewGitHubNamespaceResolver(
		WithGitHubAPI(srv.URL),
		WithGitHubNamespaceHTTPClient(srv.Client()),
		WithOurGitHubOwners("myorg"),
	)
	state, _, err := r.Resolve(context.Background(), "MyOrg/MyRepo")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if state != core.NamespaceLive {
		t.Errorf("state = %q, want live — GitHub org names are case-insensitive", state)
	}
}

// A bare owner resolves against /orgs, not /repos.
func TestGitHubBareOwnerUsesTheOrgEndpoint(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	r := NewGitHubNamespaceResolver(
		WithGitHubAPI(srv.URL),
		WithGitHubNamespaceHTTPClient(srv.Client()),
		WithOurGitHubOwners("myorg"),
	)
	if _, _, err := r.Resolve(context.Background(), "myorg"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if gotPath != "/orgs/myorg" {
		t.Errorf("path = %q, want /orgs/myorg", gotPath)
	}
}

func TestGitHubResolverIssuer(t *testing.T) {
	if got := NewGitHubNamespaceResolver().Issuer(); got != "https://token.actions.githubusercontent.com" {
		t.Errorf("Issuer() = %q", got)
	}
}

// A transport failure is an error, not an answer.
func TestGitHubResolverTransportFailureIsAnError(t *testing.T) {
	r := NewGitHubNamespaceResolver(
		WithGitHubAPI("http://127.0.0.1:1"),
		WithOurGitHubOwners("myorg"),
	)
	if _, _, err := r.Resolve(context.Background(), "myorg/myrepo"); err == nil {
		t.Fatal("want an error when the API is unreachable")
	}
}
