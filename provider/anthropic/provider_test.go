package anthropic

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// fakeAdmin is the Admin API's federation surface: three collections, create/list/get/archive, 400 on archiving a referenced parent.
type fakeAdmin struct {
	mu       sync.Mutex
	sas      []ServiceAccount
	issuers  []Issuer
	rules    []Rule
	failRule bool // make rule creation fail, to exercise rollback
	n        int
}

func (f *fakeAdmin) id(prefix string) string { f.n++; return fmt.Sprintf("%s_%03d", prefix, f.n) }

func (f *fakeAdmin) handler(t *testing.T) http.Handler {
	archived := "2026-01-01T00:00:00Z"
	live := func(a *string) bool { return a == nil }
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("authorization") != "Bearer tok" || r.Header.Get("anthropic-version") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		p := strings.TrimPrefix(r.URL.Path, "/v1/organizations/")
		parts := strings.Split(p, "/")
		write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		page := func(items any) { write(map[string]any{"data": items, "next_page": ""}) }
		switch {
		case parts[0] == "service_accounts" && len(parts) == 1 && r.Method == http.MethodGet:
			var out []ServiceAccount
			for _, s := range f.sas {
				if live(s.ArchivedAt) {
					out = append(out, s)
				}
			}
			page(out)
		case parts[0] == "service_accounts" && len(parts) == 1:
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			sa := ServiceAccount{ID: f.id("svac"), Name: in["name"], OrganizationRole: in["organization_role"]}
			f.sas = append(f.sas, sa)
			write(sa)
		case parts[0] == "service_accounts" && len(parts) == 2:
			for _, s := range f.sas {
				if s.ID == parts[1] {
					write(s)
					return
				}
			}
			http.NotFound(w, r)
		case parts[0] == "service_accounts" && parts[2] == "archive":
			for _, rl := range f.rules {
				if rl.Target.ServiceAccountID == parts[1] && live(rl.ArchivedAt) {
					http.Error(w, `{"error":"referenced by a live rule"}`, http.StatusBadRequest)
					return
				}
			}
			for i := range f.sas {
				if f.sas[i].ID == parts[1] {
					f.sas[i].ArchivedAt = &archived
					write(f.sas[i])
					return
				}
			}
			http.NotFound(w, r)
		case parts[0] == "federation_issuers" && len(parts) == 1 && r.Method == http.MethodGet:
			var out []Issuer
			for _, s := range f.issuers {
				if live(s.ArchivedAt) {
					out = append(out, s)
				}
			}
			page(out)
		case parts[0] == "federation_issuers" && len(parts) == 1:
			var in Issuer
			_ = json.NewDecoder(r.Body).Decode(&in)
			in.ID = f.id("fdis")
			f.issuers = append(f.issuers, in)
			write(in)
		case parts[0] == "federation_issuers" && len(parts) == 2:
			for _, s := range f.issuers {
				if s.ID == parts[1] {
					write(s)
					return
				}
			}
			http.NotFound(w, r)
		case parts[0] == "federation_issuers" && parts[2] == "archive":
			for _, rl := range f.rules {
				if rl.IssuerID == parts[1] && live(rl.ArchivedAt) {
					http.Error(w, `{"error":"referenced by a live rule"}`, http.StatusBadRequest)
					return
				}
			}
			for i := range f.issuers {
				if f.issuers[i].ID == parts[1] {
					f.issuers[i].ArchivedAt = &archived
					write(f.issuers[i])
					return
				}
			}
			http.NotFound(w, r)
		case parts[0] == "federation_rules" && len(parts) == 1 && r.Method == http.MethodGet:
			var out []Rule
			for _, s := range f.rules {
				if live(s.ArchivedAt) {
					out = append(out, s)
				}
			}
			page(out)
		case parts[0] == "federation_rules" && len(parts) == 1:
			if f.failRule {
				http.Error(w, `{"error":"invalid_request_error"}`, http.StatusBadRequest)
				return
			}
			var in Rule
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in.Match.SubjectPrefix == "" && len(in.Match.Claims) == 0 && in.Match.Condition == "" {
				http.Error(w, "match needs a matcher", http.StatusBadRequest)
				return
			}
			in.ID = f.id("fdrl")
			f.rules = append(f.rules, in)
			write(in)
		case parts[0] == "federation_rules" && len(parts) == 2:
			for _, s := range f.rules {
				if s.ID == parts[1] {
					write(s)
					return
				}
			}
			http.NotFound(w, r)
		case parts[0] == "federation_rules" && parts[2] == "archive":
			for i := range f.rules {
				if f.rules[i].ID == parts[1] {
					f.rules[i].ArchivedAt = &archived
					write(f.rules[i])
					return
				}
			}
			http.NotFound(w, r)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	})
}

func newProvider(t *testing.T, f *fakeAdmin) *Provider {
	t.Helper()
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	return New(WithClient(NewClient(WithBaseURL(srv.URL), WithToken("tok"), WithHTTPClient(srv.Client()))))
}

func spec() *core.AnthropicFederationSpec {
	return &core.AnthropicFederationSpec{
		OrganizationID: "00000000-0000-0000-0000-000000000000", ServiceAccountName: "deploy-bot",
		IssuerURL: "https://token.actions.githubusercontent.com", RuleName: "gha-main",
		SubjectPrefix: "repo:o/r:ref:refs/heads/main", Audience: "https://api.anthropic.com",
		WorkspaceID: "wrkspc_01", OAuthScope: "workspace:inference", Source: core.GitHubOIDC,
	}
}

func liveCount[T any](items []T, archived func(T) *string) int {
	n := 0
	for _, it := range items {
		if archived(it) == nil {
			n++
		}
	}
	return n
}

// Setup creates all three, a re-run creates nothing and lands on the same ids, validate passes, delete archives all three.
func TestLifecycle(t *testing.T) {
	f := &fakeAdmin{}
	p := newProvider(t, f)
	ctx := context.Background()
	s := spec()
	if err := s.Validate(); err != nil {
		t.Fatalf("spec: %v", err)
	}

	out, err := p.Setup(ctx, s, core.SetupOptions{})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	ids := out.Ref.ResourceIDs
	if !strings.HasPrefix(ids[keyRule], "fdrl_") || !strings.HasPrefix(ids[keyIssuer], "fdis_") || !strings.HasPrefix(ids[keySA], "svac_") {
		t.Fatalf("resource ids = %v", ids)
	}
	if !out.Ref.Owned || ids[keyCreatedIssuer] != "true" || ids[keyCreatedSA] != "true" {
		t.Errorf("ownership not recorded: owned=%v ids=%v", out.Ref.Owned, ids)
	}
	if f.rules[0].OAuthScope != "workspace:inference" || f.rules[0].Match.Audience != s.Audience || f.rules[0].Target.Type != "service_account" {
		t.Errorf("rule sent = %+v", f.rules[0])
	}
	if f.issuers[0].Name != "token-actions-githubusercontent-com" || f.issuers[0].JWKS["type"] != "discovery" {
		t.Errorf("issuer sent = %+v", f.issuers[0])
	}
	if !strings.Contains(strings.Join(out.Instructions, "\n"), "--federation-rule "+ids[keyRule]) {
		t.Errorf("instructions do not hand back the exec command: %v", out.Instructions)
	}

	again, err := p.Setup(ctx, s, core.SetupOptions{})
	if err != nil {
		t.Fatalf("re-run: %v", err)
	}
	for _, k := range []string{keyRule, keyIssuer, keySA} {
		if again.Ref.ResourceIDs[k] != ids[k] {
			t.Errorf("re-run %s = %s, first run %s", k, again.Ref.ResourceIDs[k], ids[k])
		}
	}
	if len(f.rules) != 1 || len(f.issuers) != 1 || len(f.sas) != 1 {
		t.Fatalf("re-run created duplicates: %d rules %d issuers %d sas", len(f.rules), len(f.issuers), len(f.sas))
	}
	if again.Ref.Owned {
		t.Error("a re-run that reused the rule claims to own it")
	}

	report, err := p.Validate(ctx, out.Ref, core.ValidateOptions{})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if report.Summary.FailedChecks != 0 || report.Summary.PassedChecks != 3 {
		t.Fatalf("validate: %+v", report.Checks)
	}

	if err := p.Delete(ctx, out.Ref, core.DeleteOptions{OwnedOnly: true}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if liveCount(f.rules, func(r Rule) *string { return r.ArchivedAt }) != 0 ||
		liveCount(f.issuers, func(i Issuer) *string { return i.ArchivedAt }) != 0 ||
		liveCount(f.sas, func(s ServiceAccount) *string { return s.ArchivedAt }) != 0 {
		t.Errorf("delete left live resources: %+v %+v %+v", f.rules, f.issuers, f.sas)
	}
}

// An existing issuer for the URL is reused, and a shared issuer survives delete because another rule still references it.
func TestReusesAnExistingIssuerAndKeepsItOnDelete(t *testing.T) {
	f := &fakeAdmin{issuers: []Issuer{{ID: "fdis_pre", Name: "gh", IssuerURL: "https://token.actions.githubusercontent.com"}}}
	f.rules = []Rule{{ID: "fdrl_other", Name: "other", IssuerID: "fdis_pre", Target: RuleTarget{Type: "service_account", ServiceAccountID: "svac_x"}}}
	p := newProvider(t, f)
	out, err := p.Setup(context.Background(), spec(), core.SetupOptions{})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if out.Ref.ResourceIDs[keyIssuer] != "fdis_pre" || out.Ref.ResourceIDs[keyCreatedIssuer] != "false" {
		t.Fatalf("issuer not reused: %v", out.Ref.ResourceIDs)
	}
	if err := p.Delete(context.Background(), out.Ref, core.DeleteOptions{OwnedOnly: true}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if f.issuers[0].ArchivedAt != nil {
		t.Error("a pre-existing issuer was archived")
	}
}

// Rule creation failing must archive the service account and issuer this run created.
func TestRollbackWhenTheRuleIsRefused(t *testing.T) {
	f := &fakeAdmin{failRule: true}
	p := newProvider(t, f)
	_, err := p.Setup(context.Background(), spec(), core.SetupOptions{})
	var rb *core.RollbackError
	if err == nil || !asRollback(err, &rb) {
		t.Fatalf("err = %v, want a RollbackError", err)
	}
	if f.sas[0].ArchivedAt == nil || f.issuers[0].ArchivedAt == nil {
		t.Errorf("rollback left resources live: sa=%v issuer=%v", f.sas[0].ArchivedAt, f.issuers[0].ArchivedAt)
	}
}

func asRollback(err error, target **core.RollbackError) bool {
	rb, ok := err.(*core.RollbackError)
	if ok {
		*target = rb
	}
	return ok
}

// A same-named rule bound to something else is a conflict, never silently adopted.
func TestSameNameDifferentBindingIsAConflict(t *testing.T) {
	f := &fakeAdmin{rules: []Rule{{ID: "fdrl_x", Name: "gha-main", IssuerID: "fdis_other", Target: RuleTarget{ServiceAccountID: "svac_other"}}}}
	p := newProvider(t, f)
	_, err := p.Setup(context.Background(), spec(), core.SetupOptions{})
	if err == nil || !strings.Contains(err.Error(), "pick another rule_name") {
		t.Fatalf("err = %v, want a conflict", err)
	}
}

// Without a token nothing but --dry-run may proceed, and the hint names the login that mints one.
func TestRequiresAnAdminToken(t *testing.T) {
	p := New(WithClient(NewClient(WithToken(""))))
	if _, err := p.Setup(context.Background(), spec(), core.SetupOptions{DryRun: true}); err != nil {
		t.Fatalf("dry-run needs no token: %v", err)
	}
	_, err := p.Setup(context.Background(), spec(), core.SetupOptions{})
	if err == nil || !strings.Contains(err.Error(), "org:admin") {
		t.Fatalf("err = %v, want the org:admin hint", err)
	}
}

func TestSpecValidation(t *testing.T) {
	for name, mutate := range map[string]func(*core.AnthropicFederationSpec){
		"no matcher":     func(s *core.AnthropicFederationSpec) { s.SubjectPrefix = "" },
		"bad name":       func(s *core.AnthropicFederationSpec) { s.RuleName = "Has Caps" },
		"http issuer":    func(s *core.AnthropicFederationSpec) { s.IssuerURL = "http://x.example" },
		"admin scope":    func(s *core.AnthropicFederationSpec) { s.OAuthScope = "org:admin" },
		"no workspace":   func(s *core.AnthropicFederationSpec) { s.WorkspaceID = "" },
		"both workspace": func(s *core.AnthropicFederationSpec) { s.AppliesToAllWorkspaces = true },
		"short lifetime": func(s *core.AnthropicFederationSpec) { s.TokenLifetimeSeconds = 30 },
	} {
		s := spec()
		mutate(s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s: want a validation error", name)
		}
	}
}
