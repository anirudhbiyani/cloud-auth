package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// A fake Azure speaking the documented Graph, ARM and Entra wire shapes. The
// constraints exercised here are the ones Microsoft's own documentation calls
// out and that a client discovers the hard way otherwise: the 20-credential cap,
// the creation throttle, wildcards that are matched literally, and the
// propagation window after a credential is created.

type staticCredential struct{ token string }

func (s staticCredential) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: s.token, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

type fakeAzure struct {
	t      *testing.T
	mux    *http.ServeMux
	server *httptest.Server
	calls  atomic.Int32

	// The pacing test drives concurrent requests, so the recorded body is
	// written from several handler goroutines.
	mu      sync.Mutex
	lastRaw []byte
}

func newFakeAzure(t *testing.T) *fakeAzure {
	t.Helper()
	f := &fakeAzure{t: t, mux: http.NewServeMux()}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		if r.Body != nil {
			raw, _ := io.ReadAll(r.Body)
			f.mu.Lock()
			f.lastRaw = raw
			f.mu.Unlock()
			r.Body = io.NopCloser(strings.NewReader(string(raw)))
		}
		f.mux.ServeHTTP(w, r)
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeAzure) handle(pattern string, fn http.HandlerFunc) { f.mux.HandleFunc(pattern, fn) }

func (f *fakeAzure) json(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		f.t.Fatalf("encode: %v", err)
	}
}

func (f *fakeAzure) lastJSON() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out map[string]any
	_ = json.Unmarshal(f.lastRaw, &out)
	return out
}

// body returns the last recorded request body.
func (f *fakeAzure) body() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastRaw
}

// client returns a restClient pointed at the fake, with pacing and sleeps made
// instantaneous so a throttle test does not cost four real seconds.
func (f *fakeAzure) client(t *testing.T) *restClient {
	t.Helper()
	base := f.server.URL
	clients, err := NewClients(context.Background(),
		WithCredential(staticCredential{token: "test-token"}),
		WithClientEndpoints(base+"/v1.0", base),
	)
	if err != nil {
		t.Fatalf("NewClients: %v", err)
	}
	c := clients.Graph.(*restClient)
	c.sleep = func(context.Context, time.Duration) error { return nil }
	return c
}

// Azure caps federated identity credentials at 20 per application or
// user-assigned managed identity. Its own refusal names the limit without naming
// what is occupying the slots, so the check happens here first.
func TestCreateFICRefusesTheTwentyFirst(t *testing.T) {
	f := newFakeAzure(t)
	const appID = "00000000-0000-0000-0000-000000000000"

	existing := make([]map[string]any, maxFederatedCredentials)
	for i := range existing {
		existing[i] = map[string]any{"id": fmt.Sprint(i), "name": fmt.Sprintf("cred-%d", i)}
	}
	f.handle("/v1.0/applications/"+appID+"/federatedIdentityCredentials",
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				t.Error("the credential was created despite the cap")
			}
			f.json(w, http.StatusOK, map[string]any{"value": existing})
		})

	_, err := f.client(t).CreateFederatedIdentityCredential(context.Background(), appID,
		&FederatedIdentityCredential{
			Name: "twenty-first", Issuer: "https://token.actions.githubusercontent.com",
			Subject: "repo:org/repo:ref:refs/heads/main", Audiences: []string{"api://AzureADTokenExchange"},
		})
	if err == nil {
		t.Fatal("want an error at the cap")
	}
	if !strings.Contains(err.Error(), "20 federated identity credentials") {
		t.Errorf("error should name the count and limit: %v", err)
	}
	// The flexible-FIC preview is the obvious next question, and adopting it
	// breaks IaC reads. Say so in the same breath.
	if !strings.Contains(err.Error(), "flexible") {
		t.Errorf("error should mention the flexible-FIC trade-off: %v", err)
	}
}

// Nineteen is fine; the boundary must be off-by-one correct in the safe
// direction.
func TestCreateFICAllowsUpToTheCap(t *testing.T) {
	f := newFakeAzure(t)
	const appID = "00000000-0000-0000-0000-000000000000"

	existing := make([]map[string]any, maxFederatedCredentials-1)
	for i := range existing {
		existing[i] = map[string]any{"id": fmt.Sprint(i), "name": fmt.Sprintf("cred-%d", i)}
	}
	f.handle("/v1.0/applications/"+appID+"/federatedIdentityCredentials",
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				f.json(w, http.StatusCreated, map[string]any{
					"id": "new-id", "name": "twentieth",
					"issuer": "https://token.actions.githubusercontent.com",
				})
				return
			}
			f.json(w, http.StatusOK, map[string]any{"value": existing})
		})

	got, err := f.client(t).CreateFederatedIdentityCredential(context.Background(), appID,
		&FederatedIdentityCredential{
			Name: "twentieth", Issuer: "https://token.actions.githubusercontent.com",
			Subject: "repo:org/repo:ref:refs/heads/main", Audiences: []string{"api://AzureADTokenExchange"},
		})
	if err != nil {
		t.Fatalf("CreateFederatedIdentityCredential: %v", err)
	}
	if got.Name != "twentieth" {
		t.Errorf("Name = %q", got.Name)
	}
}

// No FIC property accepts a wildcard. Azure matches the literal characters, so a
// wildcard subject produces a credential that is created successfully and then
// never matches a token — the failure mode Microsoft documents as failing
// without error.
func TestValidateFICRejectsWildcards(t *testing.T) {
	base := func() *FederatedIdentityCredential {
		return &FederatedIdentityCredential{
			Name: "gh", Issuer: "https://token.actions.githubusercontent.com",
			Subject: "repo:org/repo:ref:refs/heads/main", Audiences: []string{"api://AzureADTokenExchange"},
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*FederatedIdentityCredential)
		errHas string
	}{
		{"wildcard subject", func(c *FederatedIdentityCredential) { c.Subject = "repo:org/*" }, "subject"},
		{"wildcard issuer", func(c *FederatedIdentityCredential) { c.Issuer = "https://*.example.com" }, "issuer"},
		{"wildcard name", func(c *FederatedIdentityCredential) { c.Name = "gh-*" }, "name"},
		{"wildcard audience", func(c *FederatedIdentityCredential) { c.Audiences = []string{"api://*"} }, "audience"},
		{"single-char wildcard", func(c *FederatedIdentityCredential) { c.Subject = "repo:org/repo:ref:refs/heads/main?" }, "subject"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cred := base()
			tc.mutate(cred)
			err := validateFIC(cred)
			if err == nil {
				t.Fatal("want an error for a wildcard")
			}
			if !strings.Contains(err.Error(), tc.errHas) {
				t.Errorf("error = %q, want it to name the %s field", err, tc.errHas)
			}
			if !strings.Contains(err.Error(), "literal") {
				t.Errorf("error should explain that Azure matches literally: %v", err)
			}
		})
	}

	if err := validateFIC(base()); err != nil {
		t.Errorf("a clean credential was rejected: %v", err)
	}
}

// Azure throttles credential creation to about 0.25 req/sec per resource and
// answers a concurrent create under the same identity with 409 — which is
// indistinguishable from "already exists", so fanning out produces conflicts
// that get conflated with success.
func TestCreateFICIsSerializedAndPaced(t *testing.T) {
	f := newFakeAzure(t)
	const appID = "00000000-0000-0000-0000-000000000000"
	var inFlight, maxInFlight atomic.Int32

	f.handle("/v1.0/applications/"+appID+"/federatedIdentityCredentials",
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				f.json(w, http.StatusOK, map[string]any{"value": []any{}})
				return
			}
			n := inFlight.Add(1)
			for {
				old := maxInFlight.Load()
				if n <= old || maxInFlight.CompareAndSwap(old, n) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			inFlight.Add(-1)
			f.json(w, http.StatusCreated, map[string]any{"id": "x", "name": "y"})
		})

	c := f.client(t)
	// sleep is called while ficMu is held, so appends here are already
	// serialized by the very lock this test is checking.
	var waited []time.Duration
	c.sleep = func(_ context.Context, d time.Duration) error {
		waited = append(waited, d)
		return nil
	}

	done := make(chan error, 3)
	for i := range 3 {
		go func() {
			_, err := c.CreateFederatedIdentityCredential(context.Background(), appID,
				&FederatedIdentityCredential{
					Name: fmt.Sprintf("cred-%d", i), Issuer: "https://token.actions.githubusercontent.com",
					Subject:   fmt.Sprintf("repo:org/repo:ref:refs/heads/b%d", i),
					Audiences: []string{"api://AzureADTokenExchange"},
				})
			done <- err
		}()
	}
	for range 3 {
		if err := <-done; err != nil {
			t.Fatalf("create: %v", err)
		}
	}

	if got := maxInFlight.Load(); got > 1 {
		t.Errorf("%d creates were in flight at once; they must be serialized", got)
	}
	if len(waited) == 0 {
		t.Error("no pacing delay was applied between creates")
	}
	for _, d := range waited {
		if d > ficCreateInterval {
			t.Errorf("waited %s, longer than the %s interval", d, ficCreateInterval)
		}
	}
}

// A newly created federated credential legitimately fails for a few minutes
// while Entra replicates it. That is the ONE 4xx worth retrying here, and the
// retry must not widen to any other rejection.
func TestExchangeRetriesOnlyPropagationFailures(t *testing.T) {
	for _, tc := range []struct {
		name        string
		code        string
		description string
		wantCalls   int
		wantErrHas  string
	}{
		{
			name: "propagation delay is retried",
			code: "invalid_client",
			description: "AADSTS70021: No matching federated identity record found for " +
				"presented assertion.",
			wantCalls:  propagationRetries,
			wantErrHas: "had not propagated",
		},
		{
			name:        "a wrong subject fails immediately",
			code:        "invalid_client",
			description: "AADSTS700213: No matching federated identity record found for presented assertion subject.",
			wantCalls:   1,
			wantErrHas:  "AADSTS700213",
		},
		{
			name:        "an unknown client fails immediately",
			code:        "unauthorized_client",
			description: "AADSTS700016: Application with identifier was not found.",
			wantCalls:   1,
			wantErrHas:  "AADSTS700016",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAzure(t)
			var calls atomic.Int32
			f.handle("/", func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				f.json(w, http.StatusUnauthorized, map[string]any{
					"error": tc.code, "error_description": tc.description,
				})
			})

			c := f.client(t)
			c.http = f.server.Client()
			_, err := c.exchangeWithPropagationRetry(context.Background(), f.server.URL+"/token",
				url.Values{"client_id": {"c"}})

			if err == nil {
				t.Fatal("want an error")
			}
			if got := int(calls.Load()); got != tc.wantCalls {
				t.Errorf("made %d attempts, want %d", got, tc.wantCalls)
			}
			if !strings.Contains(err.Error(), tc.wantErrHas) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErrHas)
			}
		})
	}
}

// Entra hides the actionable identifier inside error_description; the code field
// is "invalid_client" for a dozen distinct causes.
func TestParseAPIErrorExtractsTheAADSTSCode(t *testing.T) {
	err := parseAPIError(http.StatusUnauthorized, []byte(
		`{"error":"invalid_client","error_description":"AADSTS70021: No matching federated identity record found."}`), "")

	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		t.Fatalf("not an *apiError: %T", err)
	}
	if apiErr.Code != "AADSTS70021" {
		t.Errorf("Code = %q, want AADSTS70021 (invalid_client alone is not actionable)", apiErr.Code)
	}
}

func TestAPIErrorIsTypedNotFound(t *testing.T) {
	err := parseAPIError(http.StatusNotFound, []byte(
		`{"error":{"code":"Request_ResourceNotFound","message":"Resource does not exist."}}`), "app")

	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		t.Fatalf("not an *apiError: %T", err)
	}
	if !apiErr.NotFound() {
		t.Error("NotFound() = false for Request_ResourceNotFound")
	}
	if !isNotFoundError(err) {
		t.Error("isNotFoundError = false; the typed path did not fire")
	}
}

// A denied read is not evidence of absence — the distinction the rollback logic
// turns on.
func TestForbiddenIsNotAbsence(t *testing.T) {
	err := parseAPIError(http.StatusForbidden, []byte(
		`{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges."}}`), "app")
	if isNotFoundError(err) {
		t.Errorf("a 403 read as absence: %v", err)
	}
}

// Entra error descriptions echo the assertion back.
func TestTokenErrorRedactsTheEchoedAssertion(t *testing.T) {
	const assertion = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZXBvOm9yZy9yZXBvIn0.c2lnbmF0dXJlLXRoYXQtaXMtbG9uZy1hbmQtc2VjcmV0LTEyMzQ1Njc4OTAxMjM0NTY"
	err := parseAPIError(http.StatusUnauthorized, []byte(fmt.Sprintf(
		`{"error":"invalid_client","error_description":"AADSTS700027: Client assertion %s failed signature validation."}`,
		assertion)), "")

	if strings.Contains(err.Error(), "c2lnbmF0dXJlLXRoYXQtaXMtbG9uZy1hbmQtc2VjcmV0LTEyMzQ1Njc4OTAxMjM0NTY") {
		t.Errorf("the assertion survived into the error: %v", err)
	}
	// ...but the error must stay diagnosable, or we have traded a leak for an
	// unusable message.
	if !strings.Contains(err.Error(), "AADSTS700027") {
		t.Errorf("error is no longer diagnosable: %v", err)
	}
}

// Graph and ARM issue separate tokens for separate audiences. Presenting one to
// the other fails as an authorization error that reads like a permissions bug.
func TestGraphAndARMRequestDifferentScopes(t *testing.T) {
	f := newFakeAzure(t)
	var scopes []string
	f.handle("/v1.0/applications/app-id", func(w http.ResponseWriter, _ *http.Request) {
		f.json(w, http.StatusOK, map[string]any{"id": "app-id", "displayName": "x"})
	})
	f.handle("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uami",
		func(w http.ResponseWriter, _ *http.Request) {
			f.json(w, http.StatusOK, map[string]any{"id": "/x", "name": "uami"})
		})

	c := f.client(t)
	c.credential = recordingCredential{scopes: &scopes}
	ctx := context.Background()

	if _, err := c.GetApplication(ctx, "app-id"); err != nil {
		t.Fatalf("GetApplication: %v", err)
	}
	if _, err := c.GetManagedIdentity(ctx, "sub", "rg", "uami"); err != nil {
		t.Fatalf("GetManagedIdentity: %v", err)
	}

	if len(scopes) != 2 {
		t.Fatalf("got %d token requests, want 2", len(scopes))
	}
	if scopes[0] != graphScope {
		t.Errorf("Graph call used scope %q, want %q", scopes[0], graphScope)
	}
	if scopes[1] != armScope {
		t.Errorf("ARM call used scope %q, want %q", scopes[1], armScope)
	}
}

type recordingCredential struct{ scopes *[]string }

func (r recordingCredential) GetToken(_ context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	*r.scopes = append(*r.scopes, opts.Scopes[0])
	return azcore.AccessToken{Token: "t", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

// Re-running setup must not create a duplicate grant. The assignment name is a
// client-generated GUID, so Azure answers the repeat with 409 — which is the
// desired end state, not a failure.
func TestCreateRoleAssignmentTreatsConflictAsSuccess(t *testing.T) {
	f := newFakeAzure(t)
	f.handle("/", func(w http.ResponseWriter, _ *http.Request) {
		f.json(w, http.StatusConflict, map[string]any{
			"error": map[string]any{
				"code": "RoleAssignmentExists", "message": "The role assignment already exists.",
			},
		})
	})

	err := f.client(t).CreateRoleAssignment(context.Background(),
		"/subscriptions/sub/resourceGroups/rg",
		"/subscriptions/sub/providers/Microsoft.Authorization/roleDefinitions/abc",
		"principal-id")
	if err != nil {
		t.Errorf("an existing assignment should be success, got: %v", err)
	}
}

// A brand-new service principal is rejected by ARM as "does not exist" until
// directory replication catches up, unless principalType says what it is.
func TestCreateRoleAssignmentSetsPrincipalType(t *testing.T) {
	f := newFakeAzure(t)
	f.handle("/", func(w http.ResponseWriter, _ *http.Request) {
		f.json(w, http.StatusCreated, map[string]any{"id": "ra"})
	})

	if err := f.client(t).CreateRoleAssignment(context.Background(),
		"/subscriptions/sub", "/roleDefinitions/abc", "principal-id"); err != nil {
		t.Fatalf("CreateRoleAssignment: %v", err)
	}
	props, ok := f.lastJSON()["properties"].(map[string]any)
	if !ok {
		t.Fatalf("no properties in the request: %s", f.body())
	}
	if props["principalType"] != "ServicePrincipal" {
		t.Errorf("principalType = %v, want ServicePrincipal", props["principalType"])
	}
}

// Graph pages with @odata.nextLink. Stopping at the first page answers "these
// are your applications" with a prefix of them, and callers decide existence
// from the result.
func TestListApplicationsFollowsPaging(t *testing.T) {
	f := newFakeAzure(t)
	f.handle("/v1.0/applications", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			f.json(w, http.StatusOK, map[string]any{
				"value": []map[string]any{{"id": "b", "displayName": "second"}},
			})
			return
		}
		f.json(w, http.StatusOK, map[string]any{
			"value":           []map[string]any{{"id": "a", "displayName": "first"}},
			"@odata.nextLink": f.server.URL + "/v1.0/applications?page=2",
		})
	})

	apps, err := f.client(t).ListApplications(context.Background())
	if err != nil {
		t.Fatalf("ListApplications: %v", err)
	}
	if len(apps) != 2 {
		t.Fatalf("got %d applications, want 2 (paging was not followed)", len(apps))
	}
}

// A new application must not default to a multi-tenant sign-in audience, which
// would make it assumable from directories the operator does not control.
func TestCreateApplicationDefaultsToSingleTenant(t *testing.T) {
	f := newFakeAzure(t)
	f.handle("/v1.0/applications", func(w http.ResponseWriter, _ *http.Request) {
		f.json(w, http.StatusCreated, map[string]any{"id": "new", "appId": "app"})
	})

	if _, err := f.client(t).CreateApplication(context.Background(),
		&Application{DisplayName: "cloud-auth-test"}); err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	if got := f.lastJSON()["signInAudience"]; got != "AzureADMyOrg" {
		t.Errorf("signInAudience = %v, want AzureADMyOrg", got)
	}
}

// Scope has no safe default: a resource-wide one hands out more than was asked
// for. core/target.go makes the same call for AzureTarget.Scope.
func TestExchangeTokenRequiresAScope(t *testing.T) {
	f := newFakeAzure(t)
	_, err := f.client(t).ExchangeToken(context.Background(), &ExchangeTokenInput{
		TenantID: "tenant", ClientID: "client", FederatedToken: "tok",
	})
	if err == nil {
		t.Fatal("want an error: there is no safe default scope")
	}
	if f.calls.Load() != 0 {
		t.Error("the request was sent anyway")
	}
}

// Without credentials the provider must say so, and must not claim the feature
// is unimplemented — which is what "client not configured" used to mean.
func TestRequireClientsReportsCredentialFailure(t *testing.T) {
	p := New()
	p.resolveFailed = errors.New("azure: no credential in the chain provided a token")

	err := p.requireClients(context.Background(), true, true)
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "no usable credentials") {
		t.Errorf("error = %q, want it to name the credential problem", err)
	}
	if !core.IsCategory(err, core.ErrCategoryValidation) {
		t.Errorf("category = %v", core.CategoryOf(err))
	}
}

// The Graph write and delete paths. Each is a one-line route over do(), and the
// thing worth asserting is the route: a wrong verb or path fails against a real
// tenant in a way no unit test of the body would catch.
func TestGraphWriteAndDeleteRoutes(t *testing.T) {
	f := newFakeAzure(t)
	const appID = "00000000-0000-0000-0000-000000000000"

	var got []string
	f.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Method+" "+r.URL.Path)
		f.json(w, http.StatusOK, map[string]any{
			"id": "x", "appId": "app", "displayName": "d",
			"issuer": "https://issuer", "subject": "sub",
		})
	})

	c := f.client(t)
	ctx := context.Background()

	if err := c.UpdateApplication(ctx, appID, &Application{DisplayName: "renamed"}); err != nil {
		t.Fatalf("UpdateApplication: %v", err)
	}
	if _, err := c.CreateServicePrincipal(ctx, "app-id"); err != nil {
		t.Fatalf("CreateServicePrincipal: %v", err)
	}
	if _, err := c.GetServicePrincipal(ctx, "sp-1"); err != nil {
		t.Fatalf("GetServicePrincipal: %v", err)
	}
	if _, err := c.GetFederatedIdentityCredential(ctx, appID, "cred-1"); err != nil {
		t.Fatalf("GetFederatedIdentityCredential: %v", err)
	}
	if err := c.DeleteFederatedIdentityCredential(ctx, appID, "cred-1"); err != nil {
		t.Fatalf("DeleteFederatedIdentityCredential: %v", err)
	}
	if err := c.DeleteServicePrincipal(ctx, "sp-1"); err != nil {
		t.Fatalf("DeleteServicePrincipal: %v", err)
	}
	if err := c.DeleteApplication(ctx, appID); err != nil {
		t.Fatalf("DeleteApplication: %v", err)
	}

	want := []string{
		// PATCH, not PUT: Graph replaces the whole object on PUT, so an update
		// that sent PUT would silently clear every field it did not set.
		"PATCH /v1.0/applications/" + appID,
		"POST /v1.0/servicePrincipals",
		"GET /v1.0/servicePrincipals/sp-1",
		"GET /v1.0/applications/" + appID + "/federatedIdentityCredentials/cred-1",
		"DELETE /v1.0/applications/" + appID + "/federatedIdentityCredentials/cred-1",
		"DELETE /v1.0/servicePrincipals/sp-1",
		"DELETE /v1.0/applications/" + appID,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d requests, want %d:\n%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("request %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// CreateServicePrincipal requires an application id: creating one without it
// would produce a principal attached to nothing.
func TestCreateServicePrincipalRequiresAnAppID(t *testing.T) {
	f := newFakeAzure(t)
	if _, err := f.client(t).CreateServicePrincipal(context.Background(), ""); err == nil {
		t.Fatal("want an error with no application id")
	}
	if f.calls.Load() != 0 {
		t.Error("the request was sent anyway")
	}
}

// CreateApplication requires a display name for the same reason.
func TestCreateApplicationRequiresADisplayName(t *testing.T) {
	f := newFakeAzure(t)
	if _, err := f.client(t).CreateApplication(context.Background(), &Application{}); err == nil {
		t.Fatal("want an error with no display name")
	}
	if _, err := f.client(t).CreateApplication(context.Background(), nil); err == nil {
		t.Fatal("want an error for a nil application")
	}
	if f.calls.Load() != 0 {
		t.Error("the request was sent anyway")
	}
}

// redactedPath keeps scheme, host and path for diagnostics and drops the query,
// which on these APIs carries operator-supplied resource ids.
func TestRedactedPath(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://graph.microsoft.com/v1.0/applications?$filter=secret", "https://graph.microsoft.com/v1.0/applications"},
		{"https://management.azure.com/subs/x?api-version=1", "https://management.azure.com/subs/x"},
		{"://nope", "(unparseable url)"},
	} {
		if got := redactedPath(tc.in); got != tc.want {
			t.Errorf("redactedPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
