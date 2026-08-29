package vault

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// A fake Vault speaking the real API shapes: the /v1 prefix, the X-Vault-Token
// header, the {"data": ...} envelope on reads and the {"errors": [...]} envelope
// on failures. The paths are the point — several of them differ from the obvious
// guess in ways that produce a 404 on a mount that exists.

type fakeVaultServer struct {
	t      *testing.T
	server *httptest.Server

	mu       sync.Mutex
	requests []recordedRequest
	handler  func(*recordedRequest, http.ResponseWriter)
}

type recordedRequest struct {
	Method    string
	Path      string
	Query     string
	Token     string
	Namespace string
	Body      map[string]any
}

func newFakeVaultServer(t *testing.T) *fakeVaultServer {
	t.Helper()
	f := &fakeVaultServer{t: t}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := recordedRequest{
			Method:    r.Method,
			Path:      r.URL.Path,
			Query:     r.URL.RawQuery,
			Token:     r.Header.Get(tokenHeader),
			Namespace: r.Header.Get(namespaceHeader),
		}
		if raw, _ := io.ReadAll(r.Body); len(raw) > 0 {
			_ = json.Unmarshal(raw, &rec.Body)
		}

		f.mu.Lock()
		f.requests = append(f.requests, rec)
		handler := f.handler
		f.mu.Unlock()

		if handler != nil {
			handler(&rec, w)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeVaultServer) respond(fn func(*recordedRequest, http.ResponseWriter)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handler = fn
}

func (f *fakeVaultServer) last() recordedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) == 0 {
		f.t.Fatal("no request was made")
	}
	return f.requests[len(f.requests)-1]
}

func (f *fakeVaultServer) client(t *testing.T, opts ...ClientOption) *restClient {
	t.Helper()
	all := append([]ClientOption{
		WithAddress(f.server.URL),
		WithToken("test-token"),
	}, opts...)
	c, err := NewClient(all...)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c.(*restClient)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// The endpoints Vault actually serves, several of which are not the obvious
// guess. Getting one wrong is a 404 that reads like a missing mount rather than
// a wrong URL, which is a bad hour for whoever is debugging it.
func TestRequestPaths(t *testing.T) {
	for _, tc := range []struct {
		name       string
		call       func(*restClient) error
		wantMethod string
		wantPath   string
		why        string
	}{
		{
			name:       "enable auth method",
			call:       func(c *restClient) error { return c.EnableAuthMethod(t.Context(), "jwt", "jwt", nil) },
			wantMethod: http.MethodPost,
			wantPath:   "/v1/sys/auth/jwt",
		},
		{
			name:       "read auth method reads the MOUNT, not sys/auth",
			call:       func(c *restClient) error { _, err := c.ReadAuthMethod(t.Context(), "jwt"); return err },
			wantMethod: http.MethodGet,
			wantPath:   "/v1/sys/mounts/auth/jwt",
			why:        "sys/auth/<path> is write-only; the readable form is sys/mounts/auth/<path>",
		},
		{
			name: "tune auth method",
			call: func(c *restClient) error {
				return c.TuneAuthMethod(t.Context(), "jwt", &AuthMethodConfig{MaxLeaseTTL: "1h"})
			},
			wantMethod: http.MethodPost,
			wantPath:   "/v1/sys/auth/jwt/tune",
		},
		{
			name:       "JWT role uses the SINGULAR role",
			call:       func(c *restClient) error { return c.WriteJWTRole(t.Context(), "jwt", "ci", &JWTRole{UserClaim: "sub"}) },
			wantMethod: http.MethodPost,
			wantPath:   "/v1/auth/jwt/role/ci",
		},
		{
			name: "JWT config",
			call: func(c *restClient) error {
				return c.WriteJWTConfig(t.Context(), "jwt", &JWTAuthConfig{BoundIssuer: "https://x"})
			},
			wantMethod: http.MethodPost,
			wantPath:   "/v1/auth/jwt/config",
		},
		{
			name: "AWS auth config is config/client",
			call: func(c *restClient) error {
				return c.WriteAWSConfig(t.Context(), "aws", &AWSAuthConfig{STSRegion: "us-east-1"})
			},
			wantMethod: http.MethodPost,
			wantPath:   "/v1/auth/aws/config/client",
			why:        "the AWS auth method has several config endpoints; the others configure nothing that matters here",
		},
		{
			name:       "secrets engine mount",
			call:       func(c *restClient) error { return c.EnableSecretsEngine(t.Context(), "aws", "aws", nil) },
			wantMethod: http.MethodPost,
			wantPath:   "/v1/sys/mounts/aws",
		},
		{
			name: "secrets role uses the PLURAL roles",
			call: func(c *restClient) error {
				return c.WriteAWSSecretsRole(t.Context(), "aws", "deploy", &AWSSecretsRole{CredentialType: "assumed_role"})
			},
			wantMethod: http.MethodPost,
			wantPath:   "/v1/aws/roles/deploy",
			why:        "secrets engines use roles/, auth methods use role/ — a 404 on a mount that exists",
		},
		{
			name: "policies live under sys/policies/acl",
			call: func(c *restClient) error {
				return c.WritePolicy(t.Context(), "ci", "path \"secret/*\" { capabilities = [\"read\"] }")
			},
			wantMethod: http.MethodPut,
			wantPath:   "/v1/sys/policies/acl/ci",
		},
		{
			name:       "a trailing slash on a mount does not double up",
			call:       func(c *restClient) error { return c.DisableAuthMethod(t.Context(), "/jwt/") },
			wantMethod: http.MethodDelete,
			wantPath:   "/v1/sys/auth/jwt",
			why:        "Vault treats jwt and jwt/ as one mount, but a doubled slash is a 404",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeVaultServer(t)
			f.respond(func(_ *recordedRequest, w http.ResponseWriter) {
				writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
					"type": "jwt", "policy": "x", "credential_type": "assumed_role",
				}})
			})

			if err := tc.call(f.client(t)); err != nil {
				t.Fatalf("call: %v", err)
			}
			got := f.last()
			if got.Method != tc.wantMethod || got.Path != tc.wantPath {
				t.Errorf("%s %s, want %s %s\n%s", got.Method, got.Path, tc.wantMethod, tc.wantPath, tc.why)
			}
		})
	}
}

// The credential endpoints are separate for a reason: creds and sts issue
// different credential kinds, and assumed_role needs the sts one.
func TestAWSCredentialEndpoints(t *testing.T) {
	f := newFakeVaultServer(t)
	f.respond(func(_ *recordedRequest, w http.ResponseWriter) {
		writeJSON(w, http.StatusOK, map[string]any{
			"lease_id": "aws/creds/deploy/abc", "lease_duration": 3600,
			"data": map[string]any{
				"access_key": "ASIAEXAMPLE", "secret_key": "s3cret", "security_token": "tok",
			},
		})
	})
	c := f.client(t)

	if _, err := c.GenerateAWSCredentials(t.Context(), "aws", "deploy"); err != nil {
		t.Fatalf("GenerateAWSCredentials: %v", err)
	}
	if got := f.last().Path; got != "/v1/aws/creds/deploy" {
		t.Errorf("creds path = %q", got)
	}

	creds, err := c.GenerateAWSSTSCredentials(t.Context(), "aws", "deploy",
		"arn:aws:iam::123456789012:role/target", "15m")
	if err != nil {
		t.Fatalf("GenerateAWSSTSCredentials: %v", err)
	}
	last := f.last()
	if last.Path != "/v1/aws/sts/deploy" {
		t.Errorf("sts path = %q, want /v1/aws/sts/deploy", last.Path)
	}
	if !strings.Contains(last.Query, "role_arn=") || !strings.Contains(last.Query, "ttl=15m") {
		t.Errorf("query = %q, want role_arn and ttl", last.Query)
	}
	// security_token is Vault's field name; the domain type calls it SessionToken.
	if creds.SessionToken != "tok" {
		t.Errorf("SessionToken = %q, want the security_token field mapped through", creds.SessionToken)
	}
	if creds.LeaseID != "aws/creds/deploy/abc" {
		t.Errorf("LeaseID = %q, want it carried from the envelope", creds.LeaseID)
	}
}

// Every request must carry the token, and the Enterprise namespace when one is
// configured. A missing namespace header on Enterprise resolves the path in the
// root namespace, which either 404s or — worse — hits a different real mount.
func TestHeaders(t *testing.T) {
	f := newFakeVaultServer(t)
	c := f.client(t, WithNamespace("team-a"))

	if err := c.DisableAuthMethod(t.Context(), "jwt"); err != nil {
		t.Fatalf("call: %v", err)
	}
	got := f.last()
	if got.Token != "test-token" {
		t.Errorf("%s = %q, want the configured token", tokenHeader, got.Token)
	}
	if got.Namespace != "team-a" {
		t.Errorf("%s = %q, want team-a", namespaceHeader, got.Namespace)
	}
}

// No namespace configured means no header at all, not an empty one.
func TestNoNamespaceHeaderWhenUnset(t *testing.T) {
	f := newFakeVaultServer(t)
	if err := f.client(t).DisableAuthMethod(t.Context(), "jwt"); err != nil {
		t.Fatalf("call: %v", err)
	}
	if got := f.last().Namespace; got != "" {
		t.Errorf("%s = %q, want it absent", namespaceHeader, got)
	}
}

// Vault answers a missing path with 404 and an EMPTY errors array, and a denied
// one with 403. Conflating them is how a create-or-update decision goes wrong.
func TestErrorClassification(t *testing.T) {
	for _, tc := range []struct {
		name         string
		status       int
		body         any
		wantNotFound bool
		wantSealed   bool
	}{
		{"missing path", http.StatusNotFound, map[string]any{"errors": []string{}}, true, false},
		{"permission denied", http.StatusForbidden,
			map[string]any{"errors": []string{"permission denied"}}, false, false},
		{"sealed", http.StatusServiceUnavailable,
			map[string]any{"errors": []string{"Vault is sealed"}}, false, true},
		{"standby", http.StatusServiceUnavailable,
			map[string]any{"errors": []string{"Vault is in standby mode"}}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeVaultServer(t)
			f.respond(func(_ *recordedRequest, w http.ResponseWriter) {
				writeJSON(w, tc.status, tc.body)
			})

			_, err := f.client(t).ReadJWTRole(t.Context(), "jwt", "ci")
			if err == nil {
				t.Fatal("want an error")
			}
			var apiErr *apiError
			if !errors.As(err, &apiErr) {
				t.Fatalf("not an *apiError: %T", err)
			}
			if apiErr.NotFound() != tc.wantNotFound {
				t.Errorf("NotFound() = %v, want %v", apiErr.NotFound(), tc.wantNotFound)
			}
			if apiErr.Sealed() != tc.wantSealed {
				t.Errorf("Sealed() = %v, want %v — a sealed Vault is not a misconfiguration, "+
					"and reporting it as one sends the operator to read their policy",
					apiErr.Sealed(), tc.wantSealed)
			}
			if tc.status == http.StatusForbidden && !apiErr.Forbidden() {
				t.Error("Forbidden() = false for a 403")
			}
		})
	}
}

// Vault echoes request material into some errors, and a token in one is a live
// credential.
func TestErrorBodyIsRedacted(t *testing.T) {
	const token = "hvs.CAESIJlonGSecretTokenMaterialThatIsLongEnoughToLookLikeACredential1234"
	f := newFakeVaultServer(t)
	f.respond(func(_ *recordedRequest, w http.ResponseWriter) {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"errors": []string{"permission denied for token " + token},
		})
	})

	_, err := f.client(t).ReadJWTRole(t.Context(), "jwt", "ci")
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), "SecretTokenMaterialThatIsLongEnoughToLookLikeACredential1234") {
		t.Errorf("the token survived into the error: %v", err)
	}
	// ...but the error must stay diagnosable.
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("error is no longer diagnosable: %v", err)
	}
}

// A successful write answers 204 with no body. That is success, not a decode
// failure.
func TestEmptyResponseIsNotAnError(t *testing.T) {
	f := newFakeVaultServer(t)
	f.respond(func(_ *recordedRequest, w http.ResponseWriter) {
		w.WriteHeader(http.StatusNoContent)
	})
	if err := f.client(t).WriteJWTRole(t.Context(), "jwt", "ci", &JWTRole{UserClaim: "sub"}); err != nil {
		t.Errorf("a 204 write was reported as an error: %v", err)
	}
}

// Token creation reads the auth block, not data. Reading the wrong one returns
// an empty token and no error, which fails much later and somewhere else.
func TestCreateTokenReadsTheAuthBlock(t *testing.T) {
	f := newFakeVaultServer(t)
	f.respond(func(_ *recordedRequest, w http.ResponseWriter) {
		writeJSON(w, http.StatusOK, map[string]any{
			"data": nil,
			"auth": map[string]any{
				"client_token": "hvs.newtoken", "accessor": "acc",
				"policies": []string{"default", "ci"}, "lease_duration": 3600, "renewable": true,
			},
		})
	})

	tok, err := f.client(t).CreateToken(t.Context(), &CreateTokenOptions{
		Policies: []string{"ci"}, TTL: "1h", Renewable: true,
	})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if tok.Token != "hvs.newtoken" {
		t.Errorf("Token = %q", tok.Token)
	}
	if !tok.Renewable || tok.LeaseDuration != 3600 {
		t.Errorf("lease fields not mapped: %+v", tok)
	}
}

// A response with no auth block must be an error, not a TokenResponse holding
// an empty string that fails at the point of use.
func TestCreateTokenRejectsAMissingAuthBlock(t *testing.T) {
	f := newFakeVaultServer(t)
	f.respond(func(_ *recordedRequest, w http.ResponseWriter) {
		writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{}})
	})
	if _, err := f.client(t).CreateToken(t.Context(), nil); err == nil {
		t.Error("want an error when the response carries no auth block")
	}
}

// VAULT_ADDR and VAULT_TOKEN are the documented configuration and there is no
// discovery chain behind them. Guessing an address would mean sending a token
// somewhere the operator did not name.
func TestNewClientRequiresAddressAndToken(t *testing.T) {
	for _, tc := range []struct {
		name   string
		opts   []ClientOption
		errHas string
	}{
		{"no address", []ClientOption{WithAddress(""), WithToken("t")}, "VAULT_ADDR is not set"},
		{"no token", []ClientOption{WithAddress("https://vault.example.com"), WithToken("")}, "VAULT_TOKEN is not set"},
		{"not a URL", []ClientOption{WithAddress("://nope"), WithToken("t")}, "VAULT_ADDR"},
		{"wrong scheme", []ClientOption{WithAddress("ftp://vault.example.com"), WithToken("t")}, "must be http or https"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewClient(tc.opts...); err == nil {
				t.Fatal("want an error")
			} else if !strings.Contains(err.Error(), tc.errHas) {
				t.Errorf("error = %q, want it to contain %q", err, tc.errHas)
			}
		})
	}
}

// Without configuration the provider must say so, and must not claim the feature
// is unimplemented — which is what "client not configured" used to mean.
func TestRequireClientReportsConfigurationFailure(t *testing.T) {
	p := New()
	p.resolveFailed = errors.New("vault: VAULT_ADDR is not set")

	err := p.requireClient()
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "could not reach Vault") {
		t.Errorf("error = %q, want it to name the configuration problem", err)
	}
	if !core.IsCategory(err, core.ErrCategoryValidation) {
		t.Errorf("category = %v", core.CategoryOf(err))
	}
}
