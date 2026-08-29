package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// A fake GCP. The wire shapes here are the documented ones — the LRO envelope,
// the error envelope, the IAM policy etag — because the point of these tests is
// that this client speaks the real protocol, not that it round-trips its own
// assumptions.

type fakeGCP struct {
	t       *testing.T
	mux     *http.ServeMux
	server  *httptest.Server
	calls   atomic.Int32
	lastReq map[string]any
}

func newFakeGCP(t *testing.T) *fakeGCP {
	t.Helper()
	f := &fakeGCP{t: t, mux: http.NewServeMux()}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		if r.Body != nil {
			raw, _ := io.ReadAll(r.Body)
			if len(raw) > 0 {
				var decoded map[string]any
				_ = json.Unmarshal(raw, &decoded)
				f.lastReq = decoded
			}
		}
		f.mux.ServeHTTP(w, r)
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeGCP) handle(pattern string, fn http.HandlerFunc) { f.mux.HandleFunc(pattern, fn) }

func (f *fakeGCP) json(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		f.t.Fatalf("encode: %v", err)
	}
}

// client returns a restClient pointed at the fake, with a static token so no
// real credential resolution happens.
func (f *fakeGCP) client(t *testing.T) *restClient {
	t.Helper()
	base := f.server.URL
	clients, err := NewClients(context.Background(),
		WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"})),
		WithEndpoints(base+"/v1", base+"/sts/v1", base+"/credentials/v1"),
	)
	if err != nil {
		t.Fatalf("NewClients: %v", err)
	}
	c := clients.IAM.(*restClient)
	c.pollInterval = time.Millisecond // do not sleep a second per poll in tests
	return c
}

// A 404 must be recoverable as absence WITHOUT matching on strings. Setup's
// create-or-update decision and the rollback both branch on this, and the
// rollback used to be destructive when "could not tell" read as "does not
// exist".
func TestAPIErrorIsTypedNotFound(t *testing.T) {
	f := newFakeGCP(t)
	f.handle("/v1/projects/p/locations/global/workloadIdentityPools/missing", func(w http.ResponseWriter, _ *http.Request) {
		f.json(w, http.StatusNotFound, map[string]any{
			"error": map[string]any{
				"code": 404, "status": "NOT_FOUND",
				"message": "Requested entity was not found.",
			},
		})
	})

	_, err := f.client(t).GetWorkloadIdentityPool(context.Background(),
		"projects/p/locations/global/workloadIdentityPools/missing")
	if err == nil {
		t.Fatal("want an error")
	}

	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error is not *apiError: %T", err)
	}
	if !apiErr.NotFound() {
		t.Error("NotFound() = false for a 404 NOT_FOUND")
	}
	if !isNotFoundError(err) {
		t.Error("isNotFoundError = false; the typed path did not fire")
	}
}

func TestAPIErrorDistinguishesPermissionFromAbsence(t *testing.T) {
	f := newFakeGCP(t)
	f.handle("/v1/projects/p/locations/global/workloadIdentityPools/denied", func(w http.ResponseWriter, _ *http.Request) {
		f.json(w, http.StatusForbidden, map[string]any{
			"error": map[string]any{
				"code": 403, "status": "PERMISSION_DENIED",
				"message": "Permission iam.workloadIdentityPools.get denied.",
			},
		})
	})

	_, err := f.client(t).GetWorkloadIdentityPool(context.Background(),
		"projects/p/locations/global/workloadIdentityPools/denied")
	if err == nil {
		t.Fatal("want an error")
	}
	// This is the distinction the destructive-rollback fix depends on: a denied
	// read is NOT evidence the pool is absent.
	if isNotFoundError(err) {
		t.Errorf("a 403 read as absence: %v", err)
	}
}

// Pool creation is a long-running operation. Returning as soon as the API
// accepts the request would leave Setup binding IAM against a pool that is not
// yet a valid principal set.
func TestCreatePoolAwaitsTheOperation(t *testing.T) {
	f := newFakeGCP(t)
	const poolName = "projects/123/locations/global/workloadIdentityPools/ci"
	const opName = poolName + "/operations/op1"
	var polls atomic.Int32

	f.handle("/v1/projects/123/locations/global/workloadIdentityPools", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("workloadIdentityPoolId"); got != "ci" {
			t.Errorf("workloadIdentityPoolId = %q, want ci", got)
		}
		f.json(w, http.StatusOK, map[string]any{
			"name": opName,
			"done": false,
		})
	})
	f.handle("/v1/projects/123/locations/global/workloadIdentityPools/ci/operations/op1",
		func(w http.ResponseWriter, _ *http.Request) {
			// Pending twice, then done — the shape a real LRO has.
			if polls.Add(1) < 3 {
				f.json(w, http.StatusOK, map[string]any{"name": opName, "done": false})
				return
			}
			f.json(w, http.StatusOK, map[string]any{
				"name": opName,
				"done": true,
				"response": map[string]any{
					"name": poolName, "displayName": "CI pool", "state": "ACTIVE",
				},
			})
		})

	pool, err := f.client(t).CreateWorkloadIdentityPool(context.Background(),
		"projects/123/locations/global", "ci", &WorkloadIdentityPool{DisplayName: "CI pool"})
	if err != nil {
		t.Fatalf("CreateWorkloadIdentityPool: %v", err)
	}
	if polls.Load() < 3 {
		t.Errorf("polled %d times; the operation was not awaited to completion", polls.Load())
	}
	if pool.Name != poolName {
		t.Errorf("Name = %q, want %q", pool.Name, poolName)
	}
	if pool.State != "ACTIVE" {
		t.Errorf("State = %q, want ACTIVE", pool.State)
	}
}

// A failed operation must surface as an error, not as a successfully created
// resource with empty fields.
func TestAwaitSurfacesOperationFailure(t *testing.T) {
	f := newFakeGCP(t)
	f.handle("/v1/projects/123/locations/global/workloadIdentityPools", func(w http.ResponseWriter, _ *http.Request) {
		f.json(w, http.StatusOK, map[string]any{
			"done": true,
			"error": map[string]any{
				"code": 9, "status": "FAILED_PRECONDITION",
				"message": "the pool id is reserved by a recent soft-delete",
			},
		})
	})

	_, err := f.client(t).CreateWorkloadIdentityPool(context.Background(),
		"projects/123/locations/global", "ci", nil)
	if err == nil {
		t.Fatal("want an error from a failed operation")
	}
	if !strings.Contains(err.Error(), "soft-delete") {
		t.Errorf("error lost the cause: %v", err)
	}
}

// The etag read by GetIAMPolicy must be sent back, or two concurrent grants
// silently drop one — and on a service account, what gets dropped is access.
func TestSetIAMPolicySendsTheEtagBack(t *testing.T) {
	f := newFakeGCP(t)
	const resource = "projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com"

	f.handle("/v1/"+resource+":getIamPolicy", func(w http.ResponseWriter, _ *http.Request) {
		f.json(w, http.StatusOK, map[string]any{
			"version": 3,
			"etag":    "BwXhP0mQ1A0=",
			"bindings": []map[string]any{{
				"role":    "roles/iam.workloadIdentityUser",
				"members": []string{"principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/ci/*"},
			}},
		})
	})
	f.handle("/v1/"+resource+":setIamPolicy", func(w http.ResponseWriter, _ *http.Request) {
		f.json(w, http.StatusOK, map[string]any{"etag": "BwXhP0mQ1A0="})
	})

	c := f.client(t)
	ctx := context.Background()

	policy, err := c.GetIAMPolicy(ctx, resource)
	if err != nil {
		t.Fatalf("GetIAMPolicy: %v", err)
	}
	if policy.Etag != "BwXhP0mQ1A0=" {
		t.Fatalf("Etag = %q, want it carried through", policy.Etag)
	}
	if len(policy.Bindings) != 1 || policy.Bindings[0].Role != "roles/iam.workloadIdentityUser" {
		t.Fatalf("bindings not decoded: %+v", policy.Bindings)
	}

	if err := c.SetIAMPolicy(ctx, resource, policy); err != nil {
		t.Fatalf("SetIAMPolicy: %v", err)
	}
	sent, ok := f.lastReq["policy"].(map[string]any)
	if !ok {
		t.Fatalf("no policy in the request: %+v", f.lastReq)
	}
	if sent["etag"] != "BwXhP0mQ1A0=" {
		t.Errorf("etag = %v, want the one that was read (this is a blind overwrite otherwise)", sent["etag"])
	}
	// Version 3 or conditions on the existing policy are silently dropped.
	if v, _ := sent["version"].(float64); int(v) != policyVersion {
		t.Errorf("version = %v, want %d (a lower version discards conditional bindings)", sent["version"], policyVersion)
	}
}

// getIamPolicy must ASK for version 3, or the response omits conditions and the
// read-modify-write strips somebody else's condition.
func TestGetIAMPolicyRequestsVersion3(t *testing.T) {
	f := newFakeGCP(t)
	const resource = "projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com"
	f.handle("/v1/"+resource+":getIamPolicy", func(w http.ResponseWriter, _ *http.Request) {
		f.json(w, http.StatusOK, map[string]any{"etag": "x"})
	})

	if _, err := f.client(t).GetIAMPolicy(context.Background(), resource); err != nil {
		t.Fatalf("GetIAMPolicy: %v", err)
	}
	opts, ok := f.lastReq["options"].(map[string]any)
	if !ok {
		t.Fatalf("no options in request: %+v", f.lastReq)
	}
	if v, _ := opts["requestedPolicyVersion"].(float64); int(v) != policyVersion {
		t.Errorf("requestedPolicyVersion = %v, want %d", opts["requestedPolicyVersion"], policyVersion)
	}
}

// The STS token endpoint takes no caller credential — the subject token IS the
// proof. Attaching an ADC bearer would put a second, more privileged identity on
// a request that does not need one.
func TestExchangeTokenSendsNoBearerHeader(t *testing.T) {
	f := newFakeGCP(t)
	var sawAuth string
	f.handle("/sts/v1/token", func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		f.json(w, http.StatusOK, map[string]any{
			"access_token": "ya29.federated", "token_type": "Bearer", "expires_in": 3600,
		})
	})

	out, err := f.client(t).ExchangeToken(context.Background(), &ExchangeTokenInput{
		Audience:         "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/ci/providers/gh",
		SubjectToken:     "header.payload.signature",
		SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
	})
	if err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	if sawAuth != "" {
		t.Errorf("Authorization header sent to the STS endpoint: %q", sawAuth)
	}
	if out.AccessToken != "ya29.federated" {
		t.Errorf("AccessToken = %q", out.AccessToken)
	}
	// Defaults must be filled in rather than sent empty.
	if f.lastReq["grantType"] != "urn:ietf:params:oauth:grant-type:token-exchange" {
		t.Errorf("grantType = %v", f.lastReq["grantType"])
	}
}

// STS error bodies echo the assertion back. Keeping the diagnosis while dropping
// the credential is the same trade target/redaction_test.go makes.
func TestExchangeTokenRedactsTheEchoedAssertion(t *testing.T) {
	f := newFakeGCP(t)
	const assertion = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyZXBvOm9yZy9yZXBvIn0.c2lnbmF0dXJlLXRoYXQtaXMtdmVyeS1sb25nLWFuZC1zZWNyZXQtMTIzNDU2Nzg5MA"
	f.handle("/sts/v1/token", func(w http.ResponseWriter, _ *http.Request) {
		f.json(w, http.StatusBadRequest, map[string]any{
			"error":             "invalid_grant",
			"error_description": "The subject token " + assertion + " is invalid.",
		})
	})

	_, err := f.client(t).ExchangeToken(context.Background(), &ExchangeTokenInput{
		Audience: "//iam.googleapis.com/projects/1/x", SubjectToken: assertion,
	})
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), "c2lnbmF0dXJlLXRoYXQtaXMtdmVyeS1sb25nLWFuZC1zZWNyZXQtMTIzNDU2Nzg5MA") {
		t.Errorf("the assertion survived into the error: %v", err)
	}
	// ...but the error must still be diagnosable, or we have traded a leak for
	// an unusable message.
	if !strings.Contains(err.Error(), "invalid_grant") && !strings.Contains(err.Error(), "400") {
		t.Errorf("error is no longer diagnosable: %v", err)
	}
}

func TestGenerateIDTokenRequiresAnAudience(t *testing.T) {
	f := newFakeGCP(t)
	_, err := f.client(t).GenerateIDToken(context.Background(), &GenerateIDTokenInput{
		ServiceAccountEmail: "sa@p.iam.gserviceaccount.com",
	})
	if err == nil {
		t.Fatal("want an error: an ID token with no audience is unverifiable by any recipient")
	}
	if f.calls.Load() != 0 {
		t.Error("the request was sent anyway")
	}
}

// GCP's mapping limits, checked before the call. The API rejects an over-limit
// mapping with a message naming the ceiling but not the offending entry — and by
// then the pool exists, so the operator is rolling back a half-built setup.
func TestCheckAttributeMapping(t *testing.T) {
	many := map[string]string{"google.subject": "assertion.sub"}
	for i := range maxAttributeMappings {
		many[fmt.Sprintf("attribute.k%d", i)] = "assertion.x"
	}

	huge := map[string]string{"google.subject": "assertion.sub"}
	huge["attribute.big"] = strings.Repeat("a", maxAttributeMappingBytes)

	for _, tc := range []struct {
		name    string
		mapping map[string]string
		errHas  string
	}{
		{"empty is left to the API", nil, ""},
		{"a normal mapping", map[string]string{
			"google.subject":       "assertion.sub",
			"attribute.repository": "assertion.repository",
		}, ""},
		{"too many mappings", many, "exceeds the limit of 50"},
		{"mapping too large", huge, "over the 8192-byte limit"},
		{"no google.subject", map[string]string{"attribute.repo": "assertion.repository"}, "must include google.subject"},
		{"literal subject over 127 bytes", map[string]string{
			"google.subject": `"` + strings.Repeat("x", maxMappedSubjectBytes+1) + `"`,
		}, "over the 127-byte limit"},
		{"a long expression is not a long value", map[string]string{
			"google.subject": "assertion.repository + '/' + assertion.ref + '/' + " + strings.Repeat("assertion.a + ", 20) + "assertion.b",
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkAttributeMapping(tc.mapping)
			if tc.errHas == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want an error containing %q", tc.errHas)
			}
			if !strings.Contains(err.Error(), tc.errHas) {
				t.Errorf("error = %q, want it to contain %q", err, tc.errHas)
			}
		})
	}
}

// An over-limit mapping must be refused before the provider is created, not
// after.
func TestCreateProviderChecksMappingBeforeCalling(t *testing.T) {
	f := newFakeGCP(t)
	_, err := f.client(t).CreateWorkloadIdentityPoolProvider(context.Background(),
		"projects/123/locations/global/workloadIdentityPools/ci", "gh",
		&WorkloadIdentityPoolProvider{
			AttributeMapping: map[string]string{"attribute.repo": "assertion.repository"},
			OIDC:             &OIDCProviderConfig{IssuerURI: "https://token.actions.githubusercontent.com"},
		})
	if err == nil {
		t.Fatal("want an error for a mapping with no google.subject")
	}
	if f.calls.Load() != 0 {
		t.Errorf("the provider was created anyway (%d calls)", f.calls.Load())
	}
}

// Without credentials the provider must say so — and must not claim the feature
// is unimplemented, which is what "client not configured" used to mean.
func TestRequireClientsReportsCredentialFailure(t *testing.T) {
	p := New()
	p.resolveFailed = errors.New("google: could not find default credentials")

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
