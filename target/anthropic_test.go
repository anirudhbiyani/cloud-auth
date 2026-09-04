package target

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// The Claude Platform's WIF exchanges an OIDC proof for a short-lived
// sk-ant-oat01-... token. Its protocol differs from every other token endpoint
// in this tree in one way that a form-encoded assumption would get wrong, and
// in one semantic that a caching assumption would get wrong.

func anthropicTarget() core.AnthropicTarget {
	return core.AnthropicTarget{
		FederationRuleID: "fdrl_test",
		OrganizationID:   "00000000-0000-0000-0000-000000000000",
		ServiceAccountID: "svac_test",
		WorkspaceID:      "wrkspc_test",
		TokenAudience:    "https://api.anthropic.com",
	}
}

func oidcProof(audience string) *core.SourceToken {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	jwt := enc(map[string]any{"alg": "RS256"}) + "." +
		enc(map[string]any{
			"iss": "https://token.actions.githubusercontent.com",
			"sub": "repo:myorg/myrepo:ref:refs/heads/main",
			"aud": audience, "jti": "unique-per-mint", "exp": 9999999999,
		}) + ".sig"
	return &core.SourceToken{
		Kind: core.OIDC, Value: jwt,
		Issuer:   "https://token.actions.githubusercontent.com",
		Subject:  "repo:myorg/myrepo:ref:refs/heads/main",
		Audience: audience, Expiry: time.Now().Add(time.Hour),
	}
}

func TestAnthropicExchange(t *testing.T) {
	var gotContentType string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "sk-ant-oat01-example", "token_type": "Bearer",
			"expires_in": 600, "scope": "workspace:developer",
		})
	}))
	defer srv.Close()

	e := NewAnthropicExchanger(WithAnthropicEndpoint(srv.URL),
		WithAnthropicHTTPClient(srv.Client()))
	creds, err := e.Exchange(context.Background(),
		oidcProof("https://api.anthropic.com"), anthropicTarget())
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	if creds.AccessToken != "sk-ant-oat01-example" {
		t.Errorf("AccessToken = %q", creds.AccessToken)
	}
	if creds.Cloud != core.Anthropic {
		t.Errorf("Cloud = %q", creds.Cloud)
	}
	if creds.Expiry.IsZero() {
		t.Error("no expiry was set; the cache treats a zero expiry as expired")
	}

	// JSON, not form-encoded. This is the one protocol difference from every
	// other token endpoint here, and a form gets a 400 that explains nothing.
	if !strings.Contains(gotContentType, "application/json") {
		t.Errorf("Content-Type = %q, want application/json — this endpoint does NOT take a form",
			gotContentType)
	}
	if gotBody["grant_type"] != jwtBearerGrant {
		t.Errorf("grant_type = %v, want %q", gotBody["grant_type"], jwtBearerGrant)
	}
	// The rule and the identity are named in the REQUEST, because Anthropic
	// holds the match conditions on the rule rather than on the resource.
	for field, want := range map[string]string{
		"federation_rule_id": "fdrl_test",
		"organization_id":    "00000000-0000-0000-0000-000000000000",
		"service_account_id": "svac_test",
		"workspace_id":       "wrkspc_test",
	} {
		if gotBody[field] != want {
			t.Errorf("%s = %v, want %q", field, gotBody[field], want)
		}
	}
	if gotBody["assertion"] == "" || gotBody["assertion"] == nil {
		t.Error("the assertion was not sent")
	}
}

// workspace_id is optional: the platform resolves it when the rule covers one
// workspace, and sending an empty string is not the same as omitting it.
func TestAnthropicOmitsAnEmptyWorkspace(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "t", "expires_in": 600})
	}))
	defer srv.Close()

	tgt := anthropicTarget()
	tgt.WorkspaceID = ""
	e := NewAnthropicExchanger(WithAnthropicEndpoint(srv.URL),
		WithAnthropicHTTPClient(srv.Client()))
	if _, err := e.Exchange(context.Background(),
		oidcProof("https://api.anthropic.com"), tgt); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if _, present := gotBody["workspace_id"]; present {
		t.Error("an empty workspace_id was sent as a field rather than omitted")
	}
}

// A jti-bearing identity token is single-use. The error must say so, and must
// point at the actual cause — a retry loop or a cached proof — rather than at
// the rule.
func TestAnthropicJTIReuseIsExplained(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{"type": "authentication_error", "reason": "jti_reused"},
		})
	}))
	defer srv.Close()

	e := NewAnthropicExchanger(WithAnthropicEndpoint(srv.URL),
		WithAnthropicHTTPClient(srv.Client()))
	_, err := e.Exchange(context.Background(),
		oidcProof("https://api.anthropic.com"), anthropicTarget())
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "single-use") {
		t.Errorf("the error does not explain jti single-use semantics: %v", err)
	}
	if !strings.Contains(err.Error(), "FRESH") {
		t.Errorf("the error does not say what to do: %v", err)
	}
	// It must NOT send the reader to look at the federation rule, which is the
	// wrong place entirely for this failure.
	if strings.Contains(err.Error(), "rule's conditions") {
		t.Errorf("a jti reuse was reported as a rule mismatch: %v", err)
	}
}

// A 401 that is NOT a jti reuse is a rule mismatch, and the message must say
// that rules are matched by id and never searched — otherwise the obvious
// assumption is that some other rule would have matched.
func TestAnthropicRefusalPointsAtTheNamedRule(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{"type": "permission_error", "message": "no matching rule"},
		})
	}))
	defer srv.Close()

	e := NewAnthropicExchanger(WithAnthropicEndpoint(srv.URL),
		WithAnthropicHTTPClient(srv.Client()))
	_, err := e.Exchange(context.Background(),
		oidcProof("https://api.anthropic.com"), anthropicTarget())
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "never searched") {
		t.Errorf("the error does not explain that rules are matched by id: %v", err)
	}
}

// A SigV4 proof cannot be verified against a JWKS, and the refusal must carry
// the sentinel so doctor recognises it and CategoryOf files it as configuration.
func TestAnthropicRejectsNonOIDCProof(t *testing.T) {
	e := NewAnthropicExchanger()
	_, err := e.Exchange(context.Background(),
		&core.SourceToken{Kind: core.AWSSigV4}, anthropicTarget())
	if err == nil {
		t.Fatal("want an error")
	}
	if !errors.Is(err, core.ErrNoFirstClassPath) {
		t.Errorf("error does not wrap ErrNoFirstClassPath: %v", err)
	}
	if got := core.CategoryOf(err); got != core.ErrCategoryValidation {
		t.Errorf("category = %q, want %q", got, core.ErrCategoryValidation)
	}
	for _, want := range []string{"sts:GetWebIdentityToken", "EKS IRSA", "GitHub Actions"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %q as a bridge: %v", want, err)
		}
	}
}

// A mis-audienced proof must not be transmitted. The target STS would reject it
// anyway, but only AFTER disclosure — and a federation rule may match on an
// exact audience, so the wrong one is a proof for somebody else.
func TestAnthropicRefusesAMisAudiencedProof(t *testing.T) {
	var reached bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "t", "expires_in": 600})
	}))
	defer srv.Close()

	e := NewAnthropicExchanger(WithAnthropicEndpoint(srv.URL),
		WithAnthropicHTTPClient(srv.Client()))
	_, err := e.Exchange(context.Background(),
		oidcProof("sts.amazonaws.com"), anthropicTarget())
	if err == nil {
		t.Fatal("want a refusal for a proof minted for another audience")
	}
	if reached {
		t.Error("the mis-audienced proof was transmitted before being refused")
	}
}

func TestAnthropicTargetValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*core.AnthropicTarget)
		errHas string
	}{
		{"missing rule id", func(t *core.AnthropicTarget) { t.FederationRuleID = "" }, "federation_rule_id is required"},
		{"rule id of the wrong shape", func(t *core.AnthropicTarget) { t.FederationRuleID = "svac_oops" }, "expected fdrl_"},
		{"missing organization", func(t *core.AnthropicTarget) { t.OrganizationID = "" }, "organization_id is required"},
		{"missing service account", func(t *core.AnthropicTarget) { t.ServiceAccountID = "" }, "service_account_id is required"},
		{"service account of the wrong shape", func(t *core.AnthropicTarget) { t.ServiceAccountID = "fdrl_oops" }, "expected svac_"},
		{"workspace of the wrong shape", func(t *core.AnthropicTarget) { t.WorkspaceID = "svac_oops" }, "expected wrkspc_"},
		// No default audience, deliberately: a rule may match on an exact one,
		// and guessing pins the proof to the wrong party.
		{"missing audience", func(t *core.AnthropicTarget) { t.TokenAudience = "" }, "no default"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tgt := anthropicTarget()
			tc.mutate(&tgt)
			err := tgt.Validate()
			if err == nil {
				t.Fatal("want a validation error")
			}
			if !strings.Contains(err.Error(), tc.errHas) {
				t.Errorf("error = %q, want it to contain %q", err, tc.errHas)
			}
		})
	}

	if err := anthropicTarget().Validate(); err != nil {
		t.Errorf("a well-formed target was rejected: %v", err)
	}
}

// The dispatcher has to know about it, or --to anthropic reports an unsupported
// cloud despite the exchanger existing.
func TestAnthropicIsDispatched(t *testing.T) {
	ex, err := For(core.Anthropic)
	if err != nil {
		t.Fatalf("For(anthropic): %v", err)
	}
	if _, ok := ex.(*AnthropicExchanger); !ok {
		t.Errorf("got %T, want *AnthropicExchanger", ex)
	}
}
