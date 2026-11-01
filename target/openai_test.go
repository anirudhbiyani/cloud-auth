package target

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// OpenAI's WIF is RFC 8693 token exchange: the request names the provider and service account, the mapping grants the permissions.

func openaiTarget() core.OpenAITarget {
	return core.OpenAITarget{IdentityProviderID: "wip_test", ServiceAccountID: "sa_test"}
}

func TestOpenAIExchange(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "eyJ.example", "token_type": "Bearer",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"expires_in":        3600, "expires_at": 4102444800, "scope": "api.model.request",
		})
	}))
	defer srv.Close()

	e := NewOpenAIExchanger(WithOpenAIEndpoint(srv.URL), WithOpenAIHTTPClient(srv.Client()))
	creds, err := e.Exchange(context.Background(), oidcProof(core.DefaultOpenAIAudience), openaiTarget())
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if creds.Cloud != core.OpenAI || creds.AccessToken != "eyJ.example" {
		t.Errorf("creds = %+v", creds)
	}
	// expires_at is the token's own exp; it must win over the relative expires_in.
	if got := creds.Expiry.Unix(); got != 4102444800 {
		t.Errorf("Expiry = %d, want expires_at", got)
	}
	for k, want := range map[string]string{
		"grant_type":           tokenExchangeGrant,
		"subject_token_type":   jwtTokenType,
		"identity_provider_id": "wip_test",
		"service_account_id":   "sa_test",
	} {
		if gotBody[k] != want {
			t.Errorf("body[%s] = %v, want %q", k, gotBody[k], want)
		}
	}
	if gotBody["subject_token"] == "" {
		t.Error("subject_token was not sent")
	}
}

func TestOpenAIInvalidGrantIsExplained(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"no mapping"}`))
	}))
	defer srv.Close()
	e := NewOpenAIExchanger(WithOpenAIEndpoint(srv.URL), WithOpenAIHTTPClient(srv.Client()))
	_, err := e.Exchange(context.Background(), oidcProof(core.DefaultOpenAIAudience), openaiTarget())
	if err == nil || !strings.Contains(err.Error(), "mapping") {
		t.Fatalf("error = %v, want it to explain the mapping", err)
	}
}

func TestOpenAIRejectsNonOIDCProof(t *testing.T) {
	_, err := NewOpenAIExchanger().Exchange(context.Background(), &core.SourceToken{Kind: core.AWSSigV4}, openaiTarget())
	if !errors.Is(err, core.ErrNoFirstClassPath) {
		t.Fatalf("error = %v, want ErrNoFirstClassPath", err)
	}
}

func TestOpenAIRefusesAMisAudiencedProof(t *testing.T) {
	var reached bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "t", "expires_in": 600})
	}))
	defer srv.Close()
	e := NewOpenAIExchanger(WithOpenAIEndpoint(srv.URL), WithOpenAIHTTPClient(srv.Client()))
	if _, err := e.Exchange(context.Background(), oidcProof("sts.amazonaws.com"), openaiTarget()); err == nil {
		t.Fatal("want a refusal for a proof minted for another audience")
	}
	if reached {
		t.Error("the mis-audienced proof was transmitted before being refused")
	}
}

func TestOpenAITargetValidationAndDefaults(t *testing.T) {
	if got := openaiTarget().Audience(); got != core.DefaultOpenAIAudience {
		t.Errorf("Audience() = %q, want the documented default", got)
	}
	if err := (core.OpenAITarget{ServiceAccountID: "sa"}).Validate(); err == nil || !strings.Contains(err.Error(), "identity_provider_id") {
		t.Errorf("missing provider id not rejected: %v", err)
	}
	if err := (core.OpenAITarget{IdentityProviderID: "wip"}).Validate(); err == nil || !strings.Contains(err.Error(), "service_account_id") {
		t.Errorf("missing service account not rejected: %v", err)
	}
}

func TestOpenAIIsDispatched(t *testing.T) {
	ex, err := For(core.OpenAI)
	if err != nil {
		t.Fatalf("For(openai): %v", err)
	}
	if _, ok := ex.(*OpenAIExchanger); !ok {
		t.Errorf("got %T, want *OpenAIExchanger", ex)
	}
}
