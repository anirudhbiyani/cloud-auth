package target

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// A proof minted for one target must never reach another's STS. The remote side
// would reject it, but only after we had disclosed a usable assertion about our
// identity to a party that was not the intended audience.
func TestExchangeRefusesAProofMintedForAnotherTarget(t *testing.T) {
	var reached bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		_, _ = w.Write([]byte(`{"access_token":"t","expires_in":3600}`))
	}))
	defer srv.Close()

	// Minted for Azure, presented to GCP.
	tok := oidcTokenFor("api://AzureADTokenExchange")
	_, err := NewGCPExchanger(WithGCPSTSEndpoint(srv.URL)).Exchange(
		context.Background(), tok,
		core.GCPTarget{WorkloadIdentityPool: "//iam.googleapis.com/projects/1/x"})

	if err == nil {
		t.Fatal("want a refusal")
	}
	if !strings.Contains(err.Error(), "audience binding violation") {
		t.Errorf("unexpected error: %v", err)
	}
	if reached {
		t.Error("the proof was transmitted before the check; disclosure already happened")
	}
}

func TestExchangeAllowsAMatchingAudience(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"t","expires_in":3600}`))
	}))
	defer srv.Close()

	const aud = "//iam.googleapis.com/projects/1/x"
	if _, err := NewGCPExchanger(WithGCPSTSEndpoint(srv.URL)).Exchange(
		context.Background(), oidcTokenFor(aud),
		core.GCPTarget{WorkloadIdentityPool: "//iam.googleapis.com/projects/1/x", TokenAudience: aud}); err != nil {
		t.Fatalf("matching audience must be allowed: %v", err)
	}
}

// A token with no recorded audience cannot be checked, and we do not pretend to.
func TestExchangeAllowsATokenWithNoRecordedAudience(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"t","expires_in":3600}`))
	}))
	defer srv.Close()

	tok := &core.SourceToken{Kind: core.OIDC, Value: "eyJ.a.b"} // no Audience
	if _, err := NewGCPExchanger(WithGCPSTSEndpoint(srv.URL)).Exchange(
		context.Background(), tok,
		core.GCPTarget{WorkloadIdentityPool: "//iam.googleapis.com/projects/1/x"}); err != nil {
		t.Fatalf("unverifiable audience must not be treated as a mismatch: %v", err)
	}
}

func TestAzureTenantValidation(t *testing.T) {
	valid := []string{
		"11111111-1111-1111-1111-111111111111",
		"contoso.onmicrosoft.com",
		"example.co.uk",
	}
	invalid := []string{
		"common", "organizations", "consumers", "COMMON",
		"../../evil", "evil.com/x", "tenant-123", "", "  ",
		"11111111-1111-1111-1111-111111111111/../other",
		"tenant?x=1",
	}
	for _, v := range valid {
		if err := core.ValidateAzureTenant(v); err != nil {
			t.Errorf("core.ValidateAzureTenant(%q) = %v, want nil", v, err)
		}
	}
	for _, v := range invalid {
		if err := core.ValidateAzureTenant(v); err == nil {
			t.Errorf("core.ValidateAzureTenant(%q) = nil, want an error", v)
		}
	}
}

// A multi-tenant alias would mean "whichever tenant the assertion resolves to",
// which for a federated grant is precisely the decision we must not delegate.
func TestAzureExchangeRefusesMultiTenantAlias(t *testing.T) {
	_, err := NewAzureExchanger().Exchange(context.Background(),
		oidcTokenFor("api://AzureADTokenExchange"),
		core.AzureTarget{
			Tenant:   "common",
			ClientID: "22222222-2222-2222-2222-222222222222",
			Scope:    "https://storage.azure.com/.default",
		})
	if err == nil {
		t.Fatal("want a refusal for the common endpoint")
	}
	if !strings.Contains(err.Error(), "multi-tenant alias") {
		t.Errorf("unexpected error: %v", err)
	}
}
