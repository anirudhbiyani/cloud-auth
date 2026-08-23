package target

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

func azureTarget() core.AzureTarget {
	return core.AzureTarget{
		Tenant:   "11111111-1111-1111-1111-111111111111",
		ClientID: "22222222-2222-2222-2222-222222222222",
		Scope:    "https://storage.azure.com/.default",
	}
}

func TestAzureExchangeSuccess(t *testing.T) {
	var gotAssertion, gotGrant, gotClient string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "11111111-1111-1111-1111-111111111111") {
			t.Errorf("path missing tenant: %s", r.URL.Path)
		}
		gotAssertion = r.FormValue("client_assertion")
		gotGrant = r.FormValue("grant_type")
		gotClient = r.FormValue("client_id")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"entra-token","expires_in":3599,"token_type":"Bearer"}`))
	}))
	defer srv.Close()

	e := NewAzureExchanger(WithAzureEndpoint(srv.URL), WithAzureHTTPClient(srv.Client()))
	creds, err := e.Exchange(context.Background(), oidcTokenFor(azureTarget().Audience()), azureTarget())
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if creds.AccessToken != "entra-token" {
		t.Errorf("access token = %q", creds.AccessToken)
	}
	if gotAssertion != "eyJ.payload.sig" {
		t.Errorf("client_assertion = %q, want the minted JWT", gotAssertion)
	}
	if gotGrant != "client_credentials" {
		t.Errorf("grant_type = %q", gotGrant)
	}
	if gotClient != azureTarget().ClientID {
		t.Errorf("client_id = %q", gotClient)
	}
}

func TestAzureRejectsSigV4WithBridgeGuidance(t *testing.T) {
	// The AWS-EC2 -> Azure gap: Azure accepts only RS256 OIDC, never SigV4.
	e := NewAzureExchanger()
	sigv4 := &core.SourceToken{Kind: core.AWSSigV4, Value: `{"url":"x"}`}
	_, err := e.Exchange(context.Background(), sigv4, azureTarget())
	if !errors.Is(err, core.ErrNoFirstClassPath) {
		t.Fatalf("err = %v, want ErrNoFirstClassPath", err)
	}
	msg := strings.ToLower(err.Error())
	for _, want := range []string{"cognito", "irsa", "oidc"} {
		if !strings.Contains(msg, want) {
			t.Errorf("gap message should mention %q bridge option; got %q", want, err.Error())
		}
	}
}
