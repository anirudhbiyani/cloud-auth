package target

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// The token endpoint echoes the assertion back inside its error description.
// Entra and Google both do variants of this, and the resulting error string
// travels all the way into the audit record the CLI writes to stderr.
const echoingErrorBody = `{"error":"invalid_client","error_description":"AADSTS700027: ` +
	`client assertion eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZXBvOm9yZy9yZXBvIn0.NOTAREALSIGNATURE ` +
	`failed signature validation."}`

func TestExchangeErrorsDoNotEchoTheAssertion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(echoingErrorBody))
	}))
	defer srv.Close()

	_, err := NewAzureExchanger(WithAzureEndpoint(srv.URL)).Exchange(
		context.Background(),
		&core.SourceToken{Kind: core.OIDC, Value: "eyJ.assertion.sig", Audience: "api://AzureADTokenExchange"},
		core.AzureTarget{
			Tenant:   "11111111-1111-1111-1111-111111111111",
			ClientID: "22222222-2222-2222-2222-222222222222",
			Scope:    "https://storage.azure.com/.default",
		})
	if err == nil {
		t.Fatal("want an error")
	}
	msg := err.Error()

	if strings.Contains(msg, "NOTAREALSIGNATURE") {
		t.Errorf("error echoed the assertion back:\n  %s", msg)
	}
	if !strings.Contains(msg, "[REDACTED]") {
		t.Errorf("error should show a redaction marker:\n  %s", msg)
	}
	// The diagnosis must survive redaction, or we have traded a leak for an
	// unusable error.
	for _, want := range []string{"AADSTS700027", "invalid_client", "400"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error dropped %q, which is what makes it actionable:\n  %s", want, msg)
		}
	}
}

func TestExchangeErrorsAreLengthCapped(t *testing.T) {
	huge := strings.Repeat("x", 20_000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"bad","detail":"` + huge + `"}`))
	}))
	defer srv.Close()

	_, err := NewAWSExchanger(WithAWSEndpoint(srv.URL)).
		Exchange(context.Background(), oidcToken(), awsTarget())
	if err == nil {
		t.Fatal("want an error")
	}
	if n := len(err.Error()); n > 2000 {
		t.Errorf("error is %d bytes; an error is a diagnostic, not a transcript", n)
	}
}
