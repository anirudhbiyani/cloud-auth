package target

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

func serve(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A 2xx whose body does not carry credentials is a failure, not a success with empty fields.
func TestAWSExchangeRejectsSuccessWithoutCredentials(t *testing.T) {
	srv := serve(t, 200, `<AssumeRoleWithWebIdentityResponse>
	  <ResponseMetadata><RequestId>req-empty</RequestId></ResponseMetadata>
	</AssumeRoleWithWebIdentityResponse>`)

	_, err := NewAWSExchanger(WithAWSEndpoint(srv.URL)).
		Exchange(context.Background(), oidcToken(), awsTarget())
	if err == nil {
		t.Fatal("want an error for a 2xx with no credentials")
	}
	if !strings.Contains(err.Error(), "no credentials") {
		t.Errorf("error should say what was missing, got: %v", err)
	}
	if !strings.Contains(err.Error(), "req-empty") {
		t.Errorf("error should carry the STS request-id for support, got: %v", err)
	}
}

// An unparseable Expiration used to be discarded, yielding a zero Expiry — which Credentials.Expired then treated as "never expires", so the cache served dead credentials for the life of the process.
func TestAWSExchangeRejectsUnparseableExpiration(t *testing.T) {
	srv := serve(t, 200, `<AssumeRoleWithWebIdentityResponse>
	  <AssumeRoleWithWebIdentityResult><Credentials>
	    <AccessKeyId>ASIA123</AccessKeyId>
	    <SecretAccessKey>secretkey</SecretAccessKey>
	    <SessionToken>sessiontoken</SessionToken>
	    <Expiration>not-a-timestamp</Expiration>
	  </Credentials></AssumeRoleWithWebIdentityResult>
	  <ResponseMetadata><RequestId>req-bad-exp</RequestId></ResponseMetadata>
	</AssumeRoleWithWebIdentityResponse>`)

	_, err := NewAWSExchanger(WithAWSEndpoint(srv.URL)).
		Exchange(context.Background(), oidcToken(), awsTarget())
	if err == nil {
		t.Fatal("want an error for an unparseable Expiration, not credentials with a zero expiry")
	}
	if !strings.Contains(err.Error(), "not-a-timestamp") {
		t.Errorf("error should quote the offending value, got: %v", err)
	}
}

func TestGCPExchangeRejectsMissingExpiresIn(t *testing.T) {
	srv := serve(t, 200, `{"access_token":"ya29.federated"}`)

	const aud = "//iam.googleapis.com/projects/1/x"
	_, err := NewGCPExchanger(WithGCPSTSEndpoint(srv.URL)).Exchange(
		context.Background(), oidcTokenFor(aud),
		core.GCPTarget{WorkloadIdentityPool: "//iam.googleapis.com/projects/1/x", TokenAudience: aud})
	if err == nil {
		t.Fatal("want an error when expires_in is absent")
	}
	if !strings.Contains(err.Error(), "expires_in") {
		t.Errorf("error should name the missing field, got: %v", err)
	}
}

func TestGCPImpersonationRejectsUnparseableExpireTime(t *testing.T) {
	// One server answers both the STS exchange and the impersonation call.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "generateAccessToken") {
			_, _ = w.Write([]byte(`{"accessToken":"sa-token","expireTime":"whenever"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"ya29.federated","expires_in":3600}`))
	}))
	defer srv.Close()

	const aud = "//iam.googleapis.com/projects/1/x"
	_, err := NewGCPExchanger(WithGCPSTSEndpoint(srv.URL), WithGCPIAMEndpoint(srv.URL)).Exchange(
		context.Background(), oidcTokenFor(aud),
		core.GCPTarget{
			WorkloadIdentityPool:      "//iam.googleapis.com/projects/1/x",
			TokenAudience:             aud,
			ImpersonateServiceAccount: "sa@p.iam.gserviceaccount.com",
		})
	if err == nil {
		t.Fatal("want an error for an unparseable expireTime")
	}
	if !strings.Contains(err.Error(), "whenever") {
		t.Errorf("error should quote the offending value, got: %v", err)
	}
}

func TestAzureExchangeRejectsMissingExpiresIn(t *testing.T) {
	srv := serve(t, 200, `{"access_token":"entra-token"}`)

	_, err := NewAzureExchanger(WithAzureEndpoint(srv.URL)).Exchange(
		context.Background(), oidcTokenFor("api://AzureADTokenExchange"),
		core.AzureTarget{
			Tenant:   "11111111-1111-1111-1111-111111111111",
			ClientID: "22222222-2222-2222-2222-222222222222",
			Scope:    "https://storage.azure.com/.default",
		})
	if err == nil {
		t.Fatal("want an error when expires_in is absent")
	}
	if !strings.Contains(err.Error(), "expires_in") {
		t.Errorf("error should name the missing field, got: %v", err)
	}
}
