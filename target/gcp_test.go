package target

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

func gcpTarget() core.GCPTarget {
	return core.GCPTarget{
		WorkloadIdentityPool: "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/aws",
	}
}

func TestGCPExchangeDirectAccessOIDC(t *testing.T) {
	var gotSubjectType string
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSubjectType = r.FormValue("subject_token_type")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"gcp-federated-token","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer sts.Close()

	e := NewGCPExchanger(WithGCPSTSEndpoint(sts.URL), WithGCPHTTPClient(sts.Client()))
	creds, err := e.Exchange(context.Background(), oidcTokenFor(gcpTarget().Audience()), gcpTarget())
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if creds.AccessToken != "gcp-federated-token" {
		t.Errorf("access token = %q", creds.AccessToken)
	}
	if gotSubjectType != "urn:ietf:params:oauth:token-type:jwt" {
		t.Errorf("subject_token_type = %q, want jwt for OIDC", gotSubjectType)
	}
}

func TestGCPExchangeSigV4SubjectType(t *testing.T) {
	var gotSubjectType string
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSubjectType = r.FormValue("subject_token_type")
		w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
	}))
	defer sts.Close()

	sigv4 := &core.SourceToken{Kind: core.AWSSigV4, Value: `{"url":"x"}`, Audience: gcpTarget().Audience()}
	e := NewGCPExchanger(WithGCPSTSEndpoint(sts.URL), WithGCPHTTPClient(sts.Client()))
	if _, err := e.Exchange(context.Background(), sigv4, gcpTarget()); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if gotSubjectType != "urn:ietf:params:aws:token-type:aws4_request" {
		t.Errorf("subject_token_type = %q, want aws4_request for SigV4", gotSubjectType)
	}
}

func TestGCPExchangeImpersonation(t *testing.T) {
	var iamCalled bool
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token":"federated","expires_in":3600}`))
	}))
	defer sts.Close()
	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		iamCalled = true
		if !strings.Contains(r.URL.Path, "reader@proj.iam.gserviceaccount.com") {
			t.Errorf("impersonation path missing SA: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer federated" {
			t.Errorf("impersonation must use the federated token, got %q", r.Header.Get("Authorization"))
		}
		w.Write([]byte(`{"accessToken":"impersonated-token","expireTime":"2026-07-04T13:00:00Z"}`))
	}))
	defer iam.Close()

	target := gcpTarget()
	target.ImpersonateServiceAccount = "reader@proj.iam.gserviceaccount.com"
	e := NewGCPExchanger(WithGCPSTSEndpoint(sts.URL), WithGCPIAMEndpoint(iam.URL), WithGCPHTTPClient(sts.Client()))
	creds, err := e.Exchange(context.Background(), oidcTokenFor(target.Audience()), target)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if !iamCalled {
		t.Fatal("impersonation configured but generateAccessToken not called")
	}
	if creds.AccessToken != "impersonated-token" {
		t.Errorf("access token = %q, want impersonated-token", creds.AccessToken)
	}
}
