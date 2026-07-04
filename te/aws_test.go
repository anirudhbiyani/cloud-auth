package te

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
)

const successXML = `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>ASIA123</AccessKeyId>
      <SecretAccessKey>secretkey</SecretAccessKey>
      <SessionToken>sessiontoken</SessionToken>
      <Expiration>2026-07-04T13:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
  <ResponseMetadata><RequestId>req-abc-123</RequestId></ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>`

const accessDeniedXML = `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error><Type>Sender</Type><Code>AccessDenied</Code>
    <Message>Not authorized to perform sts:AssumeRoleWithWebIdentity</Message></Error>
  <RequestId>req-err-1</RequestId>
</ErrorResponse>`

func awsTarget() cloudauth.Target {
	return cloudauth.Target{Cloud: cloudauth.AWS, Role: "arn:aws:iam::123:role/reader", Audience: "sts.amazonaws.com"}
}

func oidcToken() *cloudauth.SourceToken {
	return &cloudauth.SourceToken{Kind: cloudauth.OIDC, Value: "eyJ.payload.sig", Audience: "sts.amazonaws.com"}
}

func TestAWSExchangeSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("Action") != "AssumeRoleWithWebIdentity" {
			t.Errorf("Action = %q", r.FormValue("Action"))
		}
		if r.FormValue("WebIdentityToken") != "eyJ.payload.sig" {
			t.Errorf("token not forwarded: %q", r.FormValue("WebIdentityToken"))
		}
		w.Write([]byte(successXML))
	}))
	defer srv.Close()

	e := NewAWSExchanger(WithAWSEndpoint(srv.URL), WithAWSHTTPClient(srv.Client()))
	creds, err := e.Exchange(context.Background(), oidcToken(), awsTarget())
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if creds.AccessKeyID != "ASIA123" || creds.SecretAccessKey != "secretkey" || creds.SessionToken != "sessiontoken" {
		t.Errorf("creds not parsed: %+v", creds)
	}
	if creds.STSRequestID != "req-abc-123" {
		t.Errorf("request id = %q, want req-abc-123", creds.STSRequestID)
	}
}

func TestAWSExchangeAccessDeniedNotRetried(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(accessDeniedXML))
	}))
	defer srv.Close()

	e := NewAWSExchanger(WithAWSEndpoint(srv.URL), WithAWSHTTPClient(srv.Client()))
	_, err := e.Exchange(context.Background(), oidcToken(), awsTarget())
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, cloudauth.ErrTrustMissing) {
		t.Errorf("err = %v, want it to wrap ErrTrustMissing", err)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("made %d calls; a 4xx trust error must NOT be retried", n)
	}
}

func TestAWSExchangeRetriesOn5xx(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write([]byte(successXML))
	}))
	defer srv.Close()

	e := NewAWSExchanger(WithAWSEndpoint(srv.URL), WithAWSHTTPClient(srv.Client()), WithAWSMaxRetries(3))
	creds, err := e.Exchange(context.Background(), oidcToken(), awsTarget())
	if err != nil {
		t.Fatalf("Exchange after retries: %v", err)
	}
	if creds.AccessKeyID != "ASIA123" {
		t.Error("expected success after 5xx retries")
	}
	if n := atomic.LoadInt32(&calls); n != 3 {
		t.Errorf("made %d calls, want 3 (2 failures + 1 success)", n)
	}
}

func TestAWSExchangeRejectsSigV4Token(t *testing.T) {
	// AWS WebIdentity accepts only OIDC JWTs, not a SigV4 proof.
	e := NewAWSExchanger()
	_, err := e.Exchange(context.Background(), &cloudauth.SourceToken{Kind: cloudauth.AWSSigV4}, awsTarget())
	if err == nil {
		t.Fatal("expected error exchanging a SigV4 proof at AWS")
	}
}
