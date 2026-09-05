package broker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/source"
	"github.com/anirudhbiyani/cloud-auth/target"
)

// End-to-end exercise of the GCP GCE -> AWS pair (first-class pair #1) through the real source, target and broker code, against fakes that mimic the two services closely enough to catch wiring mistakes:
func googleIDToken(t *testing.T, audience, saUniqueID string) string {
	t.Helper()
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header := map[string]any{"alg": "RS256", "kid": "abc", "typ": "JWT"}
	// A GCE service-account ID token sets sub AND azp to the SA's numeric unique id, and aud to whatever audience was requested.
	payload := map[string]any{
		"iss": "https://accounts.google.com",
		"aud": audience,
		"azp": saUniqueID,
		"sub": saUniqueID,
		"exp": 9999999999,
	}
	return enc(header) + "." + enc(payload) + ".signature"
}

func TestGCPToAWSEndToEnd(t *testing.T) {
	const (
		audience   = "sts.amazonaws.com"
		saUniqueID = "109876543210987654321"
		roleARN    = "arn:aws:iam::123456789012:role/cloud-auth-demo"
	)

	var gotAudienceParam, gotFormat string
	metadata := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			t.Errorf("metadata request missing Metadata-Flavor: Google header")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		// The real server echoes the header back, and the client requires it: that round trip is how a spoofed metadata.google.internal is detected.
		w.Header().Set("Metadata-Flavor", "Google")
		switch {
		case strings.Contains(r.URL.Path, "/identity"):
			gotAudienceParam = r.URL.Query().Get("audience")
			gotFormat = r.URL.Query().Get("format")
			_, _ = w.Write([]byte(googleIDToken(t, gotAudienceParam, saUniqueID)))
		default:
			// Detection probes (project id, etc.)
			_, _ = w.Write([]byte("demo-project"))
		}
	}))
	defer metadata.Close()

	var gotAction, gotRole, gotToken string
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotAction = r.FormValue("Action")
		gotRole = r.FormValue("RoleArn")
		gotToken = r.FormValue("WebIdentityToken")
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>ASIADEMO</AccessKeyId>
      <SecretAccessKey>demosecret</SecretAccessKey>
      <SessionToken>demosession</SessionToken>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
  <ResponseMetadata><RequestId>req-demo-1</RequestId></ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>`))
	}))
	defer sts.Close()

	gcp := source.NewGCP(
		source.WithGCPMetadataURL(metadata.URL),
		source.WithGCPHTTPClient(metadata.Client()),
		source.WithGCPEnv(func(string) string { return "" }),
	)
	b := New(
		WithRegistry(source.NewRegistry(gcp)),
		WithExchangerFor(func(core.Cloud) (core.Exchanger, error) {
			return target.NewAWSExchanger(
				target.WithAWSEndpoint(sts.URL),
				target.WithAWSHTTPClient(sts.Client()),
			), nil
		}),
	)

	creds, rt, err := b.Exchange(context.Background(), core.AWSTarget{
		RoleARN:       roleARN,
		TokenAudience: audience,
	})
	if err != nil {
		t.Fatalf("GCP->AWS exchange: %v", err)
	}

	// Source half.
	if rt.Cloud != core.GCP {
		t.Errorf("detected cloud = %s, want gcp", rt.Cloud)
	}
	if gotAudienceParam != audience {
		t.Errorf("metadata audience = %q, want %q — the token must be minted for the target", gotAudienceParam, audience)
	}
	if gotFormat != "full" {
		t.Errorf("metadata format = %q, want full", gotFormat)
	}

	// Target half.
	if gotAction != "AssumeRoleWithWebIdentity" {
		t.Errorf("STS Action = %q", gotAction)
	}
	if gotRole != roleARN {
		t.Errorf("RoleArn = %q, want %q", gotRole, roleARN)
	}
	if gotToken == "" || strings.Count(gotToken, ".") != 2 {
		t.Errorf("WebIdentityToken is not a compact JWT: %q", gotToken)
	}

	// Credentials come back mapped.
	if creds.AccessKeyID != "ASIADEMO" || creds.SecretAccessKey != "demosecret" || creds.SessionToken != "demosession" {
		t.Errorf("credentials not mapped: %+v", creds)
	}
	if creds.STSRequestID != "req-demo-1" {
		t.Errorf("STSRequestID = %q, want it captured for the audit log", creds.STSRequestID)
	}
	if creds.Expiry.IsZero() {
		t.Error("expiry should be parsed so refresh can work")
	}
}
