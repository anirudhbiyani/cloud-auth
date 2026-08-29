package target

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// serveBody answers every request with a fixed status and body, so a fuzzer can
// drive the response-parsing path.
func serveBody(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The invariant that matters, and the one whose absence caused the immortal-
// credentials bug: either an error, or credentials with a usable expiry and a
// non-empty secret. Never a third thing.
func FuzzSTSResponseXML(f *testing.F) {
	f.Add(successXML)
	f.Add(accessDeniedXML)
	f.Add(`<AssumeRoleWithWebIdentityResponse/>`)
	f.Add(`<A><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>k</AccessKeyId></Credentials></AssumeRoleWithWebIdentityResult></A>`)
	f.Add(``)
	f.Add(`not xml at all`)

	f.Fuzz(func(t *testing.T, body string) {
		srv := serveBody(t, body)
		creds, err := NewAWSExchanger(WithAWSEndpoint(srv.URL), WithAWSMaxRetries(0)).
			Exchange(context.Background(), oidcToken(), awsTarget())

		if err != nil {
			if creds != nil {
				t.Fatalf("error and credentials together: %v / %v", err, creds)
			}
			return
		}
		if creds == nil {
			t.Fatal("no error and no credentials")
		}
		if creds.Expiry.IsZero() {
			t.Fatal("credentials with an unknown expiry: the cache cannot date these")
		}
		plain := creds.Reveal()
		if plain.AccessKeyID == "" || plain.SecretAccessKey == "" || plain.SessionToken == "" {
			t.Fatalf("incomplete credentials returned as success: %+v", creds)
		}
	})
}

// Same invariant for the JSON token endpoints.
func FuzzSTSResponseJSON(f *testing.F) {
	f.Add(`{"access_token":"t","expires_in":3600}`)
	f.Add(`{"access_token":"t"}`)
	f.Add(`{"expires_in":3600}`)
	f.Add(`{"access_token":"t","expires_in":-1}`)
	f.Add(`{}`)
	f.Add(`[]`)
	f.Add(``)
	f.Add(`{"access_token":`)

	f.Fuzz(func(t *testing.T, body string) {
		srv := serveBody(t, body)

		const aud = "//iam.googleapis.com/projects/1/x"
		creds, err := NewGCPExchanger(WithGCPSTSEndpoint(srv.URL)).Exchange(
			context.Background(), oidcTokenFor(aud),
			core.GCPTarget{WorkloadIdentityPool: "//iam.googleapis.com/projects/1/x", TokenAudience: aud})

		if err != nil {
			if creds != nil {
				t.Fatalf("error and credentials together: %v / %v", err, creds)
			}
			return
		}
		if creds == nil {
			t.Fatal("no error and no credentials")
		}
		if creds.Expiry.IsZero() {
			t.Fatal("credentials with an unknown expiry")
		}
		if creds.Reveal().AccessToken == "" {
			t.Fatal("empty access token returned as success")
		}
	})
}
