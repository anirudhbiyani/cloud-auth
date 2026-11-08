package gcp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// fakeIssuerTransport answers every discovery and JWKS request itself, so unit tests never dial a real issuer and the OIDC-discovery and clock-skew checks pass against whatever issuer a test records.
type fakeIssuerTransport struct{}

func (fakeIssuerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	origin := r.URL.Scheme + "://" + r.URL.Host
	var body any
	switch r.URL.Path {
	case "/keys":
		body = map[string]any{"keys": []map[string]string{{"kid": "k1", "kty": "RSA"}}}
	default:
		// Mirror the issuer the request was made to, including any path prefix before the well-known suffix.
		issuer := origin + strings.TrimSuffix(r.URL.Path, "/.well-known/openid-configuration")
		body = map[string]string{"issuer": issuer, "jwks_uri": origin + "/keys"}
	}
	b, _ := json.Marshal(body)
	h := http.Header{}
	h.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	h.Set("Content-Type", "application/json")
	return &http.Response{StatusCode: http.StatusOK, Header: h, Body: io.NopCloser(bytes.NewReader(b)), Request: r}, nil
}

func TestMain(m *testing.M) {
	core.DefaultValidationHTTPClient = &http.Client{Transport: fakeIssuerTransport{}}
	os.Exit(m.Run())
}
