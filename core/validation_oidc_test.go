package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// issuerServer is an HTTPS issuer serving its own discovery document and JWKS; issuerField overrides the `issuer` it claims.
func issuerServer(t *testing.T, issuerField string, keys []map[string]string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			iss := srv.URL
			if issuerField != "" {
				iss = issuerField
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": iss, "jwks_uri": srv.URL + "/keys"})
		case "/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestOIDCDiscoveryValidator(t *testing.T) {
	good := []map[string]string{{"kid": "a", "kty": "RSA"}, {"kid": "b", "kty": "RSA"}}

	t.Run("healthy issuer", func(t *testing.T) {
		srv := issuerServer(t, "", good)
		check := NewOIDCDiscoveryValidator(srv.URL, srv.Client()).Validate(context.Background(), MechanismRef{})
		if check.Status != CheckStatusPassed || !strings.Contains(check.Message, "2 signing key(s)") {
			t.Fatalf("check = %+v", check)
		}
		if check.Evidence["key_count"] != 2 {
			t.Errorf("evidence = %v", check.Evidence)
		}
	})
	t.Run("issuer field differs by a trailing slash", func(t *testing.T) {
		srv := issuerServer(t, "SELF/", good)
		v := NewOIDCDiscoveryValidator(srv.URL, srv.Client())
		// The server claims srv.URL + "/" once it knows its own URL.
		srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL + "/", "jwks_uri": srv.URL + "/keys"})
		})
		check := v.Validate(context.Background(), MechanismRef{})
		if check.Status != CheckStatusFailed || !strings.Contains(check.Message, srv.URL+`/"`) || !strings.Contains(check.Message, "trust names") {
			t.Fatalf("check = %+v", check)
		}
	})
	t.Run("empty JWKS", func(t *testing.T) {
		srv := issuerServer(t, "", []map[string]string{})
		check := NewOIDCDiscoveryValidator(srv.URL, srv.Client()).Validate(context.Background(), MechanismRef{})
		if check.Status != CheckStatusFailed || !strings.Contains(check.Message, "no keys") {
			t.Fatalf("check = %+v", check)
		}
	})
	t.Run("keys without kid are flagged but pass", func(t *testing.T) {
		srv := issuerServer(t, "", []map[string]string{{"kty": "RSA"}})
		check := NewOIDCDiscoveryValidator(srv.URL, srv.Client()).Validate(context.Background(), MechanismRef{})
		if check.Status != CheckStatusPassed || !strings.Contains(check.Message, "lack a kid") {
			t.Fatalf("check = %+v", check)
		}
	})
	t.Run("no issuer recorded is skipped", func(t *testing.T) {
		check := NewOIDCDiscoveryValidator("", nil).Validate(context.Background(), MechanismRef{})
		if check.Status != CheckStatusSkipped {
			t.Fatalf("check = %+v", check)
		}
	})
	t.Run("unreachable is a failure with remediation", func(t *testing.T) {
		check := NewOIDCDiscoveryValidator("https://127.0.0.1:1", &http.Client{Timeout: time.Second}).Validate(context.Background(), MechanismRef{})
		if check.Status != CheckStatusFailed || check.Remediation == "" {
			t.Fatalf("check = %+v", check)
		}
	})
}

func TestClockSkewValidator(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		remote time.Time
		noDate bool
		want   CheckStatus
		skew   int
	}{
		{"in sync", now, false, CheckStatusPassed, 0},
		{"20s off, within 30s", now.Add(20 * time.Second), false, CheckStatusPassed, 20},
		{"3 minutes off", now.Add(-3 * time.Minute), false, CheckStatusFailed, 180},
		{"no Date header", now, true, CheckStatusSkipped, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.noDate {
					w.Header()["Date"] = nil // net/http adds one unless the key is set to nil
				} else {
					w.Header().Set("Date", tc.remote.Format(http.TimeFormat))
				}
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(srv.Close)
			v := NewClockSkewValidator(srv.URL, 30*time.Second, srv.Client())
			v.now = func() time.Time { return now }
			check := v.Validate(context.Background(), MechanismRef{})
			if check.Status != tc.want {
				t.Fatalf("status = %s, want %s: %s", check.Status, tc.want, check.Message)
			}
			if tc.want != CheckStatusSkipped && check.Evidence["skew_seconds"] != tc.skew {
				t.Errorf("skew_seconds = %v, want %d", check.Evidence["skew_seconds"], tc.skew)
			}
		})
	}
	t.Run("no time source is skipped", func(t *testing.T) {
		if check := NewClockSkewValidator("", time.Minute, nil).Validate(context.Background(), MechanismRef{}); check.Status != CheckStatusSkipped {
			t.Fatalf("check = %+v", check)
		}
	})
}
