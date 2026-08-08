package jwt

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func makeJWT(t *testing.T, payload map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	return enc(header) + "." + enc(payload) + ".c2lnbmF0dXJl"
}

func TestParseUnverifiedExtractsClaims(t *testing.T) {
	exp := time.Date(2026, 7, 4, 13, 0, 0, 0, time.UTC).Unix()
	tok := makeJWT(t, map[string]any{
		"iss": "https://accounts.google.com",
		"sub": "1234567890",
		"aud": "sts.amazonaws.com",
		"exp": exp,
	})

	c, err := ParseUnverified(tok)
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	if c.Issuer != "https://accounts.google.com" {
		t.Errorf("iss = %q", c.Issuer)
	}
	if c.Subject != "1234567890" {
		t.Errorf("sub = %q", c.Subject)
	}
	if c.Audience != "sts.amazonaws.com" {
		t.Errorf("aud = %q", c.Audience)
	}
	if !c.Expiry.Equal(time.Unix(exp, 0)) {
		t.Errorf("exp = %v, want %v", c.Expiry, time.Unix(exp, 0))
	}
}

func TestParseUnverifiedRejectsMalformed(t *testing.T) {
	for _, tok := range []string{"", "onlyonepart", "two.parts", "a.!!!notbase64!!!.c"} {
		if _, err := ParseUnverified(tok); err == nil {
			t.Errorf("ParseUnverified(%q): expected error, got nil", tok)
		}
	}
}

func TestParseUnverifiedAudienceArray(t *testing.T) {
	// OIDC aud may be a string OR an array of strings.
	tok := makeJWT(t, map[string]any{"aud": []string{"api://AzureADTokenExchange", "other"}})
	c, err := ParseUnverified(tok)
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	if c.Audience != "api://AzureADTokenExchange" {
		t.Errorf("aud = %q, want first element of array", c.Audience)
	}
	if len(c.Audiences) != 2 || c.Audiences[0] != "api://AzureADTokenExchange" || c.Audiences[1] != "other" {
		t.Errorf("Audiences = %v, want both entries preserved", c.Audiences)
	}
	if !c.HasAudience("other") || c.HasAudience("missing") {
		t.Errorf("HasAudience membership wrong: %v", c.Audiences)
	}
}

func TestParseUnverifiedAudienceStringSetsSlice(t *testing.T) {
	tok := makeJWT(t, map[string]any{"aud": "sts.amazonaws.com"})
	c, _ := ParseUnverified(tok)
	if len(c.Audiences) != 1 || c.Audiences[0] != "sts.amazonaws.com" {
		t.Errorf("Audiences = %v, want single-element slice", c.Audiences)
	}
	if !c.HasAudience("sts.amazonaws.com") {
		t.Error("HasAudience should match the single string aud")
	}
}
