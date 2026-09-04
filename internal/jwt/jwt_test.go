package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
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

// The aud claim's shapes. A JWT may encode it as a string or an array, and both
// are normalized — but the shapes that are NEITHER decide whether a token reads
// as "audience absent" or as "audience present and wrong", which
// checkAudienceBinding treats very differently.
func TestAudienceShapes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		aud     any
		want    []string
		wantOne string
	}{
		{"a single string", "sts.amazonaws.com", []string{"sts.amazonaws.com"}, "sts.amazonaws.com"},
		{"an array", []string{"a", "b"}, []string{"a", "b"}, "a"},
		{"an empty array", []string{}, []string{}, ""},
		// Not an audience of any kind. Reading a number as one would give the
		// token an audience it does not have.
		{"a number", 42, nil, ""},
		{"an object", map[string]any{"a": "b"}, nil, ""},
		{"an array of numbers", []int{1, 2}, nil, ""},
		// null is absence, for the same reason it is in StringOrSliceClaim:
		// encoding/json treats it as a no-op, so without an explicit check it
		// would silently become one audience that is the empty string.
		{"null", nil, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := ParseUnverified(makeJWT(t, map[string]any{
				"iss": "https://issuer.example.com", "sub": "s", "aud": tc.aud,
			}))
			if err != nil {
				t.Fatalf("ParseUnverified: %v", err)
			}
			if len(c.Audiences) != len(tc.want) {
				t.Fatalf("Audiences = %v, want %v", c.Audiences, tc.want)
			}
			for i := range c.Audiences {
				if c.Audiences[i] != tc.want[i] {
					t.Fatalf("Audiences = %v, want %v", c.Audiences, tc.want)
				}
			}
			if c.Audience != tc.wantOne {
				t.Errorf("Audience = %q, want %q", c.Audience, tc.wantOne)
			}
			// Whatever the shape, an audience nobody put in the token must not
			// come back out — this is the check every exchanger relies on
			// before transmitting a proof.
			if c.HasAudience("some-other-party") {
				t.Error("HasAudience returned true for an audience not in the token")
			}
		})
	}
}

// A missing aud is absence, and must not read as an audience of "".
func TestAudienceAbsent(t *testing.T) {
	c, err := ParseUnverified(makeJWT(t, map[string]any{"iss": "https://x", "sub": "s"}))
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	if len(c.Audiences) != 0 || c.Audience != "" {
		t.Errorf("Audiences = %v, Audience = %q, want both empty", c.Audiences, c.Audience)
	}
	if c.HasAudience("") {
		t.Error("HasAudience(\"\") is true for a token with no aud claim")
	}
}

// exp is optional, and a token without one must parse with a zero expiry rather
// than fail — core.Credentials treats a zero expiry as already expired, which
// is the safe reading, and that decision belongs there rather than here.
func TestExpiryIsOptional(t *testing.T) {
	c, err := ParseUnverified(makeJWT(t, map[string]any{"iss": "https://x", "sub": "s"}))
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	if !c.Expiry.IsZero() {
		t.Errorf("Expiry = %v, want the zero time", c.Expiry)
	}

	t.Run("a non-positive exp is also zero", func(t *testing.T) {
		for _, exp := range []int64{0, -1} {
			c, err := ParseUnverified(makeJWT(t, map[string]any{"exp": exp}))
			if err != nil {
				t.Fatalf("ParseUnverified: %v", err)
			}
			if !c.Expiry.IsZero() {
				t.Errorf("exp %d gave Expiry %v, want the zero time", exp, c.Expiry)
			}
		}
	})
}

// A payload that decodes from base64 but is not a JSON object.
//
// The distinct error matters: "not base64" points at a mangled token — a
// truncated copy-paste, a wrongly-encoded segment — while "not JSON" points at
// something that decoded fine and is not a JWT payload at all, which is usually
// a token from a different system entirely.
func TestParseUnverifiedRejectsNonJSONPayload(t *testing.T) {
	enc := base64.RawURLEncoding.EncodeToString
	header := enc([]byte(`{"alg":"RS256"}`))

	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{"plain text", []byte("not json at all")},
		{"a JSON array", []byte(`["a","b"]`)},
		{"a bare string", []byte(`"hello"`)},
		{"a bare number", []byte(`42`)},
		{"truncated JSON", []byte(`{"iss":`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseUnverified(header + "." + enc(tc.payload) + ".c2ln")
			if err == nil {
				t.Fatal("a payload that is not a JSON object was accepted")
			}
			if !strings.Contains(err.Error(), "unmarshaling claims") {
				t.Errorf("error = %q, want it to distinguish a decode failure from a "+
					"parse failure", err)
			}
		})
	}
}
