package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// ParseUnverified reads attacker-adjacent input: a token from a file whose path
// comes from the environment. It must never panic, and it must never report an
// audience or expiry the payload does not contain.
func FuzzParseUnverified(f *testing.F) {
	seg := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	f.Add("a.b.c")
	f.Add("eyJhbGciOiJSUzI1NiJ9." + seg(map[string]any{"sub": "x", "aud": "y", "exp": 1}) + ".sig")
	f.Add("h." + seg(map[string]any{"aud": []string{"a", "b"}}) + ".s")
	f.Add("")
	f.Add("...")
	f.Add(strings.Repeat("A", 4096))

	f.Fuzz(func(t *testing.T, token string) {
		claims, err := ParseUnverified(token)
		if err != nil {
			// On error, nothing may be reported as parsed.
			if claims.Issuer != "" || claims.Subject != "" || len(claims.Audiences) > 0 || !claims.Expiry.IsZero() {
				t.Fatalf("error path returned populated claims: %+v", claims)
			}
			return
		}
		// A token that parsed must have had three segments.
		if n := strings.Count(token, "."); n != 2 {
			t.Fatalf("parsed a token with %d dots", n)
		}
		// Audience/Audiences must agree, or HasAudience lies.
		if len(claims.Audiences) > 0 && claims.Audience != claims.Audiences[0] {
			t.Fatalf("Audience %q disagrees with Audiences %v", claims.Audience, claims.Audiences)
		}
		if len(claims.Audiences) == 0 && claims.Audience != "" {
			t.Fatalf("Audience %q set with no Audiences", claims.Audience)
		}
		// HasAudience must be consistent with the slice it reports.
		for _, a := range claims.Audiences {
			if !claims.HasAudience(a) {
				t.Fatalf("HasAudience(%q) false but it is in Audiences", a)
			}
		}
		if claims.HasAudience("\x00-definitely-not-present") {
			t.Fatal("HasAudience returned true for an absent audience")
		}
	})
}
