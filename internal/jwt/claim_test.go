package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// StringOrSliceClaim reads a claim outside the registered set, for the one caller that needs it: "https://aws.amazon.com/roles", which STS reads for sts:RoleAuthorizedByIdp.

// rawJWT builds a token from an already-encoded payload segment, so a test can supply a payload that is not valid JSON.
func rawJWT(payloadSegment string) string {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(map[string]any{"alg": "RS256"}) + "." + payloadSegment + ".c2ln"
}

const rolesClaim = "https://aws.amazon.com/roles"

func TestStringOrSliceClaimShapes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload map[string]any
		want    []string
	}{
		{
			name:    "a single string",
			payload: map[string]any{rolesClaim: "arn:aws:iam::1:role/a"},
			want:    []string{"arn:aws:iam::1:role/a"},
		},
		{
			name: "an array",
			payload: map[string]any{rolesClaim: []string{
				"arn:aws:iam::1:role/a", "arn:aws:iam::1:role/b",
			}},
			want: []string{"arn:aws:iam::1:role/a", "arn:aws:iam::1:role/b"},
		},
		{
			name:    "an empty array is present but names nothing",
			payload: map[string]any{rolesClaim: []string{}},
			want:    []string{},
		},
		{
			name:    "an empty string is a value, not an absence",
			payload: map[string]any{rolesClaim: ""},
			want:    []string{""},
		},
		{
			// Absent is not an error.
			name:    "absent",
			payload: map[string]any{"sub": "s"},
			want:    nil,
		},
		{
			// null must read as absent, and getting there took two corrections.
			name:    "null is absent, not an empty role",
			payload: map[string]any{rolesClaim: nil},
			want:    nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := StringOrSliceClaim(makeJWT(t, tc.payload), rolesClaim)
			if err != nil {
				t.Fatalf("StringOrSliceClaim: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("got %v, want %v", got, tc.want)
					break
				}
			}
		})
	}
}

// A claim of the wrong JSON type must be an ERROR, not silently nothing.
func TestStringOrSliceClaimRejectsWrongTypes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"a number", 42},
		{"a boolean", true},
		{"an object", map[string]any{"role": "arn:aws:iam::1:role/a"}},
		{"an array of numbers", []int{1, 2}},
		{"an array of objects", []map[string]string{{"a": "b"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := StringOrSliceClaim(makeJWT(t, map[string]any{rolesClaim: tc.value}), rolesClaim)
			if err == nil {
				t.Fatalf("a %s was accepted, returning %v — a malformed claim must not read "+
					"as an absent one", tc.name, got)
			}
			if !strings.Contains(err.Error(), "neither a string nor an array") {
				t.Errorf("error = %v", err)
			}
			if got != nil {
				t.Errorf("got %v alongside an error; a caller that ignores the error must not "+
					"receive a usable value", got)
			}
		})
	}
}

// Malformed tokens.
func TestStringOrSliceClaimRejectsMalformedTokens(t *testing.T) {
	for _, tc := range []struct {
		name   string
		token  string
		errHas string
	}{
		{"empty", "", "3 segments"},
		{"one segment", "abc", "3 segments"},
		{"two segments", "abc.def", "3 segments"},
		{"four segments", "a.b.c.d", "3 segments"},
		{"payload is not base64", "aGVhZGVy.!!!not-base64!!!.c2ln", "decoding payload"},
		// "+" and "/" belong to standard base64 and not to base64url, so a payload encoded with the wrong alphabet must be refused rather than silently decoded into something else.
		{"payload uses the standard base64 alphabet", "aGVhZGVy.eyJhIjoiYisvIn0=.c2ln", "decoding payload"},
		{"payload is padded", "aGVhZGVy.eyJhIjoiYiJ9==.c2ln", "decoding payload"},
		{"payload is not JSON", rawJWT(base64.RawURLEncoding.EncodeToString([]byte("not json"))), "unmarshaling"},
		{"payload is a JSON array, not an object", rawJWT(
			base64.RawURLEncoding.EncodeToString([]byte(`["a","b"]`))), "unmarshaling"},
		{"payload is a bare string", rawJWT(
			base64.RawURLEncoding.EncodeToString([]byte(`"hello"`))), "unmarshaling"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := StringOrSliceClaim(tc.token, rolesClaim)
			if err == nil {
				t.Fatalf("a malformed token was accepted, returning %v", got)
			}
			if !strings.Contains(err.Error(), tc.errHas) {
				t.Errorf("error = %q, want it to contain %q", err, tc.errHas)
			}
			if got != nil {
				t.Errorf("got %v alongside an error", got)
			}
		})
	}
}

// The claim name is data, not a path expression: a name containing dots or slashes must be looked up literally.
func TestStringOrSliceClaimNameIsLiteral(t *testing.T) {
	tok := makeJWT(t, map[string]any{
		"https://aws.amazon.com/roles": "outer",
		"aws":                          map[string]any{"amazon": map[string]any{"roles": "nested"}},
	})

	got, err := StringOrSliceClaim(tok, rolesClaim)
	if err != nil {
		t.Fatalf("StringOrSliceClaim: %v", err)
	}
	if len(got) != 1 || got[0] != "outer" {
		t.Errorf("got %v, want the literally-named claim", got)
	}

	// A name that does not exist is absent, not a traversal into a nested value.
	nested, err := StringOrSliceClaim(tok, "aws.amazon.roles")
	if err != nil {
		t.Fatalf("StringOrSliceClaim: %v", err)
	}
	if nested != nil {
		t.Errorf("a dotted name traversed into the payload: %v", nested)
	}
}

// A duplicate key is the last one, matching encoding/json — worth pinning because the alternative behaviours (first wins, or an error) are both plausible, and a token crafted with a duplicate is exactly how somebody would try to smuggle a second value past a reader that took the first.
func TestStringOrSliceClaimDuplicateKeyTakesTheLast(t *testing.T) {
	payload := `{"` + rolesClaim + `":"first","` + rolesClaim + `":"second"}`
	got, err := StringOrSliceClaim(rawJWT(base64.RawURLEncoding.EncodeToString([]byte(payload))), rolesClaim)
	if err != nil {
		t.Fatalf("StringOrSliceClaim: %v", err)
	}
	if len(got) != 1 || got[0] != "second" {
		t.Errorf("got %v, want the last value — encoding/json's documented behaviour", got)
	}
}

// This package never verifies a signature and its doc says so.
func TestSignatureIsNotInspected(t *testing.T) {
	tok := makeJWT(t, map[string]any{rolesClaim: "arn:aws:iam::1:role/a"})
	parts := strings.Split(tok, ".")
	tampered := parts[0] + "." + parts[1] + ".!!!not-a-signature!!!"

	got, err := StringOrSliceClaim(tampered, rolesClaim)
	if err != nil {
		t.Fatalf("the signature segment was inspected: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("got %v", got)
	}
}

func FuzzStringOrSliceClaim(f *testing.F) {
	f.Add(makeJWTNoT(map[string]any{rolesClaim: "arn:aws:iam::1:role/a"}), rolesClaim)
	f.Add(makeJWTNoT(map[string]any{rolesClaim: []string{"a", "b"}}), rolesClaim)
	f.Add(makeJWTNoT(map[string]any{"sub": "s"}), rolesClaim)
	f.Add("a.b.c", "aud")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, token, name string) {
		got, err := StringOrSliceClaim(token, name)

		// Never both.
		if err != nil && got != nil {
			t.Fatalf("StringOrSliceClaim(%q, %q) returned both %v and %v", token, name, got, err)
		}
		// An error must name the package, so a caller wrapping it produces something traceable rather than a bare decoder message.
		if err != nil && !strings.HasPrefix(err.Error(), "jwt: ") {
			t.Fatalf("error is not attributed to this package: %v", err)
		}
	})
}

// makeJWTNoT is makeJWT without a *testing.T, for fuzz seeds.
func makeJWTNoT(payload map[string]any) string {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(map[string]any{"alg": "RS256"}) + "." + enc(payload) + ".c2ln"
}
