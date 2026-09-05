// Package jwt extracts claims from a JWT WITHOUT verifying its signature.
package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Claims are the subset of registered claims cloud-auth cares about.
type Claims struct {
	Issuer   string
	Subject  string
	Audience string // first audience (convenience); see Audiences for all
	// Audiences is every value of the aud claim.
	Audiences []string
	Expiry    time.Time
}

// HasAudience reports whether aud is one of the token's audiences.
func (c Claims) HasAudience(aud string) bool {
	for _, a := range c.Audiences {
		if a == aud {
			return true
		}
	}
	return false
}

// rawClaims mirrors the JSON payload; aud may be a string or []string.
type rawClaims struct {
	Iss string          `json:"iss"`
	Sub string          `json:"sub"`
	Aud json.RawMessage `json:"aud"`
	Exp int64           `json:"exp"`
}

// ParseUnverified decodes the payload segment of a compact JWT.
func ParseUnverified(token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, fmt.Errorf("jwt: expected 3 segments, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, fmt.Errorf("jwt: decoding payload: %w", err)
	}
	var rc rawClaims
	if err := json.Unmarshal(payload, &rc); err != nil {
		return Claims{}, fmt.Errorf("jwt: unmarshaling claims: %w", err)
	}
	c := Claims{Issuer: rc.Iss, Subject: rc.Sub}
	if rc.Exp > 0 {
		c.Expiry = time.Unix(rc.Exp, 0)
	}
	c.Audiences = audiences(rc.Aud)
	if len(c.Audiences) > 0 {
		c.Audience = c.Audiences[0]
	}
	return c, nil
}

// audiences normalizes the aud claim (a JSON string or array of strings) into a slice.
func audiences(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	// null is absence, checked before the string attempt for the same reason StringOrSliceClaim does: encoding/json treats null as a no-op and returns no error, so a null aud would silently become []string{""} — a token carrying one audience, the empty string, rather than none.
	if string(raw) == "null" {
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []string{s}
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr
	}
	return nil
}

// StringOrSliceClaim reads a claim that a JWT may encode as either a string or an array of strings, and returns nothing when it is absent.
func StringOrSliceClaim(token, name string) ([]string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("jwt: expected 3 segments, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jwt: decoding payload: %w", err)
	}

	var all map[string]json.RawMessage
	if err := json.Unmarshal(payload, &all); err != nil {
		return nil, fmt.Errorf("jwt: unmarshaling claims: %w", err)
	}
	raw, ok := all[name]
	if !ok {
		return nil, nil
	}

	// JSON null is absence, and it has to be handled BEFORE the string attempt.
	if string(raw) == "null" {
		return nil, nil
	}

	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{single}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, fmt.Errorf("jwt: claim %q is neither a string nor an array of strings", name)
	}
	return many, nil
}
