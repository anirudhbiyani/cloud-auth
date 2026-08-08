// Package jwt extracts claims from a JWT WITHOUT verifying its signature.
//
// This is deliberate and safe for cloud-auth's use: the token is one we just
// minted from our own metadata endpoint, and it is the *target* STS that
// verifies the signature against the issuer's JWKS. We only parse it locally to
// populate SourceToken metadata (issuer/subject/expiry) and to power `cloud-auth
// doctor` diagnostics. Never use this to make a trust decision.
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
	// Audiences is every value of the aud claim. A JWT's aud may be a single
	// string or an array; both are normalized here.
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

// ParseUnverified decodes the payload segment of a compact JWT. It does NOT
// verify the signature (see package doc).
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

// audiences normalizes the aud claim (a JSON string or array of strings) into a
// slice.
func audiences(raw json.RawMessage) []string {
	if len(raw) == 0 {
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
