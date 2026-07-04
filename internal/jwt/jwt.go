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
	Audience string
	Expiry   time.Time
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
	c.Audience = firstAudience(rc.Aud)
	return c, nil
}

// firstAudience handles aud being a JSON string or array of strings.
func firstAudience(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
		return arr[0]
	}
	return ""
}
