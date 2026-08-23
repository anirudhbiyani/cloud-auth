package core

import (
	"testing"
	"time"
)

// Credentials with an unknown expiry must count as expired. They used to count
// as immortal, so a dropped time.Parse anywhere upstream produced credentials
// the cache would serve for the life of the process.
func TestCredentialsWithUnknownExpiryAreExpired(t *testing.T) {
	c := Credentials{Cloud: AWS, AccessKeyID: "ASIA123"} // Expiry zero
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

	if !c.Expired(now, 0) {
		t.Error("zero Expiry must count as expired")
	}
	if !c.Expired(now.AddDate(-100, 0, 0), 5*time.Minute) {
		t.Error("zero Expiry must count as expired regardless of the reference time")
	}
}

func TestCredentialsExpiryBoundary(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	c := Credentials{Cloud: AWS, Expiry: now.Add(time.Hour)}

	if c.Expired(now, 0) {
		t.Error("valid for another hour, must not be expired")
	}
	if !c.Expired(now, time.Hour) {
		t.Error("a skew equal to the remaining life must count as expired")
	}
	if c.Expired(now, time.Hour-time.Nanosecond) {
		t.Error("one nanosecond inside the window must not be expired")
	}
}

// The opposite convention for SourceToken is deliberate, not an oversight: an
// AWSSigV4 proof has no exp claim, so failing closed on a zero Expiry would make
// every EC2 and ECS source permanently unusable.
func TestSourceTokenWithUnknownExpiryIsNotExpired(t *testing.T) {
	sigv4 := SourceToken{Kind: AWSSigV4, Value: `{"url":"..."}`}
	if sigv4.Expired(time.Now(), 0) {
		t.Error("a SigV4 proof carries no exp; it must not be treated as expired")
	}

	jwt := SourceToken{Kind: OIDC, Expiry: time.Now().Add(-time.Minute)}
	if !jwt.Expired(time.Now(), 0) {
		t.Error("an OIDC token past its exp must be expired")
	}
}
