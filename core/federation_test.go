package core

import (
	"testing"
	"time"
)

func TestParseCloud(t *testing.T) {
	tests := []struct {
		in      string
		want    Cloud
		wantErr bool
	}{
		{"aws", AWS, false},
		{"AWS", AWS, false},
		{"gcp", GCP, false},
		{"azure", Azure, false},
		{" azure ", Azure, false},
		{"oracle", "", true},
		{"", "", true},
	}
	for _, tc := range tests {
		got, err := ParseCloud(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseCloud(%q): want error, got nil", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseCloud(%q): unexpected error %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("ParseCloud(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSourceTokenExpired(t *testing.T) {
	base := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	tok := SourceToken{Expiry: base.Add(1 * time.Minute)}

	// Not yet expired, no skew.
	if tok.Expired(base, 0) {
		t.Error("token should not be expired 1m before expiry with no skew")
	}
	// Skew of 2m makes it count as expired early.
	if !tok.Expired(base, 2*time.Minute) {
		t.Error("token should be considered expired when skew exceeds remaining TTL")
	}
	// Past expiry.
	if !tok.Expired(base.Add(2*time.Minute), 0) {
		t.Error("token past expiry should be expired")
	}
	// Zero expiry means "no expiry known" -> never treated as expired.
	var noExp SourceToken
	if noExp.Expired(base, time.Hour) {
		t.Error("zero-expiry token should not be treated as expired")
	}
}

func TestCredentialsExpired(t *testing.T) {
	base := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	c := Credentials{Expiry: base.Add(10 * time.Minute)}
	if c.Expired(base, time.Minute) {
		t.Error("creds valid for 10m should not be expired with 1m skew")
	}
	if !c.Expired(base.Add(10*time.Minute), time.Second) {
		t.Error("creds at expiry should be expired")
	}
}

func TestSystemClock(t *testing.T) {
	var c Clock = SystemClock{}
	before := time.Now()
	got := c.Now()
	after := time.Now()
	if got.Before(before) || got.After(after) {
		t.Errorf("SystemClock.Now() = %v, want between %v and %v", got, before, after)
	}
}

func TestFakeClock(t *testing.T) {
	base := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	fc := NewFakeClock(base)
	if !fc.Now().Equal(base) {
		t.Errorf("FakeClock.Now() = %v, want %v", fc.Now(), base)
	}
	fc.Advance(5 * time.Minute)
	if !fc.Now().Equal(base.Add(5 * time.Minute)) {
		t.Errorf("after Advance, Now() = %v, want %v", fc.Now(), base.Add(5*time.Minute))
	}
}
