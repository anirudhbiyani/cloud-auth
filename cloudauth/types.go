// Package cloud-auth provides cross-cloud workload identity federation: a
// workload running in one cloud obtains short-lived credentials for another
// cloud with zero static secrets. It auto-detects its runtime, mints a native
// proof of identity, exchanges that proof at the target cloud's STS, and
// returns a credential object the target's own SDK understands.
//
// This package holds the core domain types shared by the source-identity
// providers (sip), target exchangers (te), and credential adapters (adapters).
package cloudauth

import (
	"fmt"
	"strings"
	"time"
)

// Cloud identifies a cloud provider participating in a federation exchange.
type Cloud string

const (
	AWS   Cloud = "aws"
	GCP   Cloud = "gcp"
	Azure Cloud = "azure"
)

// ParseCloud parses a case-insensitive cloud identifier, returning an error for
// unknown values so that config validation can fail closed.
func ParseCloud(s string) (Cloud, error) {
	switch Cloud(strings.ToLower(strings.TrimSpace(s))) {
	case AWS:
		return AWS, nil
	case GCP:
		return GCP, nil
	case Azure:
		return Azure, nil
	default:
		return "", fmt.Errorf("cloud-auth: unknown cloud %q (want aws, gcp, or azure)", s)
	}
}

// Kind classifies the form of a source proof.
type Kind int

const (
	// OIDC is a signed JWT verifiable via the issuer's JWKS.
	OIDC Kind = iota
	// AWSSigV4 is a pre-signed sts:GetCallerIdentity request (not a JWT).
	AWSSigV4
)

func (k Kind) String() string {
	switch k {
	case OIDC:
		return "oidc"
	case AWSSigV4:
		return "aws-sigv4"
	default:
		return "unknown"
	}
}

// SourceToken is the normalized proof of identity a source runtime mints
// locally and hands to a Target Exchanger. It never contains a long-lived
// secret.
type SourceToken struct {
	Kind     Kind
	Value    string    // JWT compact form, or the serialized pre-signed request
	Issuer   string    // OIDC iss (empty for SigV4)
	Subject  string    // OIDC sub, or the AWS principal ARN
	Audience string    // pinned aud
	Expiry   time.Time // zero means "no expiry known"
}

// Expired reports whether the token is expired as of now, treating it as
// expired skew early to tolerate clock drift. A zero Expiry means the expiry is
// unknown and the token is never treated as expired here.
func (t SourceToken) Expired(now time.Time, skew time.Duration) bool {
	if t.Expiry.IsZero() {
		return false
	}
	return !now.Before(t.Expiry.Add(-skew))
}

// Target is the explicit binding a caller wants credentials for. The source is
// auto-detected; the target is always explicit.
type Target struct {
	Cloud    Cloud
	Audience string

	// AWS
	Role string // role ARN

	// GCP
	WorkloadIdentityPool      string // projects/…/providers/…
	ImpersonateServiceAccount string // optional; empty = direct resource access

	// Azure
	Tenant   string
	ClientID string
}

// Credentials are the native short-lived credentials returned by a target STS.
type Credentials struct {
	Cloud Cloud

	// AWS
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string

	// GCP / Azure bearer token
	AccessToken string

	Expiry       time.Time
	STSRequestID string // for the audit log
}

// Expired reports whether the credentials are expired as of now, skew early.
func (c Credentials) Expired(now time.Time, skew time.Duration) bool {
	if c.Expiry.IsZero() {
		return false
	}
	return !now.Before(c.Expiry.Add(-skew))
}

// Clock abstracts time so expiry/refresh logic is deterministic in tests.
type Clock interface {
	Now() time.Time
}

// SystemClock is the production Clock backed by time.Now.
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now() }

// FakeClock is a manually-advanced Clock for tests.
type FakeClock struct{ t time.Time }

// NewFakeClock returns a FakeClock fixed at t.
func NewFakeClock(t time.Time) *FakeClock { return &FakeClock{t: t} }

func (f *FakeClock) Now() time.Time { return f.t }

// Advance moves the fake clock forward by d.
func (f *FakeClock) Advance(d time.Duration) { f.t = f.t.Add(d) }
