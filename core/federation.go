// This file holds the runtime federation domain types — the data-plane shared
// by the source-identity providers (source), target exchangers (target), and
// credential adapters (adapters): a workload obtains short-lived credentials
// for another cloud with zero static secrets by minting a native proof of
// identity and exchanging it at the target cloud's STS.
package core

import (
	"fmt"
	"strings"
	"time"
)

// Cloud identifies a cloud or identity provider. The first three are the
// federation-target hyperscalers; the remainder are additional providers the
// control-plane can establish trust with.
type Cloud string

const (
	AWS   Cloud = "aws"
	GCP   Cloud = "gcp"
	Azure Cloud = "azure"
	// Anthropic is the Claude Platform. Not a cloud, but it is a federation
	// TARGET in exactly the sense this type means: a workload presents an OIDC
	// proof and receives a short-lived credential for it.
	Anthropic  Cloud = "anthropic"
	Vault      Cloud = "vault"
	Okta       Cloud = "okta"
	GitHubOIDC Cloud = "github_oidc"
	Kubernetes Cloud = "kubernetes"
)

// federationTargets are the destinations a workload can obtain credentials FOR.
// Each has a Target type and an Exchanger.
var federationTargets = map[Cloud]bool{AWS: true, GCP: true, Azure: true, Anthropic: true}

// trustPeers are the additional providers the control plane can establish trust
// WITH. They are valid Cloud values — providers are registered for them — but
// they are not federation targets, and conflating the two is why ParseCloud used
// to reject five of this package's own constants.
var trustPeers = map[Cloud]bool{
	Vault: true, Okta: true, GitHubOIDC: true, Kubernetes: true,
}

// ParseCloud parses a case-insensitive identifier for any declared Cloud.
//
// Use it where any provider is acceptable. Where a federation target is required
// — resolving a config target, dispatching an exchanger — use
// ParseFederationTarget, which says so in the error rather than reporting a
// perfectly real cloud as unknown.
func ParseCloud(s string) (Cloud, error) {
	c := Cloud(strings.ToLower(strings.TrimSpace(s)))
	if federationTargets[c] || trustPeers[c] {
		return c, nil
	}
	return "", fmt.Errorf("cloud-auth: unknown cloud %q (want aws, gcp, azure, "+
		"vault, okta, github_oidc, or kubernetes)", s)
}

// sourceClouds are the clouds a workload can authenticate AS.
//
// A different set from federationTargets, and the difference is the point: a
// workload can be a GitHub Actions job and obtain AWS credentials, but nothing
// obtains "GitHub Actions credentials". Using federationTargets for both is why
// `source.detect` could not name a CI platform at all.
var sourceClouds = map[Cloud]bool{AWS: true, GCP: true, Azure: true, GitHubOIDC: true}

// sourceCloudAliases map the spelling an operator writes to the Cloud constant.
//
// "github" rather than "github_oidc", because source.detect splits on "-" and
// the natural value is "github-actions" — cloud "github", sub-runtime
// "actions".
var sourceCloudAliases = map[string]Cloud{
	"github":      GitHubOIDC,
	"github_oidc": GitHubOIDC,
}

// ParseSourceCloud parses a cloud a workload can authenticate as.
func ParseSourceCloud(s string) (Cloud, error) {
	normalized := strings.ToLower(strings.TrimSpace(s))
	if c, ok := sourceCloudAliases[normalized]; ok {
		return c, nil
	}
	c, err := ParseCloud(normalized)
	if err != nil {
		return "", err
	}
	if !sourceClouds[c] {
		return "", fmt.Errorf("cloud-auth: %s is not a source a workload can authenticate as "+
			"(want aws, gcp, azure, or github)", c)
	}
	return c, nil
}

// ParseFederationTarget parses a cloud a workload can obtain credentials for.
func ParseFederationTarget(s string) (Cloud, error) {
	c, err := ParseCloud(s)
	if err != nil {
		return "", err
	}
	if !federationTargets[c] {
		return "", fmt.Errorf("cloud-auth: %s is a trust peer, not a federation target: "+
			"cloud-auth can establish trust with it but cannot obtain credentials for it "+
			"(want aws, gcp, azure, or anthropic)", c)
	}
	return c, nil
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
// expired skew early to tolerate clock drift.
//
// A zero Expiry means "not applicable" and is NOT treated as expired — the
// opposite of Credentials.Expired, deliberately. An AWSSigV4 proof carries no
// exp claim at all: it is a pre-signed request whose lifetime lives in the
// signature, which only the target STS can evaluate. Failing closed on a zero
// Expiry here would make every EC2 and ECS source permanently unusable.
//
// The asymmetry is safe because a source token is a claim we hand to a verifier,
// while credentials are an authority we act on: presenting a stale proof gets a
// clean rejection from STS, whereas caching stale credentials produces confusing
// failures far from their cause.
func (t SourceToken) Expired(now time.Time, skew time.Duration) bool {
	if t.Expiry.IsZero() {
		return false
	}
	return !now.Before(t.Expiry.Add(-skew))
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
//
// An unknown expiry counts as expired. Credentials are short-lived by
// construction, so a zero Expiry does not mean "these last forever", it means
// something went wrong upstream — an STS response whose timestamp did not parse,
// a field the provider stopped sending, a zero value that was never populated.
// Treating that as immortal is the worst available answer: the cache would serve
// dead credentials for the life of the process and never refresh. Failing closed
// costs one extra exchange; failing open costs an outage that looks like a
// permissions bug.
func (c Credentials) Expired(now time.Time, skew time.Duration) bool {
	if c.Expiry.IsZero() {
		return true
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
