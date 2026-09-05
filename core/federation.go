// This file holds the runtime federation domain types — the data-plane shared by the source-identity providers (source), target exchangers (target), and credential adapters (adapters): a workload obtains short-lived credentials for another cloud with zero static secrets by minting a native proof of identity and exchanging it at the target cloud's STS.
package core

import (
	"fmt"
	"strings"
	"time"
)

// Cloud identifies a cloud or identity provider.
type Cloud string

const (
	AWS   Cloud = "aws"
	GCP   Cloud = "gcp"
	Azure Cloud = "azure"
	// Anthropic is the Claude Platform.
	Anthropic  Cloud = "anthropic"
	Vault      Cloud = "vault"
	Okta       Cloud = "okta"
	GitHubOIDC Cloud = "github_oidc"
	Kubernetes Cloud = "kubernetes"
)

// federationTargets are the destinations a workload can obtain credentials FOR.
var federationTargets = map[Cloud]bool{AWS: true, GCP: true, Azure: true, Anthropic: true}

// trustPeers are the additional providers the control plane can establish trust WITH.
var trustPeers = map[Cloud]bool{
	Vault: true, Okta: true, GitHubOIDC: true, Kubernetes: true,
}

// ParseCloud parses a case-insensitive identifier for any declared Cloud.
func ParseCloud(s string) (Cloud, error) {
	c := Cloud(strings.ToLower(strings.TrimSpace(s)))
	if federationTargets[c] || trustPeers[c] {
		return c, nil
	}
	return "", fmt.Errorf("cloud-auth: unknown cloud %q (want aws, gcp, azure, "+
		"vault, okta, github_oidc, or kubernetes)", s)
}

// sourceClouds are the clouds a workload can authenticate AS.
var sourceClouds = map[Cloud]bool{AWS: true, GCP: true, Azure: true, GitHubOIDC: true}

// sourceCloudAliases map the spelling an operator writes to the Cloud constant.
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

// SourceToken is the normalized proof of identity a source runtime mints locally and hands to a Target Exchanger.
type SourceToken struct {
	Kind     Kind
	Value    string    // JWT compact form, or the serialized pre-signed request
	Issuer   string    // OIDC iss (empty for SigV4)
	Subject  string    // OIDC sub, or the AWS principal ARN
	Audience string    // pinned aud
	Expiry   time.Time // zero means "no expiry known"
}

// Expired reports whether the token is expired as of now, treating it as expired skew early to tolerate clock drift.
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
