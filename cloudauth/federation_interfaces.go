package cloudauth

import (
	"context"
	"errors"
)

// SourceProvider detects the local runtime and mints a proof of identity.
// Implementations live in the sip package, one per cloud.
type SourceProvider interface {
	// Detect resolves the runtime with no credential input. It returns
	// ErrNotThisRuntime if the workload is not running in this provider's
	// environment, so a registry can try each provider in turn.
	Detect(ctx context.Context) (*Runtime, error)

	// Mint returns an audience-pinned proof of the detected identity. It
	// returns ErrNonFederatableSource for runtimes (e.g. EKS Pod Identity)
	// that cannot produce a portable, externally-verifiable token.
	Mint(ctx context.Context, audience string) (*SourceToken, error)
}

// Runtime describes the detected execution environment.
type Runtime struct {
	Cloud       Cloud
	SubRuntime  string // "ec2", "ecs", "eks-irsa", "eks-pod-identity", "gke", "aks", ...
	Federatable bool   // false => cannot mint a portable token; Mint will error
	Issuer      string // resolved without any credential input
	Subject     string
}

// Exchanger trades a source proof for native target credentials by calling the
// target cloud's STS. Implementations live in the te package, one per target.
type Exchanger interface {
	Exchange(ctx context.Context, tok *SourceToken, target Target) (*Credentials, error)
}

// Sentinel errors. Callers use errors.Is to branch; the CLI (cloud-auth doctor) turns
// these into actionable messages.
var (
	// ErrNotThisRuntime means a SourceProvider is not running in its cloud.
	ErrNotThisRuntime = errors.New("cloud-auth: not running in this runtime")

	// ErrNonFederatableSource means the runtime cannot mint a portable token
	// (e.g. EKS Pod Identity); the caller must use an OIDC-native source.
	ErrNonFederatableSource = errors.New("cloud-auth: source runtime cannot produce a federatable token")

	// ErrNoFirstClassPath means the source proof kind is not natively
	// accepted by the target (e.g. AWS SigV4 -> Azure, which accepts only
	// RS256 OIDC). An OIDC bridge is required.
	ErrNoFirstClassPath = errors.New("cloud-auth: no first-class keyless path for this source→target pair")

	// ErrTrustMissing means the target STS rejected the proof because no trust
	// is established (or it is misconfigured).
	ErrTrustMissing = errors.New("cloud-auth: target trust missing or misconfigured")
)
