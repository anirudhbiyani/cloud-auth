package source

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/internal/jwt"
)

// AWS IAM outbound identity federation lets an IAM principal ask STS for an
// RS256-signed JWT asserting its own identity, verifiable by anyone against a
// per-account OIDC discovery document. Before it existed, an EC2, ECS or Lambda
// workload had no OIDC token of its own: the only portable proof was a SigV4
// GetCallerIdentity request, which GCP's STS understands and Azure's does not.
// That is the ErrNoFirstClassPath gap this file closes.
//
// The SigV4 path stays. Outbound federation is opt-in per account, and a GCP
// workload identity pool provider of type aws is a well-trodden configuration
// that should keep working untouched.

// outboundTokenDuration is the lifetime requested for an STS-vended JWT.
//
// STS defaults to 300s if DurationSeconds is omitted. That is too tight to rely
// on implicitly: the proof is minted, then exchanged at a target STS whose
// retries use jittered backoff, and the cache may serve it stale while a refresh
// runs. Ask for a duration rather than inherit one. STS caps this at 3600s.
const outboundTokenDuration = 15 * time.Minute

// outboundSigningAlgorithm is the JWT signing algorithm requested from STS.
// RS256 is the only one every target accepts: Entra rejects assertions that are
// not RS256, so ES384 — the other value STS offers — would reintroduce the gap
// this path exists to close.
const outboundSigningAlgorithm = "RS256"

// AWSProof selects which proof of identity the AWS source mints on a runtime
// that has no OIDC token of its own (EC2, ECS, Lambda). EKS IRSA is unaffected:
// it already has a projected OIDC token and does not need STS to vend one.
type AWSProof string

const (
	// AWSProofAuto prefers the STS-vended OIDC JWT and falls back to the SigV4
	// GetCallerIdentity proof when the account has not enabled outbound identity
	// federation. Both assert the same IAM principal — this chooses a format, not
	// an identity, which is why a fallback here is not the silent credential
	// substitution it would be in the ambient chain.
	//
	// It does change which target-side trust configuration applies: an OIDC JWT
	// is verified against the account issuer and the sub claim, a SigV4 proof by
	// GCP calling GetCallerIdentity. A GCP pool that has only an aws provider
	// will start refusing the exchange the day someone enables outbound
	// federation on the account. Pin AWSProofSigV4 if that pool is not going to
	// gain an oidc provider.
	AWSProofAuto AWSProof = "auto"

	// AWSProofOIDC requires the STS-vended JWT and fails if the account has not
	// enabled outbound identity federation, rather than quietly producing a proof
	// the target cannot verify.
	AWSProofOIDC AWSProof = "oidc"

	// AWSProofSigV4 requires the SigV4 GetCallerIdentity proof. Only GCP's STS
	// accepts it.
	AWSProofSigV4 AWSProof = "sigv4"
)

// ParseAWSProof resolves the configured proof kind, rejecting anything it does
// not recognise instead of silently defaulting — a typo in "sigv4" must not
// hand a workload the other proof.
func ParseAWSProof(s string) (AWSProof, error) {
	switch p := AWSProof(s); p {
	case "":
		return AWSProofAuto, nil
	case AWSProofAuto, AWSProofOIDC, AWSProofSigV4:
		return p, nil
	default:
		return "", fmt.Errorf("aws: unknown proof kind %q; want one of auto, oidc, sigv4", s)
	}
}

// AWSProofEnv overrides the proof kind for a process that cannot pass an option:
// a container, a sidecar, or anything embedding this library behind a CLI it does
// not control. An unrecognised value is an error, not a fallback to the default.
//
// This is deliberately not a credential input, only a format selection — both
// proofs assert the same IAM principal, and a wrong choice is rejected by the
// target rather than silently authenticating as something else. Whichever kind is
// used is reported by "cloud-auth doctor".
const AWSProofEnv = "CLOUD_AUTH_AWS_PROOF"

// resolveProof applies AWSProofEnv unless the caller passed WithAWSProof, which
// wins: an explicit option in code is a stronger statement than the environment
// the process happens to inherit.
func (a *AWS) resolveProof() {
	if a.proof != "" {
		return
	}
	v := a.getenv(AWSProofEnv)
	if v == "" {
		a.proof = AWSProofAuto
		return
	}
	p, err := ParseAWSProof(v)
	if err != nil {
		// Held rather than returned: NewAWS has no error return, and defaulting
		// past a typo in this variable would hand the workload the other proof.
		a.proofErr = fmt.Errorf("%s: %w", AWSProofEnv, err)
		return
	}
	a.proof = p
}

// webIdentityTokenAPI is the one STS call this path makes. Injected in tests;
// satisfied by *sts.Client.
type webIdentityTokenAPI interface {
	GetWebIdentityToken(context.Context, *sts.GetWebIdentityTokenInput, ...func(*sts.Options)) (*sts.GetWebIdentityTokenOutput, error)
}

// WithAWSProof selects which proof the source mints on EC2, ECS and Lambda.
func WithAWSProof(p AWSProof) AWSOption { return func(a *AWS) { a.proof = p } }

// WithAWSWebIdentityTokenAPI injects the STS client used to vend the outbound
// OIDC JWT. When unset, one is built from the ambient configuration.
func WithAWSWebIdentityTokenAPI(c webIdentityTokenAPI) AWSOption {
	return func(a *AWS) { a.stsAPI = c }
}

// outboundState is the AWS provider's state for this path, kept together so the
// zero value of AWS stays usable.
type outboundState struct {
	// off records that the account has outbound federation disabled, so the
	// AWSProofAuto fallback costs one STS call per process rather than one per
	// mint.
	off atomic.Bool

	once sync.Once
	api  webIdentityTokenAPI
	err  error
}

// mintPrincipalProof mints a proof of the ambient IAM principal for a runtime
// that has no OIDC token of its own: EC2, ECS and Lambda.
func (a *AWS) mintPrincipalProof(ctx context.Context, audience string) (*core.SourceToken, error) {
	if a.proofErr != nil {
		return nil, a.proofErr
	}
	switch a.proof {
	case AWSProofSigV4:
		return a.mintSigV4(ctx, audience)
	case AWSProofOIDC:
		return a.mintOIDC(ctx, audience)
	case AWSProofAuto, "":
	default:
		return nil, fmt.Errorf("aws: unknown proof kind %q; want one of auto, oidc, sigv4", a.proof)
	}

	if a.outbound.off.Load() {
		return a.mintSigV4(ctx, audience)
	}
	tok, err := a.mintOIDC(ctx, audience)
	if err == nil {
		return tok, nil
	}
	// Fall back only on the account-level "not enabled" answer. An AccessDenied
	// on sts:GetWebIdentityToken means the feature is on and this principal is
	// not permitted to use it, which is a policy the operator wants to see, not
	// something to route around.
	var disabled *ststypes.OutboundWebIdentityFederationDisabledException
	if !errors.As(err, &disabled) {
		return nil, err
	}
	a.outbound.off.Store(true)
	return a.mintSigV4(ctx, audience)
}

// mintOIDC asks STS for a JWT asserting the calling principal's identity.
func (a *AWS) mintOIDC(ctx context.Context, audience string) (*core.SourceToken, error) {
	api, err := a.webIdentityAPI(ctx)
	if err != nil {
		return nil, err
	}
	out, err := api.GetWebIdentityToken(ctx, &sts.GetWebIdentityTokenInput{
		// Exactly one audience, always, even though the API accepts ten. A JWT
		// carrying ten audiences is a valid bearer proof at all ten, so any one
		// recipient can replay it against the other nine. There is no option to
		// widen this because there is no version of that which is safe here.
		Audience:         []string{audience},
		SigningAlgorithm: aws.String(outboundSigningAlgorithm),
		DurationSeconds:  aws.Int32(int32(outboundTokenDuration.Seconds())),
		// Tags is deliberately unset. STS copies request tags into the JWT as
		// request_tags claims, and the target authorizes against claims — a
		// caller-supplied claim on a proof of identity is a claim-injection
		// surface, so this path does not offer one.
	})
	if err != nil {
		return nil, fmt.Errorf("aws: sts:GetWebIdentityToken: %w", err)
	}
	if out.WebIdentityToken == nil || *out.WebIdentityToken == "" {
		return nil, fmt.Errorf("aws: STS returned an empty web identity token")
	}
	raw := *out.WebIdentityToken

	claims, err := jwt.ParseUnverified(raw)
	if err != nil {
		// Fail closed. The target might still verify this token, but we would be
		// reporting an empty issuer and subject for it, and subject pinning is
		// what the target authorizes on.
		return nil, fmt.Errorf("aws: parsing STS web identity token: %w", err)
	}
	// Defence in depth against the request above being widened, here or by STS:
	// a proof bound to more parties than we asked for must not be disclosed.
	if len(claims.Audiences) != 1 || claims.Audiences[0] != audience {
		return nil, fmt.Errorf("aws: STS returned a token with audiences %v, but the proof was "+
			"requested for %q alone; refusing to present a proof bound to another party",
			claims.Audiences, audience)
	}
	tok := &core.SourceToken{
		Kind:  core.OIDC,
		Value: raw,
		// The real issuer and subject, not a guess: iss is the account's STS
		// issuer, sub the calling principal's ARN. Note that sub identifies the
		// role, not the session — two workloads sharing a role are one subject to
		// the target, so subject pinning cannot separate them.
		Issuer:   claims.Issuer,
		Subject:  claims.Subject,
		Audience: audience,
		// STS reports the expiry directly; prefer it over the exp claim.
		Expiry: claims.Expiry,
	}
	if out.Expiration != nil {
		tok.Expiry = *out.Expiration
	}
	return tok, nil
}

// webIdentityAPI builds the STS client once.
//
// GetWebIdentityToken is not served by the global sts.amazonaws.com endpoint, so
// unlike the SigV4 proof — where the region only has to match what was signed —
// the region here decides whether the call reaches anything at all.
func (a *AWS) webIdentityAPI(ctx context.Context) (webIdentityTokenAPI, error) {
	if a.stsAPI != nil {
		return a.stsAPI, nil
	}
	a.outbound.once.Do(func() {
		region := a.region
		if a.creds != nil {
			// Caller-supplied identity: do not load the ambient chain at all, or a
			// host with no ambient credentials would fail before using the ones it
			// was handed.
			if region == "" {
				region = defaultSigningRegion
			}
			a.outbound.api = sts.NewFromConfig(aws.Config{Region: region, Credentials: a.creds})
			return
		}
		cfg, err := a.ambientConfig(ctx)
		if err != nil {
			a.outbound.err = fmt.Errorf("aws: loading config: %w", err)
			return
		}
		if region == "" {
			region = cfg.Region
		}
		if region == "" {
			region = defaultSigningRegion
		}
		a.outbound.api = sts.NewFromConfig(cfg, func(o *sts.Options) { o.Region = region })
	})
	return a.outbound.api, a.outbound.err
}
