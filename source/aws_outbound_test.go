package source

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscreds "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// stsJWT builds an unsigned JWT shaped like what sts:GetWebIdentityToken returns.
// aud is passed through as-is so a test can hand back the multi-audience form the
// mint path is required to refuse.
func stsJWT(aud any) string {
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	return enc(map[string]any{"alg": "RS256", "typ": "JWT"}) + "." +
		enc(map[string]any{
			"iss": "https://11111111-2222-3333-4444-555555555555.tokens.sts.global.api.aws",
			"sub": "arn:aws:iam::123456789012:role/DataProcessingRole",
			"aud": aud,
			"exp": 9999999999,
		}) + ".sig"
}

// fakeSTS records the request it was given and returns a canned response.
type fakeSTS struct {
	got   *sts.GetWebIdentityTokenInput
	calls int
	token string
	exp   *time.Time
	err   error
}

func (f *fakeSTS) GetWebIdentityToken(_ context.Context, in *sts.GetWebIdentityTokenInput, _ ...func(*sts.Options)) (*sts.GetWebIdentityTokenOutput, error) {
	f.calls++
	f.got = in
	if f.err != nil {
		return nil, f.err
	}
	return &sts.GetWebIdentityTokenOutput{WebIdentityToken: aws.String(f.token), Expiration: f.exp}, nil
}

// ec2Env is an EC2-shaped environment: none of the sub-runtime hints are set, so
// subRuntime resolves to "ec2" and Mint takes the principal-proof path.
func ec2Env() AWSOption { return WithAWSEnv(envFunc(map[string]string{})) }

func TestOutboundMintProducesOIDCProofFromRealClaims(t *testing.T) {
	exp := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	f := &fakeSTS{token: stsJWT("api://AzureADTokenExchange"), exp: &exp}
	a := NewAWS(ec2Env(), WithAWSWebIdentityTokenAPI(f))

	tok, err := a.Mint(context.Background(), "api://AzureADTokenExchange")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.Kind != core.OIDC {
		t.Errorf("Kind = %v, want %v: an STS-vended JWT is what makes AWS→Azure first-class", tok.Kind, core.OIDC)
	}
	if want := "https://11111111-2222-3333-4444-555555555555.tokens.sts.global.api.aws"; tok.Issuer != want {
		t.Errorf("Issuer = %q, want %q", tok.Issuer, want)
	}
	if want := "arn:aws:iam::123456789012:role/DataProcessingRole"; tok.Subject != want {
		t.Errorf("Subject = %q, want %q; the target authorizes on sub, so a guess is not good enough", tok.Subject, want)
	}
	// STS reports the expiry directly; that must win over the exp claim, which
	// here is deliberately a different (far future) value.
	if !tok.Expiry.Equal(exp) {
		t.Errorf("Expiry = %v, want the STS-reported %v", tok.Expiry, exp)
	}
}

// The request shape is a trust boundary, not a detail: one audience, RS256, an
// explicit duration, and no tags.
func TestOutboundMintRequestIsPinned(t *testing.T) {
	f := &fakeSTS{token: stsJWT("sts.googleapis.com")}
	a := NewAWS(ec2Env(), WithAWSWebIdentityTokenAPI(f))

	if _, err := a.Mint(context.Background(), "sts.googleapis.com"); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if got := f.got.Audience; len(got) != 1 || got[0] != "sts.googleapis.com" {
		t.Errorf("Audience = %v, want exactly one entry: a JWT bound to N audiences is replayable at all N", got)
	}
	if f.got.SigningAlgorithm == nil || *f.got.SigningAlgorithm != "RS256" {
		t.Errorf("SigningAlgorithm = %v, want RS256; Entra rejects anything else", f.got.SigningAlgorithm)
	}
	if f.got.DurationSeconds == nil {
		t.Error("DurationSeconds is nil: STS would default to 300s, which the retry budget can eat")
	} else if *f.got.DurationSeconds != 900 {
		t.Errorf("DurationSeconds = %d, want 900", *f.got.DurationSeconds)
	}
	if f.got.Tags != nil {
		t.Errorf("Tags = %v, want nil: request tags become JWT claims the target authorizes on", f.got.Tags)
	}
}

// If STS ever hands back a token bound to more parties than we asked for, the
// proof must not leave the process.
func TestOutboundMintRefusesMultiAudienceToken(t *testing.T) {
	f := &fakeSTS{token: stsJWT([]string{"api://AzureADTokenExchange", "https://attacker.example"})}
	a := NewAWS(ec2Env(), WithAWSWebIdentityTokenAPI(f))

	tok, err := a.Mint(context.Background(), "api://AzureADTokenExchange")
	if err == nil {
		t.Fatalf("Mint succeeded and returned a proof presentable to a second party: %+v", tok)
	}
	if !strings.Contains(err.Error(), "another party") {
		t.Errorf("error = %v, want it to name the extra audience as the reason", err)
	}
}

func TestOutboundMintFailsClosedOnUnparseableToken(t *testing.T) {
	f := &fakeSTS{token: "not.a.jwt"}
	a := NewAWS(ec2Env(), WithAWSWebIdentityTokenAPI(f))

	if _, err := a.Mint(context.Background(), "aud"); err == nil {
		t.Error("Mint succeeded on an unparseable token; it would report an empty subject for a proof the target authorizes on subject")
	}
}

func TestOutboundMintRejectsEmptyToken(t *testing.T) {
	f := &fakeSTS{token: ""}
	a := NewAWS(ec2Env(), WithAWSWebIdentityTokenAPI(f))

	if _, err := a.Mint(context.Background(), "aud"); err == nil {
		t.Error("Mint succeeded with an empty token")
	}
}

// Auto falls back to SigV4 when the account has not enabled the feature, and
// remembers, so the probe costs one call per process rather than one per mint.
func TestOutboundAutoFallsBackToSigV4AndRemembers(t *testing.T) {
	f := &fakeSTS{err: &ststypes.OutboundWebIdentityFederationDisabledException{}}
	a := NewAWS(ec2Env(),
		WithAWSWebIdentityTokenAPI(f),
		WithAWSRegion("us-west-2"),
		WithAWSCredentials(awscreds.NewStaticCredentialsProvider("AKIAEXAMPLE", "secret", "")),
	)

	for i := range 3 {
		tok, err := a.Mint(context.Background(), "sts.googleapis.com")
		if err != nil {
			t.Fatalf("mint %d: %v", i, err)
		}
		if tok.Kind != core.AWSSigV4 {
			t.Fatalf("mint %d: Kind = %v, want %v", i, tok.Kind, core.AWSSigV4)
		}
	}
	if f.calls != 1 {
		t.Errorf("GetWebIdentityToken called %d times, want 1: the disabled verdict should be cached", f.calls)
	}
}

// Any other STS failure is surfaced, not papered over with a different proof.
// AccessDenied on sts:GetWebIdentityToken means the feature is on and this
// principal is not allowed to use it — a policy the operator needs to see.
func TestOutboundAutoDoesNotFallBackOnAccessDenied(t *testing.T) {
	sentinel := errors.New("AccessDenied: not authorized to perform sts:GetWebIdentityToken")
	f := &fakeSTS{err: sentinel}
	a := NewAWS(ec2Env(), WithAWSWebIdentityTokenAPI(f))

	_, err := a.Mint(context.Background(), "sts.googleapis.com")
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want the STS error surfaced; a silent switch to SigV4 hides a policy gap", err)
	}
}

// Pinning oidc must fail rather than hand back a proof the target cannot verify.
func TestOutboundProofOIDCDoesNotFallBack(t *testing.T) {
	f := &fakeSTS{err: &ststypes.OutboundWebIdentityFederationDisabledException{}}
	a := NewAWS(ec2Env(), WithAWSWebIdentityTokenAPI(f), WithAWSProof(AWSProofOIDC))

	tok, err := a.Mint(context.Background(), "api://AzureADTokenExchange")
	if err == nil {
		t.Fatalf("Mint succeeded with %v proof despite AWSProofOIDC and the feature disabled", tok.Kind)
	}
}

// Pinning sigv4 must not consult STS at all: that is the escape hatch for a GCP
// pool that has only an aws provider configured.
func TestOutboundProofSigV4SkipsSTSEntirely(t *testing.T) {
	f := &fakeSTS{token: stsJWT("sts.googleapis.com")}
	a := NewAWS(ec2Env(),
		WithAWSWebIdentityTokenAPI(f),
		WithAWSProof(AWSProofSigV4),
		WithAWSRegion("eu-west-1"),
		WithAWSCredentials(awscreds.NewStaticCredentialsProvider("AKIAEXAMPLE", "secret", "")),
	)

	tok, err := a.Mint(context.Background(), "sts.googleapis.com")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.Kind != core.AWSSigV4 {
		t.Errorf("Kind = %v, want %v", tok.Kind, core.AWSSigV4)
	}
	if f.calls != 0 {
		t.Errorf("GetWebIdentityToken called %d times under AWSProofSigV4, want 0", f.calls)
	}
}

// EKS IRSA already has a projected OIDC token; the outbound path must not
// intercept it. Otherwise a cluster with a working IRSA setup would silently
// start presenting a different issuer and subject to its targets.
func TestOutboundDoesNotHijackIRSA(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/token"
	if err := os.WriteFile(path, []byte(azureJWT("api://AzureADTokenExchange")), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeSTS{token: stsJWT("api://AzureADTokenExchange")}
	a := NewAWS(
		WithAWSEnv(envFunc(map[string]string{
			"AWS_WEB_IDENTITY_TOKEN_FILE": path,
			"AWS_ROLE_ARN":                "arn:aws:iam::123456789012:role/irsa",
		})),
		WithAWSWebIdentityTokenAPI(f),
	)

	tok, err := a.Mint(context.Background(), "api://AzureADTokenExchange")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if f.calls != 0 {
		t.Errorf("GetWebIdentityToken called %d times on EKS IRSA, want 0", f.calls)
	}
	if tok.Issuer != "https://oidc.aks/cluster" {
		t.Errorf("Issuer = %q, want the cluster's own issuer", tok.Issuer)
	}
}

func TestParseAWSProof(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    AWSProof
		wantErr bool
	}{
		{"", AWSProofAuto, false},
		{"auto", AWSProofAuto, false},
		{"oidc", AWSProofOIDC, false},
		{"sigv4", AWSProofSigV4, false},
		// A typo must not silently select the other proof.
		{"sigv-4", "", true},
		{"SigV4", "", true},
		{"sig", "", true},
		{"none", "", true},
	} {
		got, err := ParseAWSProof(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseAWSProof(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			continue
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("ParseAWSProof(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// An unrecognised proof kind set directly on the struct must fail closed too,
// rather than fall through to a default.
func TestOutboundUnknownProofKindFails(t *testing.T) {
	a := NewAWS(ec2Env(), WithAWSProof(AWSProof("sigv-4")))
	if _, err := a.Mint(context.Background(), "aud"); err == nil {
		t.Error("Mint succeeded with an unrecognised proof kind")
	}
}

func TestOutboundProofFromEnv(t *testing.T) {
	f := &fakeSTS{token: stsJWT("sts.googleapis.com")}
	a := NewAWS(
		WithAWSEnv(envFunc(map[string]string{AWSProofEnv: "sigv4"})),
		WithAWSWebIdentityTokenAPI(f),
		WithAWSRegion("us-east-1"),
		WithAWSCredentials(awscreds.NewStaticCredentialsProvider("AKIAEXAMPLE", "secret", "")),
	)
	tok, err := a.Mint(context.Background(), "sts.googleapis.com")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.Kind != core.AWSSigV4 {
		t.Errorf("Kind = %v, want %v from %s=sigv4", tok.Kind, core.AWSSigV4, AWSProofEnv)
	}
}

// An explicit option outranks the environment the process inherited.
func TestOutboundProofOptionBeatsEnv(t *testing.T) {
	f := &fakeSTS{token: stsJWT("sts.googleapis.com")}
	a := NewAWS(
		WithAWSEnv(envFunc(map[string]string{AWSProofEnv: "sigv4"})),
		WithAWSWebIdentityTokenAPI(f),
		WithAWSProof(AWSProofOIDC),
	)
	tok, err := a.Mint(context.Background(), "sts.googleapis.com")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.Kind != core.OIDC {
		t.Errorf("Kind = %v, want %v: WithAWSProof must beat %s", tok.Kind, core.OIDC, AWSProofEnv)
	}
}

// A typo in the environment variable must not silently hand back the other proof.
func TestOutboundBadEnvFailsClosed(t *testing.T) {
	f := &fakeSTS{token: stsJWT("sts.googleapis.com")}
	a := NewAWS(
		WithAWSEnv(envFunc(map[string]string{AWSProofEnv: "sigv-4"})),
		WithAWSWebIdentityTokenAPI(f),
	)
	_, err := a.Mint(context.Background(), "sts.googleapis.com")
	if err == nil {
		t.Fatal("Mint succeeded with an unparseable proof kind in the environment")
	}
	if !strings.Contains(err.Error(), AWSProofEnv) {
		t.Errorf("error = %v, want it to name %s so the operator knows where to look", err, AWSProofEnv)
	}
	if f.calls != 0 {
		t.Errorf("STS called %d times despite the configuration error, want 0", f.calls)
	}
}
