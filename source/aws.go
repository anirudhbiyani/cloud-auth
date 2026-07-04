package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
	"github.com/anirudhbiyani/cloud-auth/internal/imds"
	"github.com/anirudhbiyani/cloud-auth/internal/jwt"
)

// DefaultSTSEndpoint is the global AWS STS endpoint used to build the
// GetCallerIdentity proof.
const DefaultSTSEndpoint = "https://sts.amazonaws.com"

// emptyPayloadHash is SHA-256 of the empty string (GetCallerIdentity has no body).
var emptyPayloadHash = func() string {
	sum := sha256.Sum256(nil)
	return hex.EncodeToString(sum[:])
}()

// AWS is the Source Identity Provider for EC2, ECS, and EKS. EC2/ECS mint a
// SigV4-signed GetCallerIdentity proof; EKS-IRSA mints a projected OIDC token.
// EKS Pod Identity is detected but flagged non-federatable.
type AWS struct {
	getenv      func(string) string
	readFile    func(string) ([]byte, error)
	imds        *imds.Client
	region      string
	creds       aws.CredentialsProvider
	stsEndpoint string
	k8sClient   k8sTokenMinter // injected for tests; nil => derive in-cluster
}

// AWSOption configures an AWS provider.
type AWSOption func(*AWS)

func WithAWSEnv(f func(string) string) AWSOption { return func(a *AWS) { a.getenv = f } }
func WithAWSFileReader(f func(string) ([]byte, error)) AWSOption {
	return func(a *AWS) { a.readFile = f }
}
func WithAWSIMDS(c *imds.Client) AWSOption                   { return func(a *AWS) { a.imds = c } }
func WithAWSRegion(r string) AWSOption                       { return func(a *AWS) { a.region = r } }
func WithAWSCredentials(p aws.CredentialsProvider) AWSOption { return func(a *AWS) { a.creds = p } }
func WithAWSSTSEndpoint(e string) AWSOption                  { return func(a *AWS) { a.stsEndpoint = e } }

// WithAWSK8sTokenClient injects a Kubernetes TokenRequest client used by the
// EKS-IRSA mint path to dynamically re-mint a projected token for a requested
// audience. When unset, the client is derived from the in-cluster environment.
func WithAWSK8sTokenClient(c k8sTokenMinter) AWSOption { return func(a *AWS) { a.k8sClient = c } }

// NewAWS builds an AWS provider with defaults.
func NewAWS(opts ...AWSOption) *AWS {
	a := &AWS{
		getenv:      os.Getenv,
		readFile:    os.ReadFile,
		imds:        imds.New(),
		stsEndpoint: DefaultSTSEndpoint,
	}
	for _, o := range opts {
		o(a)
	}
	return a
}

// subRuntime resolves the AWS sub-runtime from environment hints. IMDS is only
// consulted as the EC2 fallback (done in Detect, not here).
func (a *AWS) subRuntime() string {
	switch {
	case a.getenv("AWS_WEB_IDENTITY_TOKEN_FILE") != "":
		return "eks-irsa"
	case a.getenv("AWS_LAMBDA_FUNCTION_NAME") != "":
		// Lambda vends task-role credentials in-process; it mints the SigV4
		// GetCallerIdentity proof, same as EC2/ECS.
		return "lambda"
	case a.getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI") != "":
		// EKS Pod Identity agent vends creds over the full URI; not OIDC.
		return "eks-pod-identity"
	case a.getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") != "",
		a.getenv("ECS_CONTAINER_METADATA_URI_V4") != "",
		a.getenv("ECS_CONTAINER_METADATA_URI") != "":
		return "ecs"
	default:
		return "ec2"
	}
}

// Detect resolves the AWS sub-runtime, confirming EC2 via IMDS.
func (a *AWS) Detect(ctx context.Context) (*cloudauth.Runtime, error) {
	sub := a.subRuntime()
	rt := &cloudauth.Runtime{Cloud: cloudauth.AWS, SubRuntime: sub, Federatable: true}
	switch sub {
	case "eks-irsa":
		rt.Subject = a.getenv("AWS_ROLE_ARN")
	case "eks-pod-identity":
		rt.Federatable = false // deliberately not externally federatable
	case "ec2":
		arn, err := a.imds.Get(ctx, "/latest/meta-data/iam/info")
		if err != nil {
			// Try a lighter probe; if IMDS is unreachable, we're not on EC2.
			if _, err2 := a.imds.Get(ctx, "/latest/meta-data/instance-id"); err2 != nil {
				return nil, fmt.Errorf("%w: %v", cloudauth.ErrNotThisRuntime, err2)
			}
		} else {
			rt.Subject = string(arn)
		}
	}
	return rt, nil
}

// Mint produces the proof appropriate to the sub-runtime.
func (a *AWS) Mint(ctx context.Context, audience string) (*cloudauth.SourceToken, error) {
	if audience == "" {
		return nil, fmt.Errorf("aws: audience is required")
	}
	switch a.subRuntime() {
	case "eks-irsa":
		return a.mintIRSA(ctx, audience)
	case "eks-pod-identity":
		return nil, fmt.Errorf("%w: EKS Pod Identity vends AWS-internal credentials that are not an "+
			"externally-verifiable token; use an OIDC-native source such as EKS IRSA for cross-cloud federation",
			cloudauth.ErrNonFederatableSource)
	default: // ec2, ecs
		return a.mintSigV4(ctx, audience)
	}
}

func (a *AWS) mintIRSA(ctx context.Context, audience string) (*cloudauth.SourceToken, error) {
	raw, err := a.readFile(a.getenv("AWS_WEB_IDENTITY_TOKEN_FILE"))
	if err != nil {
		return nil, fmt.Errorf("aws: reading projected web identity token: %w", err)
	}
	claims, err := jwt.ParseUnverified(string(raw))
	if err != nil {
		return nil, fmt.Errorf("aws: parsing web identity token: %w", err)
	}
	// Fast path: the on-disk projected token already carries the requested aud.
	if claims.HasAudience(audience) {
		return &cloudauth.SourceToken{
			Kind:     cloudauth.OIDC,
			Value:    string(raw),
			Issuer:   claims.Issuer,
			Subject:  claims.Subject,
			Audience: audience,
			Expiry:   claims.Expiry,
		}, nil
	}
	// The projected SA token's aud is fixed by the pod's projected volume. When
	// running in-cluster, mint a fresh token carrying the requested audience via
	// the Kubernetes TokenRequest API rather than failing closed.
	if token, available, err := mintDynamicAudienceToken(ctx, a.k8sClient, a.getenv, a.readFile, claims, audience); available {
		if err != nil {
			return nil, fmt.Errorf("aws: %w", err)
		}
		minted, _ := jwt.ParseUnverified(token)
		return &cloudauth.SourceToken{
			Kind:     cloudauth.OIDC,
			Value:    token,
			Issuer:   minted.Issuer,
			Subject:  minted.Subject,
			Audience: audience,
			Expiry:   minted.Expiry,
		}, nil
	}
	// Not in-cluster (or TokenRequest unavailable): fail closed with guidance.
	return nil, fmt.Errorf(
		"aws: projected web identity token audience %v does not include the requested audience %q; "+
			"set the projected service-account token's audience to match the target",
		claims.Audiences, audience)
}

// mintSigV4 builds and SigV4-signs a GetCallerIdentity request, then serializes
// it into the GCP-expected token shape ({url, method, headers}). The audience
// is carried in the x-goog-cloud-target-resource header, binding the proof to
// the intended target and defeating replay against another trust.
func (a *AWS) mintSigV4(ctx context.Context, audience string) (*cloudauth.SourceToken, error) {
	creds, region, err := a.resolveCreds(ctx)
	if err != nil {
		return nil, err
	}
	reqURL := a.stsEndpoint + "/?Action=GetCallerIdentity&Version=2011-06-15"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-goog-cloud-target-resource", audience)

	signer := v4.NewSigner()
	if err := signer.SignHTTP(ctx, creds, req, emptyPayloadHash, "sts", region, time.Now().UTC()); err != nil {
		return nil, fmt.Errorf("aws: signing GetCallerIdentity: %w", err)
	}

	type kv struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	proof := struct {
		URL     string `json:"url"`
		Method  string `json:"method"`
		Headers []kv   `json:"headers"`
	}{URL: reqURL, Method: http.MethodPost}
	for k := range req.Header {
		proof.Headers = append(proof.Headers, kv{Key: k, Value: req.Header.Get(k)})
	}
	proof.Headers = append(proof.Headers, kv{Key: "host", Value: req.URL.Host})
	value, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}
	return &cloudauth.SourceToken{
		Kind:     cloudauth.AWSSigV4,
		Value:    string(value),
		Subject:  creds.AccessKeyID, // best-effort; the real principal is resolved by STS
		Audience: audience,
	}, nil
}

// resolveCreds returns the credentials and region for SigV4 signing.
func (a *AWS) resolveCreds(ctx context.Context) (aws.Credentials, string, error) {
	region := a.region
	if a.creds != nil {
		c, err := a.creds.Retrieve(ctx)
		if err != nil {
			return aws.Credentials{}, "", fmt.Errorf("aws: retrieving credentials: %w", err)
		}
		if region == "" {
			region = "us-east-1"
		}
		return c, region, nil
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return aws.Credentials{}, "", fmt.Errorf("aws: loading config: %w", err)
	}
	c, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return aws.Credentials{}, "", fmt.Errorf("aws: retrieving credentials: %w", err)
	}
	if region == "" {
		region = cfg.Region
	}
	if region == "" {
		region = "us-east-1"
	}
	return c, region, nil
}
