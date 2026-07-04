package sip

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
	"github.com/anirudhbiyani/cloud-auth/internal/imds"
)

func TestAWSDetectEC2ViaIMDS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.Write([]byte("tok"))
			return
		}
		if r.Header.Get("X-aws-ec2-metadata-token") != "tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte("arn:aws:sts::123:assumed-role/foo/i-abc"))
	}))
	defer srv.Close()

	a := NewAWS(
		WithAWSEnv(envFunc(nil)),
		WithAWSIMDS(imds.New(imds.WithBaseURL(srv.URL), imds.WithHTTPClient(srv.Client()))),
	)
	rt, err := a.Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if rt.SubRuntime != "ec2" || !rt.Federatable {
		t.Errorf("runtime = %+v, want federatable ec2", rt)
	}
}

func TestAWSDetectIRSA(t *testing.T) {
	a := NewAWS(WithAWSEnv(envFunc(map[string]string{
		"AWS_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/token",
		"AWS_ROLE_ARN":                "arn:aws:iam::123:role/pod",
	})))
	rt, err := a.Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if rt.SubRuntime != "eks-irsa" || !rt.Federatable {
		t.Errorf("runtime = %+v, want federatable eks-irsa", rt)
	}
}

func TestAWSDetectPodIdentityNonFederatable(t *testing.T) {
	a := NewAWS(WithAWSEnv(envFunc(map[string]string{
		"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://169.254.170.23/v1/credentials",
	})))
	rt, err := a.Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if rt.SubRuntime != "eks-pod-identity" {
		t.Errorf("subruntime = %q, want eks-pod-identity", rt.SubRuntime)
	}
	if rt.Federatable {
		t.Error("EKS Pod Identity must be flagged NON-federatable")
	}
}

func TestAWSMintPodIdentityRejectedWithGuidance(t *testing.T) {
	a := NewAWS(WithAWSEnv(envFunc(map[string]string{
		"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://169.254.170.23/v1/credentials",
	})))
	_, err := a.Mint(context.Background(), "sts.amazonaws.com")
	if !errors.Is(err, cloudauth.ErrNonFederatableSource) {
		t.Fatalf("err = %v, want ErrNonFederatableSource", err)
	}
	// The message must point the user at an OIDC-native source.
	if !strings.Contains(strings.ToLower(err.Error()), "irsa") {
		t.Errorf("error should guide user to IRSA/OIDC; got %q", err.Error())
	}
}

func TestAWSMintIRSAReadsTokenFile(t *testing.T) {
	dir := t.TempDir()
	tokFile := filepath.Join(dir, "token")
	os.WriteFile(tokFile, []byte(gcpJWT("sts.amazonaws.com")), 0600) // reuse a valid JWT shape

	a := NewAWS(WithAWSEnv(envFunc(map[string]string{
		"AWS_WEB_IDENTITY_TOKEN_FILE": tokFile,
		"AWS_ROLE_ARN":                "arn:aws:iam::123:role/pod",
	})))
	tok, err := a.Mint(context.Background(), "sts.amazonaws.com")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.Kind != cloudauth.OIDC {
		t.Errorf("IRSA token kind = %v, want OIDC", tok.Kind)
	}
}

func TestAWSMintEC2ProducesSigV4Proof(t *testing.T) {
	// No env hints => EC2 path. Inject static creds so signing is offline+deterministic.
	a := NewAWS(
		WithAWSEnv(envFunc(nil)),
		WithAWSRegion("us-east-1"),
		WithAWSCredentials(credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "secret", "session-tok")),
	)
	tok, err := a.Mint(context.Background(), "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/aws")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.Kind != cloudauth.AWSSigV4 {
		t.Fatalf("kind = %v, want AWSSigV4", tok.Kind)
	}
	// The serialized proof must be a replayable GetCallerIdentity request that
	// carries a SigV4 Authorization header.
	if !strings.Contains(tok.Value, "GetCallerIdentity") {
		t.Errorf("proof missing GetCallerIdentity action: %s", tok.Value)
	}
	if !strings.Contains(tok.Value, "AWS4-HMAC-SHA256") {
		t.Errorf("proof missing SigV4 Authorization: %s", tok.Value)
	}
}

var _ aws.CredentialsProvider = credentials.NewStaticCredentialsProvider("", "", "")
