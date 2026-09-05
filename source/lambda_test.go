package source

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/anirudhbiyani/cloud-auth/core"
)

func TestAWSDetectLambda(t *testing.T) {
	a := NewAWS(WithAWSEnv(envFunc(map[string]string{
		"AWS_LAMBDA_FUNCTION_NAME": "my-fn",
	})))
	rt, err := a.Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if rt.SubRuntime != "lambda" {
		t.Errorf("subruntime = %q, want lambda", rt.SubRuntime)
	}
	if !rt.Federatable {
		t.Error("lambda must be federatable")
	}
}

func TestAWSMintLambdaUsesSigV4(t *testing.T) {
	// Lambda reuses the SigV4 GetCallerIdentity proof path (same as EC2/ECS).
	a := NewAWS(
		WithAWSEnv(envFunc(map[string]string{
			"AWS_LAMBDA_FUNCTION_NAME": "my-fn",
		})),
		WithAWSRegion("us-east-1"),
		WithAWSCredentials(credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "secret", "session-tok")),
		// Pin the proof.
		WithAWSProof(AWSProofSigV4),
	)
	tok, err := a.Mint(context.Background(), "//iam.googleapis.com/x")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.Kind != core.AWSSigV4 {
		t.Fatalf("kind = %v, want AWSSigV4", tok.Kind)
	}
	if !strings.Contains(tok.Value, "GetCallerIdentity") {
		t.Errorf("proof missing GetCallerIdentity: %s", tok.Value)
	}
}
