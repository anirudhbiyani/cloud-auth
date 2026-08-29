package source

import (
	"context"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

func TestGCPDetectCloudRun(t *testing.T) {
	srv := fakeGCPMetadata(t, true)
	g := NewGCP(WithGCPMetadataURL(srv.URL), WithGCPHTTPClient(srv.Client()),
		WithGCPEnv(envFunc(map[string]string{"K_SERVICE": "my-service"})))
	rt, err := g.Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if rt.SubRuntime != "cloud-run" {
		t.Errorf("subruntime = %q, want cloud-run", rt.SubRuntime)
	}
	if rt.Cloud != core.GCP || !rt.Federatable {
		t.Errorf("runtime = %+v, want federatable gcp", rt)
	}
}

func TestGCPDetectCloudFunctions(t *testing.T) {
	srv := fakeGCPMetadata(t, true)
	g := NewGCP(WithGCPMetadataURL(srv.URL), WithGCPHTTPClient(srv.Client()),
		WithGCPEnv(envFunc(map[string]string{"FUNCTION_TARGET": "handler"})))
	rt, err := g.Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if rt.SubRuntime != "cloud-functions" {
		t.Errorf("subruntime = %q, want cloud-functions", rt.SubRuntime)
	}
}

func TestGCPCloudRunMintUsesMetadataIdentity(t *testing.T) {
	srv := fakeGCPMetadata(t, true)
	g := NewGCP(WithGCPMetadataURL(srv.URL), WithGCPHTTPClient(srv.Client()),
		WithGCPEnv(envFunc(map[string]string{"K_SERVICE": "my-service"})))
	tok, err := g.Mint(context.Background(), "sts.amazonaws.com")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.Kind != core.OIDC || tok.Audience != "sts.amazonaws.com" {
		t.Errorf("token = %+v", tok)
	}
}

// GKE hint (KUBERNETES_SERVICE_HOST) must still win over the serverless hints,
// preserving the existing detection ordering.
func TestGCPDetectGKEStillPreferredOverServerless(t *testing.T) {
	srv := fakeGCPMetadata(t, true)
	g := NewGCP(WithGCPMetadataURL(srv.URL), WithGCPHTTPClient(srv.Client()),
		WithGCPEnv(envFunc(map[string]string{
			"KUBERNETES_SERVICE_HOST": "10.0.0.1",
			"K_SERVICE":               "should-not-win",
		})))
	rt, err := g.Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if rt.SubRuntime != "gke" {
		t.Errorf("subruntime = %q, want gke", rt.SubRuntime)
	}
}
