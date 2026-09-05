package gcp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// recordingWIF answers existence probes however the test wants and records every destructive call.
type recordingWIF struct {
	// WorkloadIdentityClient is embedded so this fake keeps compiling when the interface gains a method it does not care about — this file is about rollback, not enumeration, and an unimplemented method it never calls should not make it a compile error.
	WorkloadIdentityClient

	poolGetErr     error
	providerGetErr error
	createProvErr  error
	deleteErr      error
	deletedPools   []string
}

func (r *recordingWIF) GetWorkloadIdentityPool(context.Context, string) (*WorkloadIdentityPool, error) {
	return &WorkloadIdentityPool{}, r.poolGetErr
}
func (r *recordingWIF) CreateWorkloadIdentityPool(context.Context, string, string, *WorkloadIdentityPool) (*WorkloadIdentityPool, error) {
	return &WorkloadIdentityPool{}, nil
}
func (r *recordingWIF) DeleteWorkloadIdentityPool(_ context.Context, name string) error {
	r.deletedPools = append(r.deletedPools, name)
	return r.deleteErr
}
func (r *recordingWIF) GetWorkloadIdentityPoolProvider(context.Context, string) (*WorkloadIdentityPoolProvider, error) {
	return &WorkloadIdentityPoolProvider{}, r.providerGetErr
}
func (r *recordingWIF) CreateWorkloadIdentityPoolProvider(context.Context, string, string, *WorkloadIdentityPoolProvider) (*WorkloadIdentityPoolProvider, error) {
	return nil, r.createProvErr
}
func (r *recordingWIF) DeleteWorkloadIdentityPoolProvider(context.Context, string) error { return nil }

// setupIAM covers the two policy calls Setup makes.
type setupIAM struct {
	IAMClient
	policy *IAMPolicy
}

func (s *setupIAM) GetIAMPolicy(context.Context, string) (*IAMPolicy, error) { return s.policy, nil }
func (s *setupIAM) SetIAMPolicy(context.Context, string, *IAMPolicy) error   { return nil }

func scopedSpec() *core.GCPWorkloadIdentityPoolSpec {
	return &core.GCPWorkloadIdentityPoolSpec{
		ProjectID:           "proj",
		ProjectNumber:       "123456789012",
		PoolID:              "prod-pool",
		ProviderID:          "gh",
		ProviderType:        "oidc",
		OIDCIssuerURL:       "https://token.actions.githubusercontent.com",
		ServiceAccountEmail: "deployer@proj.iam.gserviceaccount.com",
		AttributeCondition:  `assertion.repository == "myorg/myrepo"`,
		SubjectScope:        "repo:myorg/myrepo:ref:refs/heads/main",
	}
}

// A pool that already existed must survive a later failure.
func TestRollbackLeavesAPreexistingPool(t *testing.T) {
	wif := &recordingWIF{
		// The pool is visible, so this run does not create it.
		providerGetErr: errors.New("404 not found"),
		createProvErr:  errors.New("provider create failed"),
	}
	p := New(WithWorkloadIdentityClient(wif), WithIAMClient(&setupIAM{policy: &IAMPolicy{}}))

	_, err := p.Setup(context.Background(), scopedSpec(), core.SetupOptions{})
	if err == nil {
		t.Fatal("want the create failure to surface")
	}
	if len(wif.deletedPools) != 0 {
		t.Fatalf("deleted a pool this run did not create: %v", wif.deletedPools)
	}
	if !strings.Contains(err.Error(), "failed to create workload identity provider") {
		t.Errorf("unexpected error: %v", err)
	}
}

// A rollback that itself fails must say so.
func TestFailedRollbackReportsTheOrphan(t *testing.T) {
	notFound := errors.New("404 not found")
	wif := &recordingWIF{
		poolGetErr:     notFound,
		providerGetErr: notFound,
		createProvErr:  errors.New("provider create failed"),
		deleteErr:      errors.New("delete denied"),
	}
	p := New(WithWorkloadIdentityClient(wif), WithIAMClient(&setupIAM{policy: &IAMPolicy{}}))

	_, err := p.Setup(context.Background(), scopedSpec(), core.SetupOptions{})
	if err == nil {
		t.Fatal("want an error")
	}
	var rb *core.RollbackError
	if !errors.As(err, &rb) {
		t.Fatalf("want a RollbackError naming the orphan, got %T: %v", err, err)
	}
	if len(rb.OrphanedResources) != 1 {
		t.Errorf("orphaned resources = %v, want the pool it could not delete", rb.OrphanedResources)
	}
}

// The legitimate case: the probe says clearly that the pool was absent, this run created it, and then the provider create failed — so the pool it created is its to clean up.
func TestRollbackRemovesAPoolItDidCreate(t *testing.T) {
	notFound := errors.New("404 not found")
	wif := &recordingWIF{
		poolGetErr:     notFound,
		providerGetErr: notFound,
		createProvErr:  errors.New("provider create failed"),
	}
	p := New(WithWorkloadIdentityClient(wif), WithIAMClient(&setupIAM{policy: &IAMPolicy{}}))

	if _, err := p.Setup(context.Background(), scopedSpec(), core.SetupOptions{}); err == nil {
		t.Fatal("want the create failure to surface")
	}
	if len(wif.deletedPools) != 1 {
		t.Fatalf("a pool created by this run should be rolled back; deletions = %v", wif.deletedPools)
	}
}

// Success must not roll anything back.
func TestNoRollbackOnSuccess(t *testing.T) {
	notFound := errors.New("404 not found")
	wif := &recordingWIF{poolGetErr: notFound, providerGetErr: notFound}
	p := New(WithWorkloadIdentityClient(wif), WithIAMClient(&setupIAM{policy: &IAMPolicy{}}))

	if _, err := p.Setup(context.Background(), scopedSpec(), core.SetupOptions{}); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if len(wif.deletedPools) != 0 {
		t.Errorf("deleted a pool on the success path: %v", wif.deletedPools)
	}
}
