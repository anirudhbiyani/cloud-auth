package gcp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// `audit` covered one of the four clouds cloud-auth supports.

type listingWIF struct {
	WorkloadIdentityClient
	pools     []*WorkloadIdentityPool
	providers map[string][]*WorkloadIdentityPoolProvider
	poolsErr  error
	provErr   map[string]error
}

func (l *listingWIF) ListWorkloadIdentityPools(context.Context, string) ([]*WorkloadIdentityPool, error) {
	return l.pools, l.poolsErr
}

func (l *listingWIF) ListWorkloadIdentityPoolProviders(_ context.Context, parent string) ([]*WorkloadIdentityPoolProvider, error) {
	if err := l.provErr[parent]; err != nil {
		return nil, err
	}
	return l.providers[parent], nil
}

const testPool = "projects/my-project/locations/global/workloadIdentityPools/ci"

func TestGCPListTrustRecords(t *testing.T) {
	t.Setenv(inventoryProjectEnv, "my-project")

	wif := &listingWIF{
		pools: []*WorkloadIdentityPool{{Name: testPool, DisplayName: "ci", State: "ACTIVE"}},
		providers: map[string][]*WorkloadIdentityPoolProvider{
			testPool: {
				{
					Name: testPool + "/providers/github", DisplayName: "github", State: "ACTIVE",
					AttributeCondition: `assertion.sub == "repo:myorg/myrepo:ref:refs/heads/main"`,
					OIDC: &OIDCProviderConfig{
						IssuerURI:        "https://token.actions.githubusercontent.com",
						AllowedAudiences: []string{"https://github.com/myorg"},
					},
				},
				{
					// An aws-type provider trusts an ACCOUNT, verified by a SigV4 GetCallerIdentity call.
					Name: testPool + "/providers/aws", State: "ACTIVE",
					AttributeCondition: `assertion.account == "123456789012"`,
					AWS:                &AWSProviderConfig{AccountID: "123456789012"},
				},
			},
		},
	}

	records, err := New(WithWorkloadIdentityClient(wif)).ListTrustRecords(context.Background())
	if err != nil {
		t.Fatalf("ListTrustRecords: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2:\n%+v", len(records), records)
	}

	byResource := map[string]core.TrustRecord{}
	for _, r := range records {
		byResource[r.Resource] = r
	}

	gh := byResource[testPool+"/providers/github"]
	if gh.Issuer != "https://token.actions.githubusercontent.com" {
		t.Errorf("Issuer = %q", gh.Issuer)
	}
	if !strings.Contains(gh.SubjectCondition, "repo:myorg/myrepo") {
		t.Errorf("SubjectCondition = %q, want the subject out of the CEL condition", gh.SubjectCondition)
	}
	// CEL, not a made-up IAM operator: recording "StringEquals" would let the wildcard-under-exact-operator detector reason about an expression language it knows nothing about.
	if gh.Operator != "CEL" {
		t.Errorf("Operator = %q, want CEL", gh.Operator)
	}
	if gh.Name != "ci/github" {
		t.Errorf("Name = %q, want pool/provider", gh.Name)
	}

	aws := byResource[testPool+"/providers/aws"]
	if aws.Issuer != "aws:123456789012" {
		t.Errorf("aws-type provider Issuer = %q; it trusts an account, not an OIDC issuer", aws.Issuer)
	}
}

// A provider with no attribute condition admits every identity its issuer will mint.
func TestGCPMissingAttributeConditionScoresCritical(t *testing.T) {
	t.Setenv(inventoryProjectEnv, "my-project")

	wif := &listingWIF{
		pools: []*WorkloadIdentityPool{{Name: testPool, DisplayName: "ci"}},
		providers: map[string][]*WorkloadIdentityPoolProvider{
			testPool: {{
				Name: testPool + "/providers/wide",
				OIDC: &OIDCProviderConfig{IssuerURI: "https://token.actions.githubusercontent.com"},
			}},
		},
	}

	records, err := New(WithWorkloadIdentityClient(wif)).ListTrustRecords(context.Background())
	if err != nil {
		t.Fatalf("ListTrustRecords: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records", len(records))
	}
	if got := core.ScoreSubject(records[0].SubjectCondition).Breadth; got != core.BreadthCritical {
		t.Errorf("breadth = %s, want critical for a provider with no attribute condition", got)
	}
}

// GCP keeps a deleted pool listed for 30 days.
func TestGCPSkipsSoftDeletedPools(t *testing.T) {
	t.Setenv(inventoryProjectEnv, "my-project")

	wif := &listingWIF{
		pools: []*WorkloadIdentityPool{
			{Name: testPool, DisplayName: "ci", State: "ACTIVE"},
			{Name: testPool + "-old", DisplayName: "old", State: "DELETED"},
		},
		providers: map[string][]*WorkloadIdentityPoolProvider{
			testPool: {{Name: testPool + "/providers/p", State: "ACTIVE",
				AttributeCondition: `assertion.sub == "x"`}},
		},
	}
	// The soft-deleted pool must not even be asked for its providers.
	wif.provErr = map[string]error{
		testPool + "-old": errors.New("a deleted pool was enumerated"),
	}

	records, err := New(WithWorkloadIdentityClient(wif)).ListTrustRecords(context.Background())
	if err != nil {
		t.Fatalf("ListTrustRecords: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("got %d records, want 1 — a soft-deleted pool was inventoried", len(records))
	}
}

// One unreadable pool must not abort the project, and must be recorded as a gap rather than skipped: a pool nobody can read is missing information, not an absence of trust.
func TestGCPUnreadablePoolIsRecordedAsUnknown(t *testing.T) {
	t.Setenv(inventoryProjectEnv, "my-project")

	wif := &listingWIF{
		pools: []*WorkloadIdentityPool{
			{Name: testPool, DisplayName: "ci"},
			{Name: testPool + "-denied", DisplayName: "denied"},
		},
		providers: map[string][]*WorkloadIdentityPoolProvider{
			testPool: {{Name: testPool + "/providers/p", AttributeCondition: `assertion.sub == "x"`}},
		},
		provErr: map[string]error{testPool + "-denied": errors.New("permission denied")},
	}

	records, err := New(WithWorkloadIdentityClient(wif)).ListTrustRecords(context.Background())
	if err != nil {
		t.Fatalf("one unreadable pool aborted the whole project: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2 (one real, one gap)", len(records))
	}

	var gaps int
	for _, r := range records {
		if r.Liveness.State == core.NamespaceUnknown && strings.Contains(r.Liveness.Detail, "permission denied") {
			gaps++
		}
	}
	if gaps != 1 {
		t.Errorf("the unreadable pool was not recorded as a gap: %+v", records)
	}
}

// A pool is project-scoped and GCP has no tenant-wide listing, so there is no project to infer — saying which variable to set beats a confusing 404.
func TestGCPInventoryNeedsAProject(t *testing.T) {
	t.Setenv(inventoryProjectEnv, "")
	_, err := New(WithWorkloadIdentityClient(&listingWIF{})).ListTrustRecords(context.Background())
	if err == nil {
		t.Fatal("want an error with no project set")
	}
	if !strings.Contains(err.Error(), inventoryProjectEnv) {
		t.Errorf("the error does not name the variable to set: %v", err)
	}
}

func TestGCPInventoryCloud(t *testing.T) {
	if got := New().InventoryCloud(); got != core.GCP {
		t.Errorf("InventoryCloud() = %q", got)
	}
}
