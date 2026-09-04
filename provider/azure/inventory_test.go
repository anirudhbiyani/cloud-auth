package azure

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// Published telemetry put 24% of GitHub namespaces referenced in Azure trust
// configuration at unregistered and claimable — a higher rate than AWS, and
// none of it created by cloud-auth. So the tenant is what gets enumerated, not
// the state file.

type listingGraph struct {
	GraphClient
	apps    []*Application
	creds   map[string][]*FederatedIdentityCredential
	appsErr error
	credErr map[string]error
}

func (l *listingGraph) ListApplications(context.Context) ([]*Application, error) {
	return l.apps, l.appsErr
}

func (l *listingGraph) ListFederatedIdentityCredentials(_ context.Context, appID string) ([]*FederatedIdentityCredential, error) {
	if err := l.credErr[appID]; err != nil {
		return nil, err
	}
	return l.creds[appID], nil
}

func TestAzureListTrustRecords(t *testing.T) {
	graph := &listingGraph{
		apps: []*Application{
			{ID: "app-1", AppID: "aaaa", DisplayName: "deploy"},
			{ID: "app-2", AppID: "bbbb", DisplayName: "unused"},
		},
		creds: map[string][]*FederatedIdentityCredential{
			"app-1": {{
				ID: "cred-1", Name: "github-main",
				Issuer:    "https://token.actions.githubusercontent.com",
				Subject:   "repo:myorg/myrepo:ref:refs/heads/main",
				Audiences: []string{core.DefaultAzureAudience},
			}},
			// An application with no federated credentials is not a trust
			// relationship and must not appear.
			"app-2": {},
		},
	}

	records, err := New(WithGraphClient(graph)).ListTrustRecords(context.Background())
	if err != nil {
		t.Fatalf("ListTrustRecords: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1 (only the app with a credential):\n%+v", len(records), records)
	}

	r := records[0]
	if r.Cloud != core.Azure {
		t.Errorf("Cloud = %q", r.Cloud)
	}
	if r.SubjectCondition != "repo:myorg/myrepo:ref:refs/heads/main" {
		t.Errorf("SubjectCondition = %q", r.SubjectCondition)
	}
	// Azure has no condition operator: subjects are compared literally, always.
	// Recording that explicitly matters because the breadth scorer and the
	// wildcard detector both read the operator, and an absent one would read as
	// "unknown" rather than "exact by construction".
	if r.Operator != "StringEquals" {
		t.Errorf("Operator = %q, want StringEquals — Azure matches subjects literally", r.Operator)
	}
	if !strings.Contains(r.Resource, "federatedIdentityCredentials/github-main") {
		t.Errorf("Resource = %q, want it to address the credential", r.Resource)
	}
	if r.Name != "deploy/github-main" {
		t.Errorf("Name = %q, want app/credential", r.Name)
	}
	// A legacy GitHub subject on Azure is rename-fragile just as on AWS.
	if !core.IsRenameFragile(r.Issuer, r.SubjectCondition) {
		t.Error("a legacy GitHub subject should be flagged rename-fragile")
	}
}

// One unreadable application must not abort the tenant — a single app the
// caller cannot read would otherwise hide every other finding — and it is
// recorded as a gap rather than skipped.
func TestAzureUnreadableApplicationIsRecordedAsUnknown(t *testing.T) {
	graph := &listingGraph{
		apps: []*Application{
			{ID: "app-1", DisplayName: "readable"},
			{ID: "app-2", DisplayName: "denied"},
		},
		creds: map[string][]*FederatedIdentityCredential{
			"app-1": {{Name: "c", Issuer: "https://issuer.example.com", Subject: "sub"}},
		},
		credErr: map[string]error{"app-2": errors.New("Authorization_RequestDenied")},
	}

	records, err := New(WithGraphClient(graph)).ListTrustRecords(context.Background())
	if err != nil {
		t.Fatalf("one unreadable application aborted the tenant: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2 (one real, one gap)", len(records))
	}

	var gaps int
	for _, r := range records {
		if r.Liveness.State == core.NamespaceUnknown &&
			strings.Contains(r.Liveness.Detail, "Authorization_RequestDenied") {
			gaps++
		}
	}
	if gaps != 1 {
		t.Errorf("the unreadable application was not recorded as a gap: %+v", records)
	}
}

// A failure listing applications at all is a real error: unlike one bad app, it
// means nothing about the tenant was seen, and returning an empty inventory
// would read as "no federated trust".
func TestAzureListApplicationsFailureIsAnError(t *testing.T) {
	graph := &listingGraph{appsErr: errors.New("Graph unavailable")}
	if _, err := New(WithGraphClient(graph)).ListTrustRecords(context.Background()); err == nil {
		t.Fatal("a total listing failure was reported as an empty inventory")
	}
}

func TestAzureInventoryCloud(t *testing.T) {
	if got := New().InventoryCloud(); got != core.Azure {
		t.Errorf("InventoryCloud() = %q", got)
	}
}
