package core

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// The check no mainstream scanner makes: shared issuers run ONE issuer across
// every tenant and permit namespace reuse, so a deleted org can be re-registered
// by anyone, who then mints a token with an identical sub and assumes a role
// that is still sitting there.

func TestNamespaceFromSubject(t *testing.T) {
	for _, tc := range []struct {
		name    string
		subject string
		want    string
		wantOK  bool
	}{
		{"GitHub Actions", "repo:myorg/myrepo:ref:refs/heads/main", "myorg/myrepo", true},
		{"GitHub immutable", "repo:myorg@1/myrepo@2:ref:refs/heads/main", "myorg@1/myrepo@2", true},
		{"GitLab CI", "project_path:mygroup/myproject:ref_type:branch:ref:main", "mygroup/myproject", true},
		{"Terraform Cloud", "organization:myorg:project:prod:workspace:app:run_phase:apply", "myorg", true},
		{"Kubernetes", "system:serviceaccount:payments:ledger", "payments", true},

		// A wildcard namespace is unbounded, not unregistered. Reporting one as
		// claimable would be wrong, and the breadth score already covers it.
		{"wildcard org", "repo:*", "", false},
		{"wildcard repo", "repo:myorg/*", "", false},
		{"wildcard namespace", "system:serviceaccount:*:ledger", "", false},

		{"unrecognised shape", "some:other:subject", "", false},
		{"empty", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := NamespaceFromSubject(tc.subject)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (got %q)", ok, tc.wantOK, got)
			}
			if got != tc.want {
				t.Errorf("namespace = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIsSharedIssuer(t *testing.T) {
	for _, tc := range []struct {
		issuer string
		want   bool
	}{
		{"https://token.actions.githubusercontent.com", true},
		{"token.actions.githubusercontent.com", true},
		{"https://gitlab.com", true},
		{"https://app.terraform.io", true},
		// A cluster's own issuer serves one tenant: its namespaces cannot be
		// re-registered by a stranger.
		{"https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLE", false},
		{"https://gitlab.example.com", false},
		{"", false},
	} {
		if got := IsSharedIssuer(tc.issuer); got != tc.want {
			t.Errorf("IsSharedIssuer(%q) = %v, want %v", tc.issuer, got, tc.want)
		}
	}
}

// fakeResolver answers without a network.
type fakeResolver struct {
	issuer string
	states map[string]NamespaceState
	err    error
}

func (f fakeResolver) Issuer() string { return f.issuer }
func (f fakeResolver) Resolve(_ context.Context, ns string) (NamespaceState, string, error) {
	if f.err != nil {
		return NamespaceUnknown, "", f.err
	}
	if s, ok := f.states[ns]; ok {
		return s, "", nil
	}
	return NamespaceUnregistered, "", nil
}

func TestResolveLiveness(t *testing.T) {
	const gh = "https://token.actions.githubusercontent.com"
	resolvers := []NamespaceResolver{fakeResolver{
		issuer: gh,
		states: map[string]NamespaceState{
			"myorg/myrepo":     NamespaceLive,
			"someoneelse/repo": NamespaceNotOurs,
		},
	}}

	for _, tc := range []struct {
		name      string
		issuer    string
		subject   string
		wantState NamespaceState
		detailHas string
	}{
		{"live and ours", gh, "repo:myorg/myrepo:ref:refs/heads/main", NamespaceLive, ""},
		{"live but somebody else's", gh, "repo:someoneelse/repo:ref:refs/heads/main", NamespaceNotOurs, ""},
		{"unregistered and claimable", gh, "repo:deletedorg/gone:ref:refs/heads/main", NamespaceUnregistered, ""},
		{
			name: "a single-tenant issuer cannot be re-registered", issuer: "https://oidc.eks.us-west-2.amazonaws.com/id/X",
			subject: "system:serviceaccount:payments:ledger", wantState: NamespaceUnknown,
			detailHas: "not a shared issuer",
		},
		{
			name: "a wildcard namespace has nothing to resolve", issuer: gh,
			subject: "repo:myorg/*", wantState: NamespaceUnknown, detailHas: "no concrete namespace",
		},
		{
			name: "no resolver for this issuer", issuer: "https://gitlab.com",
			subject: "project_path:g/p:ref:main", wantState: NamespaceUnknown, detailHas: "no resolver",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveLiveness(context.Background(), tc.issuer, tc.subject, resolvers)
			if got.State != tc.wantState {
				t.Errorf("state = %q, want %q (detail: %s)", got.State, tc.wantState, got.Detail)
			}
			if tc.detailHas != "" && !strings.Contains(got.Detail, tc.detailHas) {
				t.Errorf("detail = %q, want it to mention %q", got.Detail, tc.detailHas)
			}
		})
	}
}

// "We could not tell" and "it is safe" are different answers, and conflating
// them is the same mistake as reporting a skipped check as passed.
func TestResolverFailureIsUnknownNotClean(t *testing.T) {
	got := ResolveLiveness(context.Background(),
		"https://token.actions.githubusercontent.com",
		"repo:myorg/myrepo:ref:refs/heads/main",
		[]NamespaceResolver{fakeResolver{
			issuer: "https://token.actions.githubusercontent.com",
			err:    errors.New("rate limited"),
		}})

	if got.State != NamespaceUnknown {
		t.Errorf("state = %q, want unknown", got.State)
	}
	if !strings.Contains(got.Detail, "rate limited") {
		t.Errorf("the cause was lost: %q", got.Detail)
	}
}

// The immutable-subject enforcement applies to any renamed OR transferred
// repository, which makes a legacy subject a scheduled outage nobody scheduled.
func TestIsRenameFragile(t *testing.T) {
	const gh = "https://token.actions.githubusercontent.com"
	for _, tc := range []struct {
		name    string
		issuer  string
		subject string
		want    bool
	}{
		{"legacy GitHub subject", gh, "repo:myorg/myrepo:ref:refs/heads/main", true},
		{"immutable GitHub subject", gh, "repo:myorg@1/myrepo@2:ref:refs/heads/main", false},
		{"wildcard survives a rename by construction", gh, "repo:myorg/*", false},
		{"not GitHub", "https://gitlab.com", "project_path:g/p:ref:main", false},
		{"not a repo subject", gh, "system:serviceaccount:ns:sa", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsRenameFragile(tc.issuer, tc.subject); got != tc.want {
				t.Errorf("IsRenameFragile(%q, %q) = %v, want %v", tc.issuer, tc.subject, got, tc.want)
			}
		})
	}
}

// fakeSource enumerates fixed records.
type fakeSource struct {
	cloud   Cloud
	records []TrustRecord
	err     error
}

func (f fakeSource) InventoryCloud() Cloud { return f.cloud }
func (f fakeSource) ListTrustRecords(context.Context) ([]TrustRecord, error) {
	return f.records, f.err
}

func TestBuildInventoryScoresAndResolves(t *testing.T) {
	const gh = "https://token.actions.githubusercontent.com"
	sources := []InventorySource{
		fakeSource{cloud: AWS, records: []TrustRecord{
			{Cloud: AWS, Resource: "arn:aws:iam::1:role/live", Issuer: gh,
				SubjectCondition: "repo:myorg/myrepo:ref:refs/heads/main"},
			{Cloud: AWS, Resource: "arn:aws:iam::1:role/dead", Issuer: gh,
				SubjectCondition: "repo:deletedorg/gone:ref:refs/heads/main"},
			{Cloud: AWS, Resource: "arn:aws:iam::1:role/wide", Issuer: gh,
				SubjectCondition: "repo:myorg/*"},
		}},
	}
	resolvers := []NamespaceResolver{fakeResolver{
		issuer: gh, states: map[string]NamespaceState{"myorg/myrepo": NamespaceLive},
	}}

	records, failures := BuildInventory(context.Background(), sources, resolvers)
	if len(failures) != 0 {
		t.Fatalf("unexpected failures: %v", failures)
	}
	if len(records) != 3 {
		t.Fatalf("got %d records, want 3", len(records))
	}

	byName := map[string]TrustRecord{}
	for _, r := range records {
		byName[r.Resource] = r
	}

	live := byName["arn:aws:iam::1:role/live"]
	if live.Liveness.State != NamespaceLive {
		t.Errorf("live role: state = %q", live.Liveness.State)
	}
	if !live.RenameFragile {
		t.Error("a legacy GitHub subject should be flagged rename-fragile")
	}
	if live.Severity() != FindingWarning {
		t.Errorf("rename-fragile alone is a warning, got %v", live.Severity())
	}

	dead := byName["arn:aws:iam::1:role/dead"]
	if dead.Liveness.State != NamespaceUnregistered {
		t.Errorf("dead role: state = %q, want unregistered", dead.Liveness.State)
	}
	if dead.Severity() != FindingCritical {
		t.Errorf("an unregistered namespace is claimable right now; severity = %v", dead.Severity())
	}

	wide := byName["arn:aws:iam::1:role/wide"]
	if wide.Breadth.Breadth != BreadthHigh {
		t.Errorf("org-wide subject: breadth = %s, want high", wide.Breadth.Breadth)
	}
	// A wildcard namespace is unbounded, not claimable — those are different
	// problems and only one of them is a land grab.
	if wide.Liveness.State != NamespaceUnknown {
		t.Errorf("wildcard namespace: state = %q, want unknown", wide.Liveness.State)
	}
}

// A missing GCP credential must not hide the AWS findings.
func TestBuildInventoryContinuesPastAFailingSource(t *testing.T) {
	const gh = "https://token.actions.githubusercontent.com"
	records, failures := BuildInventory(context.Background(), []InventorySource{
		fakeSource{cloud: GCP, err: errors.New("no credentials")},
		fakeSource{cloud: AWS, records: []TrustRecord{
			{Cloud: AWS, Resource: "arn:aws:iam::1:role/r", Issuer: gh,
				SubjectCondition: "repo:myorg/myrepo:ref:refs/heads/main"},
		}},
	}, nil)

	if len(records) != 1 {
		t.Errorf("got %d records; a failing source hid the others", len(records))
	}
	if len(failures) != 1 {
		t.Fatalf("got %d failures, want 1", len(failures))
	}
	// The failure has to name the cloud, or an incomplete inventory reads as a
	// complete one with less in it.
	if !strings.Contains(failures[0].Error(), "gcp") {
		t.Errorf("the failure does not name the cloud: %v", failures[0])
	}
}

func TestRecordSeverity(t *testing.T) {
	for _, tc := range []struct {
		name string
		rec  TrustRecord
		want FindingSeverity
	}{
		{"unregistered namespace", TrustRecord{
			Liveness: LivenessResult{State: NamespaceUnregistered}}, FindingCritical},
		{"somebody else's namespace", TrustRecord{
			Liveness: LivenessResult{State: NamespaceNotOurs}}, FindingCritical},
		{"critical breadth", TrustRecord{
			Breadth:  BreadthAssessment{Breadth: BreadthCritical},
			Liveness: LivenessResult{State: NamespaceLive}}, FindingCritical},
		{"high breadth", TrustRecord{
			Breadth:  BreadthAssessment{Breadth: BreadthHigh},
			Liveness: LivenessResult{State: NamespaceLive}}, FindingWarning},
		{"rename fragile only", TrustRecord{
			RenameFragile: true,
			Liveness:      LivenessResult{State: NamespaceLive}}, FindingWarning},
		{"nothing wrong", TrustRecord{
			Liveness: LivenessResult{State: NamespaceLive}}, FindingInfo},
		// Unknown liveness is not critical on its own — it is the absence of an
		// answer, and treating every unresolvable namespace as an emergency
		// would bury the ones that are.
		{"unknown liveness", TrustRecord{
			Liveness: LivenessResult{State: NamespaceUnknown}}, FindingInfo},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rec.Severity(); got != tc.want {
				t.Errorf("severity = %v, want %v", got, tc.want)
			}
		})
	}
}
