package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

func rec(resource, subject string, breadth core.Breadth, state core.NamespaceState) core.TrustRecord {
	return core.TrustRecord{
		Cloud: core.AWS, Resource: resource, Name: resource,
		Issuer: "https://token.actions.githubusercontent.com", SubjectCondition: subject,
		Breadth:  core.BreadthAssessment{Breadth: breadth, BreadthText: breadth.String()},
		Liveness: core.LivenessResult{State: state},
	}
}

// Worst first, so the row that needs acting on is the first one read — and
// stable within a severity, so two runs diff cleanly.
func TestAuditOrdersWorstFirst(t *testing.T) {
	records := []core.TrustRecord{
		rec("arn:aws:iam::1:role/fine", "repo:o/r:ref:refs/heads/main", core.BreadthExact, core.NamespaceLive),
		rec("arn:aws:iam::1:role/claimable", "repo:gone/x:ref:refs/heads/main", core.BreadthExact, core.NamespaceUnregistered),
		rec("arn:aws:iam::1:role/broad", "repo:o/*", core.BreadthHigh, core.NamespaceLive),
	}
	sortRecords(records)

	if records[0].Name != "arn:aws:iam::1:role/claimable" {
		t.Errorf("first record is %q; an unregistered namespace is claimable right now and "+
			"must sort above everything", records[0].Name)
	}
	if records[len(records)-1].Name != "arn:aws:iam::1:role/fine" {
		t.Errorf("last record is %q, want the clean one", records[len(records)-1].Name)
	}

	// Stable across repeats.
	first := records[0].Resource
	for range 10 {
		sortRecords(records)
		if records[0].Resource != first {
			t.Fatal("sort order is not stable between runs")
		}
	}
}

// An inventory missing a cloud is not an inventory. The warning goes FIRST,
// because a reader who stops at the table would otherwise conclude those clouds
// were clean.
func TestAuditTableLeadsWithIncompleteness(t *testing.T) {
	var sb strings.Builder
	writeAuditTable(&sb, []core.TrustRecord{
		rec("arn:aws:iam::1:role/r", "repo:o/r:ref:refs/heads/main", core.BreadthExact, core.NamespaceLive),
	}, []error{errors.New("gcp: no credentials")})

	out := sb.String()
	if !strings.HasPrefix(out, "⚠ INCOMPLETE") {
		t.Errorf("the incompleteness warning is not first:\n%s", out)
	}
	if !strings.Contains(out, "nothing below\n  says anything about them") {
		t.Errorf("the warning does not say what it means:\n%s", out)
	}
}

// A critical row gets its detail spelled out: a table cell cannot carry
// "anyone can register this name and assume this role right now".
func TestAuditTableExplainsCriticalRows(t *testing.T) {
	r := rec("arn:aws:iam::1:role/claimable", "repo:gone/x:ref:refs/heads/main",
		core.BreadthExact, core.NamespaceUnregistered)
	r.Liveness.Detail = "this namespace does not exist on GitHub: anyone can register it"

	var sb strings.Builder
	writeAuditTable(&sb, []core.TrustRecord{r}, nil)
	out := sb.String()

	if !strings.Contains(out, "anyone can register it") {
		t.Errorf("the critical detail was not printed:\n%s", out)
	}
	if !strings.Contains(out, "role/claimable") {
		t.Errorf("the resource was not named:\n%s", out)
	}
}

func TestAuditJSONIsValidAndCounts(t *testing.T) {
	var sb strings.Builder
	err := writeAuditJSON(&sb, []core.TrustRecord{
		rec("arn:aws:iam::1:role/a", "repo:gone/x:ref:refs/heads/main", core.BreadthExact, core.NamespaceUnregistered),
		rec("arn:aws:iam::1:role/b", "repo:o/*", core.BreadthHigh, core.NamespaceLive),
		rec("arn:aws:iam::1:role/c", "repo:o/r:ref:refs/heads/main", core.BreadthExact, core.NamespaceLive),
	}, []error{errors.New("gcp: no credentials")})
	if err != nil {
		t.Fatalf("writeAuditJSON: %v", err)
	}

	var report auditReport
	if err := json.Unmarshal([]byte(sb.String()), &report); err != nil {
		t.Fatalf("output is not valid JSON (%v):\n%s", err, sb.String())
	}
	if report.Summary.Total != 3 || report.Summary.Critical != 1 || report.Summary.Warning != 1 {
		t.Errorf("summary = %+v", report.Summary)
	}
	if !report.Incomplete || len(report.Failures) != 1 {
		t.Errorf("a failed source must mark the report incomplete: %+v", report)
	}
}

// Empty renders as [] rather than null, so a consumer need not special-case it.
func TestAuditJSONEmptyIsAnArray(t *testing.T) {
	var sb strings.Builder
	if err := writeAuditJSON(&sb, nil, nil); err != nil {
		t.Fatalf("writeAuditJSON: %v", err)
	}
	if !strings.Contains(sb.String(), `"records": []`) {
		t.Errorf("empty records should render as []:\n%s", sb.String())
	}
}

func TestAuditExit(t *testing.T) {
	claimable := rec("arn:aws:iam::1:role/a", "repo:gone/x:ref:refs/heads/main",
		core.BreadthExact, core.NamespaceUnregistered)
	broad := rec("arn:aws:iam::1:role/b", "repo:o/*", core.BreadthHigh, core.NamespaceLive)
	clean := rec("arn:aws:iam::1:role/c", "repo:o/r:ref:refs/heads/main",
		core.BreadthExact, core.NamespaceLive)

	for _, tc := range []struct {
		name     string
		records  []core.TrustRecord
		failures []error
		failOn   string
		wantErr  bool
	}{
		{"no gate configured", []core.TrustRecord{claimable}, nil, "", false},
		{"critical gate, critical present", []core.TrustRecord{claimable}, nil, "critical", true},
		{"critical gate, only a warning", []core.TrustRecord{broad}, nil, "critical", false},
		{"warning gate catches the warning", []core.TrustRecord{broad}, nil, "warning", true},
		{"clean inventory passes", []core.TrustRecord{clean}, nil, "critical", false},
		{"an unknown threshold is an error", []core.TrustRecord{clean}, nil, "nonsense", true},
		{
			// A green gate over a cloud that was never read is worse than no
			// gate: the unread cloud is exactly where an unseen finding is.
			name:    "clean but incomplete does not pass the gate",
			records: []core.TrustRecord{clean}, failures: []error{errors.New("gcp: no credentials")},
			failOn: "critical", wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := auditExit(tc.records, tc.failures, tc.failOn)
			if (err != nil) != tc.wantErr {
				t.Fatalf("auditExit = %v, want error: %v", err, tc.wantErr)
			}
			if err == nil {
				return
			}
			// A gate failure must be a validation failure, so main maps it to
			// the exit code that means "misconfigured", not "the run broke".
			var vf validationFailure
			if tc.failOn != "nonsense" && !errors.As(err, &vf) {
				t.Errorf("gate failure is not a validationFailure: %T", err)
			}
		})
	}
}

// The rename-fragile summary is the query nothing else answers: the trust works
// until somebody renames a repo, and that change looks nothing like an auth
// change.
func TestAuditTableSummarisesRenameFragility(t *testing.T) {
	r := rec("arn:aws:iam::1:role/legacy", "repo:o/r:ref:refs/heads/main",
		core.BreadthExact, core.NamespaceLive)
	r.RenameFragile = true

	var sb strings.Builder
	writeAuditTable(&sb, []core.TrustRecord{r}, nil)
	if !strings.Contains(sb.String(), "renamed or transferred") {
		t.Errorf("rename fragility was not summarised:\n%s", sb.String())
	}
}

func TestShortResource(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"arn:aws:iam::123456789012:role/deploy", "role/deploy"},
		{"arn:aws:iam::123456789012:role/team/deploy", "role/team/deploy"},
		{"short", "short"},
	} {
		if got := shortResource(tc.in); got != tc.want {
			t.Errorf("shortResource(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
