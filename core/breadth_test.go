package core

import (
	"context"
	"strings"
	"testing"
)

// The behaviour this exists to fix: `--subject "repo:myorg/myrepo:*"` — the
// value the README told people to type — passed every gate with no warning,
// because isUnscoped correctly answers a narrower question and nothing answered
// the broader one.

func TestScoreSubject(t *testing.T) {
	for _, tc := range []struct {
		name      string
		subject   string
		want      Breadth
		admitsHas string
	}{
		// Critical: any tenant of the issuer.
		{"no subject at all", "", BreadthCritical, "no subject condition"},
		{"bare star", "*", BreadthCritical, "every workload"},
		{"double star", "**", BreadthCritical, "every workload"},
		{"question star", "?*", BreadthCritical, "every workload"},
		{"star colon star", "*:*", BreadthCritical, "every workload"},
		{"all segments wild", "*:*:*", BreadthCritical, "every workload"},
		{"repo colon star", "repo:*", BreadthCritical, "every repository of every organisation"},
		{"wildcard leading segment", "*:myorg/myrepo:ref:refs/heads/main", BreadthCritical, "any tenant"},

		// High: every repo in an org, every ServiceAccount in a cluster.
		{"every repo in an org", "repo:myorg/*", BreadthHigh, "organisation"},
		{"every repo in an org, ref pinned", "repo:myorg/*:ref:refs/heads/main", BreadthHigh, "organisation"},
		{"every SA everywhere", "system:serviceaccount:*:*", BreadthHigh, "every namespace"},
		{"every namespace, one name", "system:serviceaccount:*:deployer", BreadthHigh, "EVERY namespace"},
		{"one namespace, every SA", "system:serviceaccount:payments:*", BreadthHigh, "every ServiceAccount in that namespace"},

		// Medium: every ref/tag/event of one workload.
		{"trailing wildcard", "repo:myorg/myrepo:*", BreadthMedium, "pull_request"},

		// Info: an interior wildcard.
		{"interior wildcard", "repo:myorg/myrepo:ref:refs/heads/*", BreadthInfo, "interior wildcard"},

		// Exact.
		{"pinned branch", "repo:myorg/myrepo:ref:refs/heads/main", BreadthExact, "exactly one"},
		{"pinned environment", "repo:myorg/myrepo:environment:production", BreadthExact, "exactly one"},
		{"pinned service account", "system:serviceaccount:payments:ledger", BreadthExact, "exactly one"},
		{"immutable subject", "repo:myorg@1/myrepo@2:ref:refs/heads/main", BreadthExact, "exactly one"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ScoreSubject(tc.subject)
			if got.Breadth != tc.want {
				t.Errorf("ScoreSubject(%q) = %s, want %s\n  admits: %s",
					tc.subject, got.Breadth, tc.want, got.Admits)
			}
			if !strings.Contains(got.Admits, tc.admitsHas) {
				t.Errorf("admits = %q, want it to mention %q", got.Admits, tc.admitsHas)
			}
			if got.BreadthText != got.Breadth.String() {
				t.Errorf("BreadthText %q does not match Breadth %s", got.BreadthText, got.Breadth)
			}
			// Anything above exact must say what to do about it.
			if got.Breadth > BreadthExact && got.Advice == "" {
				t.Errorf("%s subject has no advice", got.Breadth)
			}
		})
	}
}

// The three patterns the PRD calls out by name as passing isUnscoped while
// admitting far more than an operator expects. This is the whole point.
func TestPatternsThatIsUnscopedCorrectlyCallsScoped(t *testing.T) {
	for _, tc := range []struct {
		subject string
		want    Breadth
	}{
		{"repo:myorg/myrepo:*", BreadthMedium},
		{"repo:*", BreadthCritical},
		{"system:serviceaccount:*:sa", BreadthHigh},
		{"repo:myorg/*", BreadthHigh},
	} {
		t.Run(tc.subject, func(t *testing.T) {
			// isUnscoped is right to say these pin real characters. The scorer
			// is answering a different question, and both answers stand.
			if isUnscoped(tc.subject) {
				t.Fatalf("isUnscoped(%q) = true; this test's premise is that it is false", tc.subject)
			}
			if got := ScoreSubject(tc.subject).Breadth; got != tc.want {
				t.Errorf("ScoreSubject(%q) = %s, want %s", tc.subject, got, tc.want)
			}
		})
	}
}

// The scorer must not disagree with isUnscoped where isUnscoped has an opinion:
// anything it calls unscoped is, by definition, maximally broad.
func TestScorerAgreesWithIsUnscoped(t *testing.T) {
	for _, s := range []string{"", "*", "**", "?*", "*:*", "*:*:*", "   ", "?:?"} {
		if !isUnscoped(s) {
			continue
		}
		if got := ScoreSubject(s).Breadth; got != BreadthCritical {
			t.Errorf("isUnscoped(%q) = true but ScoreSubject = %s, want critical", s, got)
		}
	}
}

// Only critical breadth demands a recorded reason. Making High require one too
// would put a prompt in front of a legitimately common org-wide pattern and
// train people to pass the override reflexively.
func TestOnlyCriticalNeedsJustification(t *testing.T) {
	for _, tc := range []struct {
		subject string
		want    bool
	}{
		{"", true},
		{"*", true},
		{"repo:*", true},
		{"repo:myorg/*", false},
		{"repo:myorg/myrepo:*", false},
		{"repo:myorg/myrepo:ref:refs/heads/main", false},
	} {
		if got := ScoreSubject(tc.subject).NeedsJustification(); got != tc.want {
			t.Errorf("ScoreSubject(%q).NeedsJustification() = %v, want %v", tc.subject, got, tc.want)
		}
	}
}

// Breadth ordering is compared with >= in the gates, so it has to be a real
// ordering — the same mistake Severity made with a string type.
func TestBreadthOrdering(t *testing.T) {
	if !(BreadthExact < BreadthInfo &&
		BreadthInfo < BreadthMedium &&
		BreadthMedium < BreadthHigh &&
		BreadthHigh < BreadthCritical) {
		t.Fatal("breadth constants are not strictly increasing")
	}
	for _, b := range []Breadth{BreadthExact, BreadthInfo, BreadthMedium, BreadthHigh, BreadthCritical} {
		if b.String() == "" {
			t.Errorf("breadth %d has no name", b)
		}
	}
}

// Scoring must not depend on surrounding whitespace, matching isUnscoped.
func TestScoreSubjectIgnoresSurroundingWhitespace(t *testing.T) {
	for _, s := range []string{"repo:myorg/myrepo:*", "repo:myorg/*", "*", "repo:o/r:ref:refs/heads/main"} {
		bare := ScoreSubject(s).Breadth
		padded := ScoreSubject("  " + s + "  ").Breadth
		if bare != padded {
			t.Errorf("ScoreSubject(%q) = %s but padded = %s", s, bare, padded)
		}
	}
}

func FuzzScoreSubject(f *testing.F) {
	for _, s := range []string{
		"", "*", "repo:*", "repo:org/*", "repo:org/repo:*",
		"system:serviceaccount:*:*", "repo:o/r:ref:refs/heads/main", ":::", "?",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, subject string) {
		got := ScoreSubject(subject)

		// Never panics, always names its score, and always says what it admits.
		if got.BreadthText == "" || got.Admits == "" {
			t.Fatalf("ScoreSubject(%q) produced an incomplete assessment: %+v", subject, got)
		}
		// A subject with no wildcard that pins something is exact: there is
		// nothing in it for a pattern operator to expand.
		//
		// The isUnscoped guard is not redundant. The fuzzer found ":::" — no
		// wildcard, and it still pins nothing, because every segment is empty.
		// "contains no wildcard" and "constrains something" are different
		// properties and this invariant needs both.
		if !strings.ContainsAny(subject, "*?") && !isUnscoped(subject) {
			if got.Breadth > BreadthExact {
				t.Fatalf("ScoreSubject(%q) = %s, but it pins characters and has no wildcard",
					subject, got.Breadth)
			}
		}
		// Whatever isUnscoped calls unscoped is maximally broad, or the two
		// have drifted apart.
		if isUnscoped(subject) && got.Breadth != BreadthCritical {
			t.Fatalf("isUnscoped(%q) = true but ScoreSubject = %s", subject, got.Breadth)
		}
	})
}

// fakeTrust supplies a trust policy for the validator.
type fakeTrust struct {
	policy *TrustPolicy
	err    error
}

func (f fakeTrust) TrustPolicy(context.Context, MechanismRef) (*TrustPolicy, error) {
	return f.policy, f.err
}

// The grading has to reach the report, and — critically — a medium-breadth
// subject must be REPORTED without invalidating it. Failing every deployment
// that uses repo:org/repo:* on a matter of degree would train people to ignore
// this check entirely.
func TestSubjectBreadthValidatorGrades(t *testing.T) {
	for _, tc := range []struct {
		name         string
		subjects     []string
		wantStatus   CheckStatus
		wantSeverity Severity
		invalidates  bool
	}{
		{"exact", []string{"repo:o/r:ref:refs/heads/main"}, CheckStatusPassed, SeverityWarning, false},
		{"medium", []string{"repo:o/r:*"}, CheckStatusFailed, SeverityWarning, false},
		{"high", []string{"repo:o/*"}, CheckStatusFailed, SeverityError, true},
		{"critical", []string{"repo:*"}, CheckStatusFailed, SeverityCritical, true},
		{"no condition at all", nil, CheckStatusFailed, SeverityCritical, true},
		{"the worst of several wins", []string{"repo:o/r:ref:refs/heads/main", "repo:o/*"},
			CheckStatusFailed, SeverityError, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := NewSubjectBreadthValidator(fakeTrust{policy: &TrustPolicy{Subjects: tc.subjects}})
			check := v.Validate(context.Background(), MechanismRef{ID: "r"})

			if check.Status != tc.wantStatus {
				t.Errorf("status = %s, want %s (%s)", check.Status, tc.wantStatus, check.Message)
			}
			if check.Severity != tc.wantSeverity {
				t.Errorf("severity = %s, want %s", check.Severity, tc.wantSeverity)
			}

			report := &ValidationReport{Checks: []ValidationCheck{check}}
			if got := !report.IsValid(); got != tc.invalidates {
				t.Errorf("invalidates the report = %v, want %v — breadth is a spectrum, and "+
					"turning a matter of degree into a red build trains people to ignore it",
					got, tc.invalidates)
			}
		})
	}
}

// A trust policy that could not be read is skipped, never passed.
func TestSubjectBreadthValidatorSkipsWhenItCannotRead(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source TrustPolicySource
	}{
		{"no source configured", nil},
		{"the read failed", fakeTrust{err: errRead{}}},
		{"the policy came back nil", fakeTrust{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := NewSubjectBreadthValidator(tc.source)
			check := v.Validate(context.Background(), MechanismRef{ID: "r"})
			if check.Status != CheckStatusSkipped {
				t.Errorf("status = %s, want skipped", check.Status)
			}
			if !strings.Contains(check.Message, "NOT scored") {
				t.Errorf("a skip must say plainly that nothing was checked: %q", check.Message)
			}
			if check.Remediation == "" {
				t.Error("a skipped check must say what to verify by hand")
			}
		})
	}
}

type errRead struct{}

func (errRead) Error() string { return "no credentials" }
