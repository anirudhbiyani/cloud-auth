package core

import (
	"strings"
	"testing"
)

// One AWS AccessDenied covers roughly fifteen root causes. These are the seven
// worth naming, tested against fixtures with no cloud — which is exactly what
// keeping the detectors pure buys.

// trust builds a policy with one subject condition.
func trust(operator, subject string) *TrustPolicy {
	return &TrustPolicy{
		Issuer:     "https://token.actions.githubusercontent.com",
		Subjects:   []string{subject},
		Conditions: []TrustCondition{{Operator: operator, Claim: "sub", Value: subject}},
	}
}

// token builds a source proof.
func token(subject string) *SourceToken {
	return &SourceToken{
		Kind:     OIDC,
		Issuer:   "https://token.actions.githubusercontent.com",
		Subject:  subject,
		Audience: "sts.amazonaws.com",
	}
}

// findingFor returns the finding from the named detector, or fails.
func findingFor(t *testing.T, findings []Finding, detector string) Finding {
	t.Helper()
	for _, f := range findings {
		if f.Detector == detector {
			return f
		}
	}
	var names []string
	for _, f := range findings {
		names = append(names, f.Detector)
	}
	t.Fatalf("no finding from %q; got %v", detector, names)
	return Finding{}
}

// noFindingFrom asserts a detector stayed quiet.
func noFindingFrom(t *testing.T, findings []Finding, detector string) {
	t.Helper()
	for _, f := range findings {
		if f.Detector == detector {
			t.Errorf("%s fired when it should not have: %s", detector, f.Summary)
		}
	}
}

// GitHub enforced immutable subject claims on 15 July 2026 for new repositories
// and for any repository renamed or transferred. Nothing in the workflow
// changes; the deploy just starts failing.
func TestImmutableSubjectMismatch(t *testing.T) {
	const legacy = "repo:myorg/myrepo:ref:refs/heads/main"
	const immutable = "repo:myorg@123456/myrepo@456789:ref:refs/heads/main"

	t.Run("policy is legacy, token is immutable", func(t *testing.T) {
		f := findingFor(t, Explain(ExplainInput{
			Trust: trust("StringEquals", legacy), Token: token(immutable),
		}), "github-immutable-subject")

		if f.Severity != FindingCritical {
			t.Errorf("severity = %v, want critical", f.Severity)
		}
		if f.Presented != immutable || f.Configured != legacy {
			t.Errorf("diff = presented %q / configured %q", f.Presented, f.Configured)
		}
		// The fix must carry the corrected value, not just describe the problem.
		if !strings.Contains(f.Fix, immutable) {
			t.Errorf("fix does not name the corrected subject: %s", f.Fix)
		}
	})

	t.Run("policy is immutable, token is legacy", func(t *testing.T) {
		f := findingFor(t, Explain(ExplainInput{
			Trust: trust("StringEquals", immutable), Token: token(legacy),
		}), "github-immutable-subject")
		if f.Presented != legacy {
			t.Errorf("Presented = %q", f.Presented)
		}
	})

	t.Run("both immutable is fine", func(t *testing.T) {
		noFindingFrom(t, Explain(ExplainInput{
			Trust: trust("StringEquals", immutable), Token: token(immutable),
		}), "github-immutable-subject")
	})

	t.Run("both legacy is fine", func(t *testing.T) {
		noFindingFrom(t, Explain(ExplainInput{
			Trust: trust("StringEquals", legacy), Token: token(legacy),
		}), "github-immutable-subject")
	})

	t.Run("a non-GitHub subject is not our business", func(t *testing.T) {
		noFindingFrom(t, Explain(ExplainInput{
			Trust: trust("StringEquals", "system:serviceaccount:ns:sa"),
			Token: token("system:serviceaccount:ns:sa"),
		}), "github-immutable-subject")
	})
}

// GitHub's sub is a positional concatenation: adding an environment REPLACES
// the ref segment. Nothing in the workflow diff looks related to auth.
func TestEnvironmentOverridesBranch(t *testing.T) {
	const pinnedToRef = "repo:myorg/myrepo:ref:refs/heads/main"
	const presentsEnv = "repo:myorg/myrepo:environment:production"

	f := findingFor(t, Explain(ExplainInput{
		Trust: trust("StringEquals", pinnedToRef), Token: token(presentsEnv),
	}), "github-environment-overrides-ref")

	if f.Severity != FindingCritical {
		t.Errorf("severity = %v, want critical", f.Severity)
	}
	if !strings.Contains(f.Summary, "environment") {
		t.Errorf("summary does not explain the mechanism: %s", f.Summary)
	}

	t.Run("the reverse direction", func(t *testing.T) {
		findingFor(t, Explain(ExplainInput{
			Trust: trust("StringEquals", presentsEnv), Token: token(pinnedToRef),
		}), "github-environment-overrides-ref")
	})

	t.Run("matching pair is fine", func(t *testing.T) {
		noFindingFrom(t, Explain(ExplainInput{
			Trust: trust("StringEquals", presentsEnv), Token: token(presentsEnv),
		}), "github-environment-overrides-ref")
	})
}

// A "*" under StringEquals is matched literally: the trust is not too wide, it
// is silently dead, and the AccessDenied looks identical to a wrong subject.
func TestWildcardUnderExactOperator(t *testing.T) {
	for _, tc := range []struct {
		name     string
		operator string
		subject  string
		wantFire bool
	}{
		{"StringEquals with a wildcard", "StringEquals", "repo:myorg/myrepo:*", true},
		{"StringEquals with a question mark", "StringEquals", "repo:myorg/myrepo:ref?", true},
		{"ForAllValues:StringEquals with a wildcard", "ForAllValues:StringEquals", "repo:myorg/*", true},
		{"StringLike with a wildcard is intended", "StringLike", "repo:myorg/myrepo:*", false},
		{"ForAnyValue:StringLike is intended", "ForAnyValue:StringLike", "repo:myorg/*", false},
		{"StringEquals without a wildcard", "StringEquals", "repo:myorg/myrepo:ref:refs/heads/main", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings := Explain(ExplainInput{
				Trust: trust(tc.operator, tc.subject),
				Token: token("repo:myorg/myrepo:ref:refs/heads/main"),
			})
			if tc.wantFire {
				f := findingFor(t, findings, "wildcard-under-exact-operator")
				if !strings.Contains(f.Summary, tc.operator) {
					t.Errorf("summary does not name the operator: %s", f.Summary)
				}
			} else {
				noFindingFrom(t, findings, "wildcard-under-exact-operator")
			}
		})
	}
}

// Entra matches case-sensitively, and a case-only difference is close to
// invisible to a human reading a diff.
func TestCaseOnlyMismatch(t *testing.T) {
	tp := trust("StringEquals", "repo:MyOrg/MyRepo:ref:refs/heads/main")
	f := findingFor(t, Explain(ExplainInput{
		Trust: tp, Token: token("repo:myorg/myrepo:ref:refs/heads/main"),
	}), "case-only-mismatch")

	if f.Claim != "sub" {
		t.Errorf("Claim = %q, want sub", f.Claim)
	}
	if !strings.Contains(strings.ToLower(f.Summary), "capitalisation") {
		t.Errorf("summary should say the difference is case: %s", f.Summary)
	}

	t.Run("a genuine difference is not a case difference", func(t *testing.T) {
		noFindingFrom(t, Explain(ExplainInput{
			Trust: trust("StringEquals", "repo:other/repo:ref:refs/heads/main"),
			Token: token("repo:myorg/myrepo:ref:refs/heads/main"),
		}), "case-only-mismatch")
	})
}

// GCP's google.subject is capped at 127 bytes, and GitHub's immutable subjects
// are materially longer than the legacy ones.
func TestOversizedMappedSubject(t *testing.T) {
	long := "repo:averyveryverylongorganizationname@123456789/" +
		"anextremelylongrepositoryname@987654321:ref:refs/heads/a-long-release-branch-name"
	if len(long) <= maxMappedSubjectBytes {
		t.Fatalf("fixture is only %d bytes; it must exceed %d to exercise this",
			len(long), maxMappedSubjectBytes)
	}

	gcpTarget := GCPTarget{
		WorkloadIdentityPool: "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/x",
	}
	f := findingFor(t, Explain(ExplainInput{
		Trust: trust("StringEquals", long), Token: token(long), Target: gcpTarget,
	}), "gcp-subject-too-long")

	if !strings.Contains(f.Fix, "extract(") {
		t.Errorf("the fix should name the CEL workaround: %s", f.Fix)
	}

	t.Run("not GCP, not this detector's problem", func(t *testing.T) {
		noFindingFrom(t, Explain(ExplainInput{
			Trust: trust("StringEquals", long), Token: token(long),
			Target: AWSTarget{RoleARN: "arn:aws:iam::123456789012:role/r"},
		}), "gcp-subject-too-long")
	})

	t.Run("a short subject is fine", func(t *testing.T) {
		noFindingFrom(t, Explain(ExplainInput{
			Trust: trust("StringEquals", "repo:o/r:ref:refs/heads/main"),
			Token: token("repo:o/r:ref:refs/heads/main"), Target: gcpTarget,
		}), "gcp-subject-too-long")
	})
}

// A trailing ":*" also matches repo:…:pull_request, which a FORK's pull request
// reaches — so anyone able to open a PR can run with these credentials.
func TestForkPullRequestExposure(t *testing.T) {
	f := findingFor(t, Explain(ExplainInput{
		Trust: trust("StringLike", "repo:myorg/myrepo:*"),
		Token: token("repo:myorg/myrepo:ref:refs/heads/main"),
	}), "github-fork-pull-request")

	if f.Severity != FindingWarning {
		t.Errorf("severity = %v, want warning: this admits more than intended "+
			"but is not why this particular exchange failed", f.Severity)
	}
	if !strings.Contains(f.Summary, "pull_request") {
		t.Errorf("summary should name what it admits: %s", f.Summary)
	}

	t.Run("a pinned ref does not expose forks", func(t *testing.T) {
		noFindingFrom(t, Explain(ExplainInput{
			Trust: trust("StringLike", "repo:myorg/myrepo:ref:refs/heads/*"),
			Token: token("repo:myorg/myrepo:ref:refs/heads/main"),
		}), "github-fork-pull-request")
	})

	t.Run("a literal trailing star under StringEquals matches nothing", func(t *testing.T) {
		// The wildcard-under-exact-operator detector owns that case; this one
		// must not also claim it, or one policy produces two contradictory
		// findings — too wide AND matches nothing.
		noFindingFrom(t, Explain(ExplainInput{
			Trust: trust("StringEquals", "repo:myorg/myrepo:*"),
			Token: token("repo:myorg/myrepo:ref:refs/heads/main"),
		}), "github-fork-pull-request")
	})
}

// "No provider registered" and "registered, issuer differs" surface as the same
// AccessDenied and need opposite fixes.
func TestIssuerMismatch(t *testing.T) {
	t.Run("no provider registered", func(t *testing.T) {
		tp := trust("StringEquals", "repo:myorg/myrepo:ref:refs/heads/main")
		tp.Issuer = ""
		f := findingFor(t, Explain(ExplainInput{
			Trust: tp, Token: token("repo:myorg/myrepo:ref:refs/heads/main"),
		}), "issuer-not-registered")
		if f.Configured != "(none)" {
			t.Errorf("Configured = %q, want (none)", f.Configured)
		}
	})

	t.Run("registered but different", func(t *testing.T) {
		tp := trust("StringEquals", "repo:myorg/myrepo:ref:refs/heads/main")
		tp.Issuer = "https://gitlab.example.com"
		f := findingFor(t, Explain(ExplainInput{
			Trust: tp, Token: token("repo:myorg/myrepo:ref:refs/heads/main"),
		}), "issuer-mismatch")
		if !strings.Contains(f.Fix, "opposite fixes") {
			t.Errorf("the fix should distinguish it from the missing-provider case: %s", f.Fix)
		}
	})

	t.Run("trailing slash is called out specifically", func(t *testing.T) {
		tp := trust("StringEquals", "repo:myorg/myrepo:ref:refs/heads/main")
		tp.Issuer = "https://token.actions.githubusercontent.com/"
		f := findingFor(t, Explain(ExplainInput{
			Trust: tp, Token: token("repo:myorg/myrepo:ref:refs/heads/main"),
		}), "issuer-mismatch")
		if !strings.Contains(f.Summary, "trailing slash") {
			t.Errorf("summary should name the trailing slash: %s", f.Summary)
		}
	})

	t.Run("scheme differences are not a mismatch", func(t *testing.T) {
		// AWS registers a bare host; the token carries https://. Reporting that
		// as a mismatch would be a false positive on every correct AWS setup.
		tp := trust("StringEquals", "repo:myorg/myrepo:ref:refs/heads/main")
		tp.Issuer = "token.actions.githubusercontent.com"
		noFindingFrom(t, Explain(ExplainInput{
			Trust: tp, Token: token("repo:myorg/myrepo:ref:refs/heads/main"),
		}), "issuer-mismatch")
	})
}

// Without live trust, Explain returns nothing: base doctor behaviour is
// unchanged and --explain is opt-in.
func TestExplainWithoutTrustReturnsNothing(t *testing.T) {
	if got := Explain(ExplainInput{Token: token("repo:o/r:ref:refs/heads/main")}); got != nil {
		t.Errorf("Explain with no trust policy returned %d findings", len(got))
	}
}

// Most severe first, so the reason the exchange failed is the first thing read.
func TestFindingsAreOrderedBySeverity(t *testing.T) {
	tp := trust("StringLike", "repo:myorg/myrepo:*")
	tp.Issuer = "https://gitlab.example.com"

	findings := Explain(ExplainInput{
		Trust: tp, Token: token("repo:myorg/myrepo:ref:refs/heads/main"),
	})
	if len(findings) < 2 {
		t.Fatalf("expected several findings, got %d", len(findings))
	}
	for i := 1; i < len(findings); i++ {
		if findings[i-1].Severity < findings[i].Severity {
			t.Fatalf("findings are not severity-ordered: %v then %v",
				findings[i-1].SeverityText, findings[i].SeverityText)
		}
	}
	if findings[0].Severity != FindingCritical {
		t.Errorf("first finding is %v, want critical", findings[0].SeverityText)
	}
}

// Every finding has to be actionable: a detector that says something is wrong
// without saying what to do is a worse AccessDenied.
func TestEveryFindingCarriesAFix(t *testing.T) {
	tp := &TrustPolicy{
		Issuer:   "https://gitlab.example.com",
		Subjects: []string{"repo:myorg/myrepo:*"},
		Conditions: []TrustCondition{
			{Operator: "StringEquals", Claim: "sub", Value: "repo:myorg/myrepo:*"},
			{Operator: "StringLike", Claim: "sub", Value: "repo:MyOrg/myrepo:*"},
			{Operator: "StringEquals", Claim: "aud", Value: "STS.amazonaws.com"},
		},
	}
	findings := Explain(ExplainInput{
		Trust: tp, Token: token("repo:myorg@1/myrepo@2:environment:production"),
	})
	if len(findings) == 0 {
		t.Fatal("this policy is wrong in several ways; no findings were produced")
	}
	for _, f := range findings {
		if f.Summary == "" || f.Fix == "" {
			t.Errorf("%s has an empty summary or fix: %+v", f.Detector, f)
		}
		if f.SeverityText == "" {
			t.Errorf("%s has no severity text, which --format json needs", f.Detector)
		}
	}
}
