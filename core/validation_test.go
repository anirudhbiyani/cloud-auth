package core

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Severity is a string type, so comparing it with >= is a lexicographic compare, not a severity compare.
func TestSeverityRankOrdering(t *testing.T) {
	if SeverityInfo.Rank() >= SeverityWarning.Rank() ||
		SeverityWarning.Rank() >= SeverityError.Rank() ||
		SeverityError.Rank() >= SeverityCritical.Rank() {
		t.Fatalf("severity ranks are not strictly increasing: info=%d warning=%d error=%d critical=%d",
			SeverityInfo.Rank(), SeverityWarning.Rank(), SeverityError.Rank(), SeverityCritical.Rank())
	}
}

func TestIsValidUsesSeverityRankNotStringCompare(t *testing.T) {
	tests := []struct {
		name     string
		status   CheckStatus
		severity Severity
		want     bool // expected IsValid()
	}{
		// The bug this pins: a CRITICAL failure must invalidate the report.
		{"critical failure invalidates", CheckStatusFailed, SeverityCritical, false},
		{"error failure invalidates", CheckStatusFailed, SeverityError, false},
		// ...and a low-severity failure must NOT invalidate it.
		{"warning failure does not invalidate", CheckStatusFailed, SeverityWarning, true},
		{"info failure does not invalidate", CheckStatusFailed, SeverityInfo, true},
		{"passed critical is valid", CheckStatusPassed, SeverityCritical, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &ValidationReport{Checks: []ValidationCheck{
				{ID: "x", Status: tc.status, Severity: tc.severity},
			}}
			if got := r.IsValid(); got != tc.want {
				t.Errorf("IsValid() = %v, want %v (status=%s severity=%s)",
					got, tc.want, tc.status, tc.severity)
			}
		})
	}
}

// A skipped check verified nothing.
func TestIsCompleteDistinguishesUnverifiedFromValid(t *testing.T) {
	r := &ValidationReport{Checks: []ValidationCheck{
		{ID: "reachable", Status: CheckStatusPassed, Severity: SeverityError},
		{ID: "trust_policy", Status: CheckStatusSkipped, Severity: SeverityError},
	}}
	if !r.IsValid() {
		t.Error("IsValid() should be true: nothing failed")
	}
	if r.IsComplete() {
		t.Error("IsComplete() must be false when an error-severity check was skipped")
	}
	skipped := r.SkippedChecks()
	if len(skipped) != 1 || skipped[0].ID != "trust_policy" {
		t.Errorf("SkippedChecks() = %+v, want just trust_policy", skipped)
	}
}

func TestIsCompleteIgnoresLowSeveritySkips(t *testing.T) {
	// A skipped informational check doesn't make the run incomplete.
	r := &ValidationReport{Checks: []ValidationCheck{
		{ID: "a", Status: CheckStatusPassed, Severity: SeverityError},
		{ID: "b", Status: CheckStatusSkipped, Severity: SeverityInfo},
	}}
	if !r.IsComplete() {
		t.Error("IsComplete() should be true when only low-severity checks were skipped")
	}
}

// The stubs are honest (Skipped, not Passed) but must say so loudly enough that a caller can act on it.
func TestStubbedValidatorsAreSkippedWithRemediation(t *testing.T) {
	for _, v := range []Validator{
		NewTrustPolicyMatchValidator("iss", "aud", "sub"),
		NewPermissionsValidator([]string{"s3:GetObject"}),
	} {
		got := v.Validate(context.Background(), MechanismRef{ID: "r"})
		if got.Status != CheckStatusSkipped {
			t.Errorf("%s: status = %s, want skipped", v.ID(), got.Status)
		}
		if got.Remediation == "" {
			t.Errorf("%s: skipped check must carry remediation guidance", v.ID())
		}
	}
}

// --------------------------------------------------------------------------- Trust-policy and permission validators, once a provider supplies live facts.

type fakeTrustSource struct {
	tp  *TrustPolicy
	err error
}

func (f *fakeTrustSource) TrustPolicy(context.Context, MechanismRef) (*TrustPolicy, error) {
	return f.tp, f.err
}

type fakeGrantSource struct {
	policies []string
	err      error
}

func (f *fakeGrantSource) GrantedPolicies(context.Context, MechanismRef) ([]string, error) {
	return f.policies, f.err
}

func TestTrustPolicyMatchAgainstLivePolicy(t *testing.T) {
	const (
		iss = "https://token.actions.githubusercontent.com"
		aud = "sts.amazonaws.com"
		sub = "repo:myorg/myrepo:ref:refs/heads/main"
	)
	tests := []struct {
		name string
		live *TrustPolicy
		want CheckStatus
		// substring the failure message must mention, so an operator can act
		mentions string
	}{
		{
			name: "exact match passes",
			live: &TrustPolicy{Issuer: iss, Audiences: []string{aud}, Subjects: []string{sub}},
			want: CheckStatusPassed,
		},
		{
			name:     "wrong issuer fails and names it",
			live:     &TrustPolicy{Issuer: "https://evil.example", Audiences: []string{aud}, Subjects: []string{sub}},
			want:     CheckStatusFailed,
			mentions: "issuer",
		},
		{
			name:     "missing audience fails",
			live:     &TrustPolicy{Issuer: iss, Audiences: []string{"other"}, Subjects: []string{sub}},
			want:     CheckStatusFailed,
			mentions: "audience",
		},
		{
			name:     "subject not admitted fails",
			live:     &TrustPolicy{Issuer: iss, Audiences: []string{aud}, Subjects: []string{"repo:other/repo:*"}},
			want:     CheckStatusFailed,
			mentions: "subject",
		},
		{
			// A StringLike wildcard in the deployed policy legitimately admits a concrete expected subject.
			name: "wildcard pattern admits concrete subject",
			live: &TrustPolicy{Issuer: iss, Audiences: []string{aud}, Subjects: []string{"repo:myorg/myrepo:*"}},
			want: CheckStatusPassed,
		},
		{
			// An unscoped trust is the confused-deputy hole this check exists for.
			name:     "wide-open subject is rejected outright",
			live:     &TrustPolicy{Issuer: iss, Audiences: []string{aud}, Subjects: []string{"*"}},
			want:     CheckStatusFailed,
			mentions: "unscoped",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := NewTrustPolicyMatchValidator(iss, aud, sub,
				WithTrustPolicySource(&fakeTrustSource{tp: tc.live}))
			got := v.Validate(context.Background(), MechanismRef{ID: "r"})
			if got.Status != tc.want {
				t.Fatalf("status = %s, want %s (message=%q)", got.Status, tc.want, got.Message)
			}
			if tc.mentions != "" && !strings.Contains(strings.ToLower(got.Message), tc.mentions) {
				t.Errorf("message %q should mention %q", got.Message, tc.mentions)
			}
		})
	}
}

func TestTrustPolicyFetchErrorFails(t *testing.T) {
	v := NewTrustPolicyMatchValidator("i", "a", "s",
		WithTrustPolicySource(&fakeTrustSource{err: errors.New("access denied")}))
	got := v.Validate(context.Background(), MechanismRef{ID: "r"})
	if got.Status != CheckStatusFailed {
		t.Errorf("status = %s, want failed when the policy cannot be read", got.Status)
	}
}

func TestPermissionsAgainstGrantedPolicies(t *testing.T) {
	required := []string{"arn:aws:iam::aws:policy/ReadOnlyAccess", "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"}

	t.Run("all present passes", func(t *testing.T) {
		v := NewPermissionsValidator(required,
			WithGrantedPolicySource(&fakeGrantSource{policies: append([]string{"extra"}, required...)}))
		got := v.Validate(context.Background(), MechanismRef{ID: "r"})
		if got.Status != CheckStatusPassed {
			t.Errorf("status = %s, want passed (message=%q)", got.Status, got.Message)
		}
	})

	t.Run("missing one fails and names it", func(t *testing.T) {
		v := NewPermissionsValidator(required,
			WithGrantedPolicySource(&fakeGrantSource{policies: required[:1]}))
		got := v.Validate(context.Background(), MechanismRef{ID: "r"})
		if got.Status != CheckStatusFailed {
			t.Fatalf("status = %s, want failed", got.Status)
		}
		if !strings.Contains(got.Message, "AmazonS3ReadOnlyAccess") {
			t.Errorf("message %q must name the missing policy", got.Message)
		}
	})
}

// Without a source both remain honestly skipped — the pre-existing behaviour.
func TestValidatorsSkipWithoutSource(t *testing.T) {
	for _, v := range []Validator{
		NewTrustPolicyMatchValidator("i", "a", "s"),
		NewPermissionsValidator([]string{"p"}),
	} {
		if got := v.Validate(context.Background(), MechanismRef{ID: "r"}); got.Status != CheckStatusSkipped {
			t.Errorf("%s: status = %s, want skipped without a source", v.ID(), got.Status)
		}
	}
}

// Azure matches issuer/subject/audience case-sensitively and exactly.
func TestTrustPolicyReportsCaseOnlyMismatchExplicitly(t *testing.T) {
	tests := []struct {
		name                   string
		expIss, expAud, expSub string
		live                   *TrustPolicy
	}{
		{
			name:   "issuer differs only in case",
			expIss: "https://oidc.eks.us-east-1.amazonaws.com/id/ABC", expAud: "api://AzureADTokenExchange", expSub: "system:serviceaccount:ns:sa",
			live: &TrustPolicy{
				Issuer:    "https://oidc.eks.us-east-1.amazonaws.com/id/abc",
				Audiences: []string{"api://AzureADTokenExchange"},
				Subjects:  []string{"system:serviceaccount:ns:sa"},
			},
		},
		{
			name:   "subject differs only in case",
			expIss: "https://x", expAud: "api://AzureADTokenExchange", expSub: "system:serviceaccount:NS:SA",
			live: &TrustPolicy{
				Issuer:    "https://x",
				Audiences: []string{"api://AzureADTokenExchange"},
				Subjects:  []string{"system:serviceaccount:ns:sa"},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := NewTrustPolicyMatchValidator(tc.expIss, tc.expAud, tc.expSub,
				WithTrustPolicySource(&fakeTrustSource{tp: tc.live}))
			got := v.Validate(context.Background(), MechanismRef{ID: "r"})
			if got.Status != CheckStatusFailed {
				t.Fatalf("status = %s, want failed", got.Status)
			}
			if !strings.Contains(strings.ToLower(got.Message), "case") {
				t.Errorf("message %q should call out the case-only difference", got.Message)
			}
		})
	}
}
