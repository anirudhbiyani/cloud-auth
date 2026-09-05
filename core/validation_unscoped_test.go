package core

import (
	"context"
	"strings"
	"testing"
)

type stubTrustPolicy struct{ tp *TrustPolicy }

func (s stubTrustPolicy) TrustPolicy(context.Context, MechanismRef) (*TrustPolicy, error) {
	return s.tp, nil
}

// Regression: this exact input used to report "trust policy pins the expected issuer, audience and subject" — a false assurance about the only condition that decides who may assume the role.
func TestTrustPolicyFailsWhenNoSubjectConditionExists(t *testing.T) {
	live := &TrustPolicy{
		Issuer:    "https://token.actions.githubusercontent.com",
		Audiences: []string{"sts.amazonaws.com"},
		Subjects:  nil, // no sub condition at all
	}
	v := NewTrustPolicyMatchValidator(
		"https://token.actions.githubusercontent.com", "sts.amazonaws.com", "",
		WithTrustPolicySource(stubTrustPolicy{live}))

	c := v.Validate(context.Background(), MechanismRef{})
	if c.Status != CheckStatusFailed {
		t.Fatalf("status = %s, want failed; message = %q", c.Status, c.Message)
	}
	if !strings.Contains(c.Message, "NO subject condition") {
		t.Errorf("message should name the absent condition, got %q", c.Message)
	}
}

// Regression: an attacker (or a drifting IaC module) appends a second Allow statement.
func TestTrustPolicyFailsWhenWidenedByAnExtraStatement(t *testing.T) {
	live := &TrustPolicy{
		Issuer: "https://token.actions.githubusercontent.com",
		Audiences: []string{
			"sts.amazonaws.com",
			"attacker-aud",
		},
		Subjects: []string{
			"repo:myorg/myrepo:ref:refs/heads/main",
			"repo:attacker/evil:*",
		},
	}
	v := NewTrustPolicyMatchValidator(
		"https://token.actions.githubusercontent.com",
		"sts.amazonaws.com",
		"repo:myorg/myrepo:ref:refs/heads/main",
		WithTrustPolicySource(stubTrustPolicy{live}))

	c := v.Validate(context.Background(), MechanismRef{})
	if c.Status != CheckStatusFailed {
		t.Fatalf("status = %s, want failed; message = %q", c.Status, c.Message)
	}
	for _, want := range []string{"attacker-aud", "repo:attacker/evil:*", "widened"} {
		if !strings.Contains(c.Message, want) {
			t.Errorf("message should mention %q, got %q", want, c.Message)
		}
	}
}

// The happy path must stay quiet, or the two checks above are worthless.
func TestTrustPolicyStillPassesWhenExactlyAsConfigured(t *testing.T) {
	live := &TrustPolicy{
		Issuer:    "https://token.actions.githubusercontent.com",
		Audiences: []string{"sts.amazonaws.com"},
		Subjects:  []string{"repo:myorg/myrepo:ref:refs/heads/main"},
	}
	v := NewTrustPolicyMatchValidator(
		"https://token.actions.githubusercontent.com",
		"sts.amazonaws.com",
		"repo:myorg/myrepo:ref:refs/heads/main",
		WithTrustPolicySource(stubTrustPolicy{live}))

	if c := v.Validate(context.Background(), MechanismRef{}); c.Status != CheckStatusPassed {
		t.Fatalf("status = %s, want passed; message = %q", c.Status, c.Message)
	}
}

func TestIsUnscoped(t *testing.T) {
	unscoped := []string{"", "*", "**", "?*", "*:*", "*:*:*", "  *  "}
	scoped := []string{
		"repo:myorg/myrepo:*",
		"repo:*",
		"system:serviceaccount:ns:sa",
		"system:serviceaccount:*:sa",
	}
	for _, p := range unscoped {
		if !isUnscoped(p) {
			t.Errorf("isUnscoped(%q) = false, want true", p)
		}
	}
	for _, p := range scoped {
		if isUnscoped(p) {
			t.Errorf("isUnscoped(%q) = true, want false", p)
		}
	}
}
