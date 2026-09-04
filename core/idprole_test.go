package core

import (
	"strings"
	"testing"
)

// AWS shipped sts:RoleAuthorizedByIdp in July 2026: an identity provider embeds
// "https://aws.amazon.com/roles" in the token naming which roles it may assume,
// and STS enforces that as an allow-list BEFORE the trust policy is evaluated.
//
// That "before" is the whole reason this detector exists. When the condition
// fails, nothing else in the policy is consulted — every other claim can match
// perfectly and the exchange is still refused, and nothing in the resulting
// error says which of the two happened.

func trustRequiringIdPAuthorization(subject string) *TrustPolicy {
	tp := trust("StringEquals", subject)
	tp.Conditions = append(tp.Conditions, TrustCondition{
		Operator: "Bool", Claim: IdPAuthorizedRoleConditionKey, Value: "true",
	})
	return tp
}

func TestIdPAuthorizedRole(t *testing.T) {
	const subject = "repo:myorg/myrepo:ref:refs/heads/main"
	const role = "arn:aws:iam::123456789012:role/deploy"

	t.Run("token carries no claim at all", func(t *testing.T) {
		f := findingFor(t, Explain(ExplainInput{
			Trust: trustRequiringIdPAuthorization(subject), Token: token(subject),
			TargetRole: role,
		}), "idp-authorized-role-missing")

		if f.Severity != FindingCritical {
			t.Errorf("severity = %v, want critical", f.Severity)
		}
		// The message has to explain the evaluation order, or an operator will
		// go looking at the subject condition — which is fine, and irrelevant.
		if !strings.Contains(f.Fix, "BEFORE the trust policy") {
			t.Errorf("the fix does not explain the evaluation order: %s", f.Fix)
		}
	})

	t.Run("claim names other roles", func(t *testing.T) {
		f := findingFor(t, Explain(ExplainInput{
			Trust: trustRequiringIdPAuthorization(subject), Token: token(subject),
			TargetRole:         role,
			IdPAuthorizedRoles: []string{"arn:aws:iam::123456789012:role/other"},
		}), "idp-authorized-role-mismatch")

		if !strings.Contains(f.Presented, "role/other") {
			t.Errorf("Presented = %q, want the roles the IdP DID authorize", f.Presented)
		}
		if f.Configured != role {
			t.Errorf("Configured = %q, want the role being attempted", f.Configured)
		}
	})

	t.Run("claim names this role", func(t *testing.T) {
		findings := Explain(ExplainInput{
			Trust: trustRequiringIdPAuthorization(subject), Token: token(subject),
			TargetRole:         role,
			IdPAuthorizedRoles: []string{"arn:aws:iam::1:role/other", role},
		})
		noFindingFrom(t, findings, "idp-authorized-role-missing")
		noFindingFrom(t, findings, "idp-authorized-role-mismatch")
	})

	// The condition is off by default and most policies will never carry it;
	// firing on every one of them would be noise.
	t.Run("policy does not require it", func(t *testing.T) {
		findings := Explain(ExplainInput{
			Trust: trust("StringEquals", subject), Token: token(subject), TargetRole: role,
		})
		noFindingFrom(t, findings, "idp-authorized-role-missing")
		noFindingFrom(t, findings, "idp-authorized-role-mismatch")
	})

	// Without knowing which role is being attempted there is nothing to compare
	// against, and guessing would produce a finding nobody can act on.
	t.Run("no target role to compare", func(t *testing.T) {
		noFindingFrom(t, Explain(ExplainInput{
			Trust: trustRequiringIdPAuthorization(subject), Token: token(subject),
			IdPAuthorizedRoles: []string{"arn:aws:iam::1:role/other"},
		}), "idp-authorized-role-mismatch")
	})
}

// A null roles claim must reach this detector as ABSENCE, not as one authorized
// role that happens to be the empty string.
//
// internal/jwt returned []string{""} for a null claim, because encoding/json
// treats null as a no-op and unmarshaling it into a string silently succeeds.
// That took this detector down its "the claim names OTHER roles" branch and
// printed "" as an authorized role, instead of saying the token carries no
// claim — sending an operator to look for a misconfiguration that is not there.
func TestNullRolesClaimReadsAsAbsent(t *testing.T) {
	const subject = "repo:myorg/myrepo:ref:refs/heads/main"
	const role = "arn:aws:iam::123456789012:role/deploy"

	// What jwt.StringOrSliceClaim now returns for a null claim.
	findings := Explain(ExplainInput{
		Trust: trustRequiringIdPAuthorization(subject), Token: token(subject),
		TargetRole: role, IdPAuthorizedRoles: nil,
	})
	missing := findingFor(t, findings, "idp-authorized-role-missing")
	if missing.Presented != "(absent)" {
		t.Errorf("Presented = %q, want (absent)", missing.Presented)
	}
	noFindingFrom(t, findings, "idp-authorized-role-mismatch")

	// The shape the bug produced, asserted so the difference is visible: one
	// empty-string role takes the other branch entirely.
	wrong := Explain(ExplainInput{
		Trust: trustRequiringIdPAuthorization(subject), Token: token(subject),
		TargetRole: role, IdPAuthorizedRoles: []string{""},
	})
	noFindingFrom(t, wrong, "idp-authorized-role-missing")
	findingFor(t, wrong, "idp-authorized-role-mismatch")
}
