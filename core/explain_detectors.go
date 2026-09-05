package core

import (
	"fmt"
	"strings"
)

// The detectors. Each answers one question an AccessDenied does not.

// githubIssuer is GitHub Actions' single global OIDC issuer, shared by every tenant on the platform.
const githubIssuer = "token.actions.githubusercontent.com"

// maxMappedSubjectBytes is GCP's hard limit on a mapped google.subject.
const maxMappedSubjectBytes = 127

// isGitHubSubject reports whether a value looks like a GitHub Actions `sub`.
func isGitHubSubject(v string) bool { return strings.HasPrefix(v, "repo:") }

// immutableSubject reports whether a GitHub subject uses the immutable form, where the org and repo carry their numeric ids.
func immutableSubject(v string) bool {
	if !isGitHubSubject(v) {
		return false
	}
	repoPart := strings.TrimPrefix(v, "repo:")
	if i := strings.Index(repoPart, ":"); i >= 0 {
		repoPart = repoPart[:i]
	}
	return strings.Contains(repoPart, "@")
}

// detectImmutableSubjectMismatch catches a policy written against the legacy GitHub subject while the token presents the immutable form, or the reverse.
func detectImmutableSubjectMismatch(in ExplainInput) []Finding {
	presented := presentedSubject(in)
	if !isGitHubSubject(presented) {
		return nil
	}

	tokenImmutable := immutableSubject(presented)
	var out []Finding
	for _, cond := range in.Trust.SubjectConditions() {
		if !isGitHubSubject(cond.Value) {
			continue
		}
		policyImmutable := immutableSubject(cond.Value)
		if policyImmutable == tokenImmutable {
			continue
		}

		if tokenImmutable {
			out = append(out, newFinding("github-immutable-subject", FindingCritical,
				"the trust policy uses GitHub's legacy subject format, but this token presents the "+
					"immutable format (the org and repo carry numeric ids)",
				fmt.Sprintf("update the policy's sub condition to %q — GitHub enforced immutable "+
					"subject claims on 15 July 2026 for new repositories and for any repository that "+
					"is renamed or transferred, so this breaks the first time either happens",
					presented)).
				withDiff("sub", presented, cond.Value))
			continue
		}
		out = append(out, newFinding("github-immutable-subject", FindingCritical,
			"the trust policy uses GitHub's immutable subject format, but this token presents the "+
				"legacy format",
			fmt.Sprintf("either this repository has not migrated yet — in which case the policy should "+
				"read %q for now — or the policy was written for a different repository", presented)).
			withDiff("sub", presented, cond.Value))
	}
	return out
}

// detectEnvironmentOverridesBranch catches the positional-concatenation trap in GitHub's subject.
func detectEnvironmentOverridesBranch(in ExplainInput) []Finding {
	presented := presentedSubject(in)
	if !isGitHubSubject(presented) {
		return nil
	}
	presentsEnvironment := strings.Contains(presented, ":environment:")

	var out []Finding
	for _, cond := range in.Trust.SubjectConditions() {
		if !isGitHubSubject(cond.Value) {
			continue
		}
		policyPinsRef := strings.Contains(cond.Value, ":ref:")

		if presentsEnvironment && policyPinsRef {
			out = append(out, newFinding("github-environment-overrides-ref", FindingCritical,
				"this job declares an environment, so GitHub replaced the ref segment of `sub` with "+
					"it — the policy pins a ref that the token can no longer carry",
				fmt.Sprintf("change the policy's sub condition to %q, or remove the environment from "+
					"the job. GitHub's sub is a positional concatenation: environment REPLACES ref "+
					"rather than joining it", presented)).
				withDiff("sub", presented, cond.Value))
			continue
		}
		if !presentsEnvironment && strings.Contains(cond.Value, ":environment:") {
			out = append(out, newFinding("github-environment-overrides-ref", FindingCritical,
				"the policy expects an environment segment, but this job does not declare an "+
					"environment, so the token presents a ref instead",
				fmt.Sprintf("add `environment:` to the job, or change the policy's sub condition to %q",
					presented)).
				withDiff("sub", presented, cond.Value))
		}
	}
	return out
}

// detectExactOperatorWithWildcard catches a wildcard under an operator that does not expand it.
func detectExactOperatorWithWildcard(in ExplainInput) []Finding {
	var out []Finding
	for _, cond := range in.Trust.Conditions {
		if !cond.IsPattern() || cond.HonoursWildcards() {
			continue
		}
		out = append(out, newFinding("wildcard-under-exact-operator", FindingCritical,
			fmt.Sprintf("the %s condition uses %s, which compares literally — the %q in it is matched "+
				"as a character, so this condition can never match any token",
				cond.Claim, cond.Operator, wildcardChars(cond.Value)),
			fmt.Sprintf("change the operator to %sLike to make the pattern mean what it looks like, "+
				"or replace %q with the exact value you intend to allow",
				strings.TrimSuffix(cond.Operator, "Equals"), cond.Value)).
			withDiff(cond.Claim, presentedFor(in, cond.Claim), cond.Value))
	}
	return out
}

// wildcardChars names which wildcard characters appear, for the message.
func wildcardChars(v string) string {
	var chars []string
	if strings.Contains(v, "*") {
		chars = append(chars, "*")
	}
	if strings.Contains(v, "?") {
		chars = append(chars, "?")
	}
	return strings.Join(chars, " and ")
}

// presentedFor returns the token's value for a claim.
func presentedFor(in ExplainInput, claim string) string {
	if in.Token == nil {
		return ""
	}
	switch claim {
	case "sub":
		return in.Token.Subject
	case "aud", "oaud":
		return in.Token.Audience
	}
	return ""
}

// detectCaseOnlyMismatch catches values that differ only in case.
func detectCaseOnlyMismatch(in ExplainInput) []Finding {
	var out []Finding

	check := func(claim, presented, configured string) {
		if presented == "" || configured == "" || presented == configured {
			return
		}
		if !strings.EqualFold(presented, configured) {
			return
		}
		out = append(out, newFinding("case-only-mismatch", FindingCritical,
			fmt.Sprintf("the %s differs from the policy only in capitalisation", claim),
			"Entra matches issuer, subject and audience case-sensitively; correct the case in the "+
				"trust configuration to match the token exactly").
			withDiff(claim, presented, configured))
	}

	if in.Token != nil {
		if in.Trust.Issuer != "" {
			check("issuer", in.Token.Issuer, in.Trust.Issuer)
		}
		for _, cond := range in.Trust.SubjectConditions() {
			check("sub", in.Token.Subject, cond.Value)
		}
		for _, cond := range in.Trust.AudienceConditions() {
			check(cond.Claim, in.Token.Audience, cond.Value)
		}
	}
	return out
}

// detectOversizedMappedSubject catches a subject that will not fit GCP's google.subject.
func detectOversizedMappedSubject(in ExplainInput) []Finding {
	if in.Target == nil || in.Target.Cloud() != GCP {
		return nil
	}
	presented := presentedSubject(in)
	if len(presented) <= maxMappedSubjectBytes {
		return nil
	}
	return []Finding{newFinding("gcp-subject-too-long", FindingCritical,
		fmt.Sprintf("this token's sub is %d bytes; GCP's google.subject is capped at %d",
			len(presented), maxMappedSubjectBytes),
		"map a shorter value instead of the whole claim — CEL's extract() is the documented "+
			"workaround, e.g. "+
			`google.subject = assertion.sub.extract("repo:{repo}:") — or map assertion.repository_id, `+
			"which is stable across renames").
		withDiff("sub", presented, fmt.Sprintf("(at most %d bytes)", maxMappedSubjectBytes))}
}

// detectForkPullRequestExposure catches a trailing wildcard that admits pull_request runs.
func detectForkPullRequestExposure(in ExplainInput) []Finding {
	var out []Finding
	for _, cond := range in.Trust.SubjectConditions() {
		if !isGitHubSubject(cond.Value) || !cond.HonoursWildcards() {
			continue
		}
		if !strings.HasSuffix(cond.Value, ":*") {
			continue
		}
		out = append(out, newFinding("github-fork-pull-request", FindingWarning,
			fmt.Sprintf("the sub condition %q ends in a wildcard, so it also matches "+
				"repo:…:pull_request — which a pull request from a FORK reaches", cond.Value),
			"pin the segment: repo:org/repo:ref:refs/heads/main for a branch, or "+
				"repo:org/repo:environment:production for an environment. If pull_request runs are "+
				"meant to have these credentials, say so explicitly rather than by wildcard").
			withDiff("sub", presentedSubject(in), cond.Value))
	}
	return out
}

// detectIssuerMismatch separates "no IdP registered" from "registered, but the issuer string differs".
func detectIssuerMismatch(in ExplainInput) []Finding {
	if in.Token == nil || in.Token.Issuer == "" {
		return nil
	}
	if in.Trust.Issuer == "" {
		return []Finding{newFinding("issuer-not-registered", FindingCritical,
			"the trust policy names no OIDC issuer, so no identity provider is registered for this "+
				"token's issuer",
			fmt.Sprintf("register %q as an OIDC identity provider on the target, then add it as the "+
				"federated principal of the trust policy", in.Token.Issuer)).
			withDiff("iss", in.Token.Issuer, "(none)")}
	}

	presented := normalizeIssuer(in.Token.Issuer)
	configured := normalizeIssuer(in.Trust.Issuer)
	if presented == configured {
		return nil
	}
	if strings.EqualFold(presented, configured) {
		return nil // detectCaseOnlyMismatch says it better
	}

	finding := newFinding("issuer-mismatch", FindingCritical,
		"an identity provider IS registered, but its issuer differs from the one this token was "+
			"minted by",
		fmt.Sprintf("register an identity provider for %q, or point the trust policy at the existing "+
			"one. A registered-but-different issuer and no provider at all both surface as "+
			"AccessDenied, and they need opposite fixes", in.Token.Issuer)).
		withDiff("iss", in.Token.Issuer, in.Trust.Issuer)

	// Trailing slash and scheme are the two that waste the most time, because the strings look identical at a glance.
	if strings.TrimSuffix(presented, "/") == strings.TrimSuffix(configured, "/") {
		finding.Summary = "the issuer differs only by a trailing slash"
		finding.Fix = "remove or add the trailing slash so the two match exactly"
	}
	return []Finding{finding}
}

// normalizeIssuer strips the scheme, which providers store inconsistently: AWS registers a bare host, most tokens carry https://.
func normalizeIssuer(v string) string {
	v = strings.TrimPrefix(v, "https://")
	return strings.TrimPrefix(v, "http://")
}

// detectIdPAuthorizedRoleMismatch catches a trust policy demanding sts:RoleAuthorizedByIdp against a token whose issuer did not authorize this role.
func detectIdPAuthorizedRoleMismatch(in ExplainInput) []Finding {
	var required bool
	for _, c := range in.Trust.Conditions {
		if c.Claim == IdPAuthorizedRoleConditionKey && strings.EqualFold(c.Value, "true") {
			required = true
			break
		}
	}
	if !required {
		return nil
	}

	if len(in.IdPAuthorizedRoles) == 0 {
		return []Finding{newFinding("idp-authorized-role-missing", FindingCritical,
			"the trust policy requires sts:RoleAuthorizedByIdp, but this token carries no "+
				IdPAuthorizedRoleClaim+" claim",
			"either configure the identity provider to embed "+IdPAuthorizedRoleClaim+
				" naming this role, or drop the condition. STS evaluates it BEFORE the trust "+
				"policy, so while it fails nothing else in the policy is consulted at all").
			withDiff(IdPAuthorizedRoleClaim, "(absent)", "required")}
	}

	if in.TargetRole == "" {
		return nil // nothing to compare against
	}
	for _, role := range in.IdPAuthorizedRoles {
		if strings.EqualFold(strings.TrimSpace(role), strings.TrimSpace(in.TargetRole)) {
			return nil
		}
	}

	return []Finding{newFinding("idp-authorized-role-mismatch", FindingCritical,
		"the identity provider authorized this token for other roles, and this is not one of them",
		fmt.Sprintf("add %q to the %s claim the identity provider embeds, or assume one of the roles "+
			"it already names", in.TargetRole, IdPAuthorizedRoleClaim)).
		withDiff(IdPAuthorizedRoleClaim, strings.Join(in.IdPAuthorizedRoles, ", "), in.TargetRole)}
}
