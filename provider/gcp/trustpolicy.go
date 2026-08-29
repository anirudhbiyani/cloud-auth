package gcp

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// Implements core's validation source interfaces so its
// trust-policy and permission checks run against live GCP state. core is
// the leaf package, so the dependency is inverted through these interfaces.
var (
	_ core.TrustPolicySource   = (*Provider)(nil)
	_ core.GrantedPolicySource = (*Provider)(nil)
)

// celLiteral extracts double-quoted string literals from a CEL attribute
// condition. GCP scopes a workload identity pool provider with an expression
// such as:
//
//	assertion.sub == "system:serviceaccount:ns:verifier"
//	attribute.aws_role == "arn:aws:sts::123:assumed-role/r"
//
// Fully evaluating CEL is out of scope, but the literals are what an operator
// configured and what the expected subject must match, so surfacing them makes
// the comparison meaningful rather than skipping the check entirely.
var celLiteral = regexp.MustCompile(`"([^"]*)"`)

func subjectsFromAttributeCondition(cond string) []string {
	if strings.TrimSpace(cond) == "" {
		// No attribute condition means the provider admits EVERY identity the
		// issuer can mint — the classic confused-deputy hole, and Google's own
		// docs call it out. Surface it as the wildcard so the core validator
		// fails it rather than reporting a hollow pass.
		return []string{"*"}
	}
	matches := celLiteral.FindAllStringSubmatch(cond, -1)
	if len(matches) == 0 {
		// A condition we cannot decompose (e.g. purely arithmetic). Return it
		// verbatim so the failure message shows the operator what is configured.
		return []string{cond}
	}
	subjects := make([]string, 0, len(matches))
	seen := map[string]bool{}
	for _, m := range matches {
		if v := m[1]; v != "" && !seen[v] {
			seen[v] = true
			subjects = append(subjects, v)
		}
	}
	return subjects
}

// TrustPolicy reads the live workload identity pool provider and normalizes it.
func (p *Provider) TrustPolicy(ctx context.Context, ref core.MechanismRef) (*core.TrustPolicy, error) {
	if err := p.requireClients(true, false); err != nil {
		return nil, err
	}
	providerName := ref.ResourceIDs["provider_name"]
	if providerName == "" {
		return nil, fmt.Errorf("gcp: mechanism ref %q has no provider_name; cannot read its trust configuration", ref.ID)
	}

	wp, err := p.wifClient.GetWorkloadIdentityPoolProvider(ctx, providerName)
	if err != nil {
		return nil, fmt.Errorf("gcp: reading workload identity pool provider %s: %w", providerName, err)
	}
	if wp == nil {
		return nil, fmt.Errorf("gcp: workload identity pool provider %s not found", providerName)
	}

	tp := &core.TrustPolicy{
		Subjects: subjectsFromAttributeCondition(wp.AttributeCondition),
		Raw:      wp.AttributeCondition,
	}

	switch {
	case wp.OIDC != nil:
		tp.Issuer = wp.OIDC.IssuerURI
		tp.Audiences = append(tp.Audiences, wp.OIDC.AllowedAudiences...)
		if len(tp.Audiences) == 0 {
			// An unset allowed-audiences list does NOT mean "none accepted":
			// GCP falls back to the provider's own resource name (in both its
			// "//iam.googleapis.com/..." and https forms). Reporting none would
			// make the audience check fail against a correct provider.
			full := wp.Name
			if full == "" {
				full = providerName
			}
			tp.Audiences = append(tp.Audiences,
				"//iam.googleapis.com/"+full,
				"https://iam.googleapis.com/"+full,
			)
		}
	case wp.AWS != nil:
		// An aws-type provider trusts an AWS account rather than an OIDC issuer.
		// Render it distinctly so a mismatch reads sensibly.
		tp.Issuer = "aws-account:" + wp.AWS.AccountID
	default:
		return nil, fmt.Errorf("gcp: provider %s has neither an OIDC nor an AWS configuration", providerName)
	}

	// A disabled provider cannot mint anything; surface it as an unusable trust.
	if wp.Disabled {
		tp.Raw = "PROVIDER DISABLED; " + tp.Raw
	}
	return tp, nil
}

// GrantedPolicies returns the IAM roles bound on the target service account.
//
// As on AWS this verifies bindings, not effective permissions: it catches a role
// that was removed or never granted, but not a custom role whose contents were
// narrowed.
func (p *Provider) GrantedPolicies(ctx context.Context, ref core.MechanismRef) ([]string, error) {
	if err := p.requireClients(false, true); err != nil {
		return nil, err
	}
	sa := ref.ResourceIDs["service_account_email"]
	if sa == "" {
		return nil, fmt.Errorf("gcp: mechanism ref %q has no service_account_email; cannot list its roles", ref.ID)
	}
	resource := "projects/-/serviceAccounts/" + sa

	policy, err := p.iamClient.GetIAMPolicy(ctx, resource)
	if err != nil {
		return nil, fmt.Errorf("gcp: reading IAM policy for %s: %w", sa, err)
	}
	if policy == nil {
		return nil, nil
	}

	roles := make([]string, 0, len(policy.Bindings))
	seen := map[string]bool{}
	for _, b := range policy.Bindings {
		if b == nil || b.Role == "" || seen[b.Role] {
			continue
		}
		seen[b.Role] = true
		roles = append(roles, b.Role)
	}
	return roles, nil
}

// firstCELLiteral returns the first quoted literal in a CEL attribute
// condition, i.e. the concrete subject an operator scoped the provider to. Used
// to turn a recorded condition back into an expected subject for comparison.
func firstCELLiteral(cond string) string {
	if cond == "" {
		return ""
	}
	if m := celLiteral.FindStringSubmatch(cond); len(m) > 1 {
		return m[1]
	}
	return ""
}
