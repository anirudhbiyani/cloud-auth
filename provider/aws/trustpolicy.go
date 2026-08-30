package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// This file implements the validation source interfaces from core, so the
// core's trust-policy and permission checks actually run against live IAM state
// instead of reporting "skipped". core is the leaf package (providers
// import it, never the reverse), so the dependency is inverted through these
// interfaces.
var (
	_ core.TrustPolicySource   = (*Provider)(nil)
	_ core.GrantedPolicySource = (*Provider)(nil)
)

// iamPolicyDoc mirrors an IAM policy document. Several fields are polymorphic
// in the IAM schema — Principal.Federated, Action, and condition values may each
// be a bare string or an array — so they are decoded as json.RawMessage and
// normalized by stringOrSlice.
type iamPolicyDoc struct {
	Version   string `json:"Version"`
	Statement []struct {
		Effect    string `json:"Effect"`
		Principal struct {
			Federated json.RawMessage `json:"Federated"`
		} `json:"Principal"`
		Action    json.RawMessage                       `json:"Action"`
		Condition map[string]map[string]json.RawMessage `json:"Condition"`
	} `json:"Statement"`
}

// stringOrSlice normalizes a JSON value that IAM allows to be either a string
// or an array of strings.
func stringOrSlice(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if s == "" {
			return nil
		}
		return []string{s}
	}
	var xs []string
	if err := json.Unmarshal(raw, &xs); err == nil {
		return xs
	}
	return nil
}

// issuerFromFederatedPrincipal turns a trust-policy principal into the issuer
// URL a token actually carries.
//
// The principal is either an OIDC provider ARN
// ("arn:aws:iam::123:oidc-provider/token.actions.githubusercontent.com") or, for
// AWS's built-in IdPs, a bare host ("accounts.google.com"). Both denote the
// issuer "https://<host+path>", which is what the spec's OIDCProviderURL holds —
// comparing the raw ARN against it would never match.
func issuerFromFederatedPrincipal(principal string) string {
	if principal == "" {
		return ""
	}
	if strings.HasPrefix(principal, "arn:") {
		if i := strings.Index(principal, ":oidc-provider/"); i >= 0 {
			return "https://" + principal[i+len(":oidc-provider/"):]
		}
		// A non-OIDC federated principal (e.g. SAML); return it unchanged so the
		// mismatch is reported honestly rather than mangled into a URL.
		return principal
	}
	if strings.HasPrefix(principal, "https://") || strings.HasPrefix(principal, "http://") {
		return principal
	}
	return "https://" + principal
}

// TrustPolicy reads the role's live assume-role policy and normalizes it into
// the provider-neutral shape the core validator compares against.
func (p *Provider) TrustPolicy(ctx context.Context, ref core.MechanismRef) (*core.TrustPolicy, error) {
	roleName := ref.ResourceIDs["role_name"]
	if roleName == "" {
		return nil, fmt.Errorf("aws: mechanism ref %q has no role_name; cannot read its trust policy", ref.ID)
	}

	client, err := p.iam(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws: resolving IAM client: %w", err)
	}

	role, err := client.GetRole(ctx, roleName)
	if err != nil {
		return nil, fmt.Errorf("aws: reading role %s: %w", roleName, err)
	}
	if role == nil {
		return nil, fmt.Errorf("aws: role %s not found", roleName)
	}

	doc := role.AssumeRolePolicyDocument
	// IAM may hand back the document URL-encoded depending on the API path.
	if decoded, derr := urlDecodeIfNeeded(doc); derr == nil {
		doc = decoded
	}

	var parsed iamPolicyDoc
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		return nil, fmt.Errorf("aws: parsing trust policy for role %s: %w", roleName, err)
	}

	tp := &core.TrustPolicy{Raw: doc}
	seenAud := map[string]bool{}
	seenSub := map[string]bool{}

	for _, st := range parsed.Statement {
		// Only Allow statements grant trust; a Deny doesn't widen it.
		if st.Effect != "" && !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		if fed := stringOrSlice(st.Principal.Federated); len(fed) > 0 && tp.Issuer == "" {
			tp.Issuer = issuerFromFederatedPrincipal(fed[0])
		}
		// Condition keys are "<provider>:aud" / ":sub" / ":oaud", across any
		// operator (StringEquals, StringLike, ForAllValues:StringEquals, ...).
		// The claim suffix is what identifies the claim, and the operator is
		// what says how it is matched — this used to keep the first and discard
		// the second, which makes a literal "*" under StringEquals (matches
		// nothing, trust silently dead) indistinguishable from the same "*"
		// under StringLike (matches everything, trust wide open).
		//
		// Iteration order over the operator map is random, so conditions are
		// sorted before returning.
		for operator, kv := range st.Condition {
			for key, raw := range kv {
				claim := key
				if i := strings.LastIndex(key, ":"); i >= 0 {
					claim = key[i+1:]
				}
				values := stringOrSlice(raw)
				switch claim {
				// ":oaud" carries the real audience for Google, where ":aud" is
				// mapped to the azp claim — collect both.
				case "aud", "oaud":
					for _, v := range values {
						tp.Conditions = append(tp.Conditions,
							core.TrustCondition{Operator: operator, Claim: claim, Value: v})
						if !seenAud[v] {
							seenAud[v] = true
							tp.Audiences = append(tp.Audiences, v)
						}
					}
				case "sub":
					for _, v := range values {
						tp.Conditions = append(tp.Conditions,
							core.TrustCondition{Operator: operator, Claim: claim, Value: v})
						if !seenSub[v] {
							seenSub[v] = true
							tp.Subjects = append(tp.Subjects, v)
						}
					}
				default:
					// sts:RoleAuthorizedByIdp is not a claim on the token — it
					// is a question STS answers about one — but it has to be
					// retained, or --explain cannot see that the policy demands
					// something the token may not carry.
					if key == core.IdPAuthorizedRoleConditionKey {
						for _, v := range values {
							tp.Conditions = append(tp.Conditions, core.TrustCondition{
								Operator: operator, Claim: core.IdPAuthorizedRoleConditionKey, Value: v,
							})
						}
					}
				}
			}
		}
	}
	// Deterministic order: the operator map above iterates randomly, and a
	// diff that reorders itself between runs is unreadable.
	slices.SortFunc(tp.Conditions, func(a, b core.TrustCondition) int {
		if n := strings.Compare(a.Claim, b.Claim); n != 0 {
			return n
		}
		if n := strings.Compare(a.Operator, b.Operator); n != 0 {
			return n
		}
		return strings.Compare(a.Value, b.Value)
	})
	return tp, nil
}

// GrantedPolicies lists what is actually attached to the role: managed policy
// ARNs plus inline policy names.
//
// This verifies attachment, which is what catches drift and accidental
// detachment. It is not an effective-permission simulation, so it cannot detect
// a managed policy whose contents grant less than its name suggests.
func (p *Provider) GrantedPolicies(ctx context.Context, ref core.MechanismRef) ([]string, error) {
	roleName := ref.ResourceIDs["role_name"]
	if roleName == "" {
		return nil, fmt.Errorf("aws: mechanism ref %q has no role_name; cannot list its policies", ref.ID)
	}

	client, err := p.iam(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws: resolving IAM client: %w", err)
	}

	attached, err := client.ListAttachedRolePolicies(ctx, roleName)
	if err != nil {
		return nil, fmt.Errorf("aws: listing attached policies for role %s: %w", roleName, err)
	}
	inline, err := client.ListRolePolicies(ctx, roleName)
	if err != nil {
		return nil, fmt.Errorf("aws: listing inline policies for role %s: %w", roleName, err)
	}

	out := make([]string, 0, len(attached)+len(inline))
	out = append(out, attached...)
	out = append(out, inline...)
	return out, nil
}

// urlDecodeIfNeeded percent-decodes an IAM policy document when the API
// returned it URL-encoded (the raw IAM API does; some SDK paths pre-decode).
// A document that isn't encoded is returned unchanged.
func urlDecodeIfNeeded(doc string) (string, error) {
	if !strings.Contains(doc, "%") {
		return doc, nil
	}
	return url.QueryUnescape(doc)
}
