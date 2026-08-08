package azure

import (
	"context"
	"fmt"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
)

// Implements the cloudauth validation source interfaces so the core's
// trust-policy and permission checks run against live Entra state. cloudauth is
// the leaf package, so the dependency is inverted through these interfaces.
var (
	_ cloudauth.TrustPolicySource   = (*Provider)(nil)
	_ cloudauth.GrantedPolicySource = (*Provider)(nil)
)

// TrustPolicy reads the live federated identity credential.
//
// Azure's FIC maps onto the neutral shape almost exactly — issuer, subject and
// audiences are first-class fields — so no parsing is needed. What matters is
// that Entra matches all three **case-sensitively and exactly**, including
// trailing slashes: values are therefore passed through verbatim, with no
// normalization, so a case-only difference surfaces as a mismatch instead of
// being silently "corrected" here and then failing at exchange time with an
// opaque AADSTS70021.
func (p *Provider) TrustPolicy(ctx context.Context, ref cloudauth.MechanismRef) (*cloudauth.TrustPolicy, error) {
	var (
		cred *FederatedIdentityCredential
		err  error
	)

	switch {
	// App registration path.
	case ref.ResourceIDs["app_object_id"] != "":
		appID := ref.ResourceIDs["app_object_id"]
		credID := ref.ResourceIDs["federated_credential_id"]
		if credID == "" {
			credID = ref.ResourceIDs["federated_credential_name"]
		}
		if credID == "" {
			return nil, fmt.Errorf("azure: mechanism ref %q names an application but no federated credential", ref.ID)
		}
		cred, err = p.graphClient.GetFederatedIdentityCredential(ctx, appID, credID)
		if err != nil {
			return nil, fmt.Errorf("azure: reading federated credential %s on app %s: %w", credID, appID, err)
		}

	// User-assigned managed identity path.
	case ref.ResourceIDs["identity_name"] != "":
		credName := ref.ResourceIDs["federated_credential_name"]
		if credName == "" {
			credName = ref.ResourceIDs["federated_credential_id"]
		}
		if credName == "" {
			return nil, fmt.Errorf("azure: mechanism ref %q names a managed identity but no federated credential", ref.ID)
		}
		cred, err = p.armClient.GetManagedIdentityFederatedCredential(ctx,
			ref.ResourceIDs["subscription_id"],
			ref.ResourceIDs["resource_group"],
			ref.ResourceIDs["identity_name"],
			credName)
		if err != nil {
			return nil, fmt.Errorf("azure: reading federated credential %s on identity %s: %w",
				credName, ref.ResourceIDs["identity_name"], err)
		}

	default:
		return nil, fmt.Errorf("azure: mechanism ref %q identifies neither an app registration "+
			"(app_object_id) nor a user-assigned managed identity (identity_name)", ref.ID)
	}

	if cred == nil {
		return nil, fmt.Errorf("azure: federated credential not found for mechanism %q", ref.ID)
	}

	tp := &cloudauth.TrustPolicy{
		Issuer:    cred.Issuer,
		Audiences: append([]string(nil), cred.Audiences...),
	}
	// A FIC carries exactly one subject; the neutral shape holds a list.
	if cred.Subject != "" {
		tp.Subjects = []string{cred.Subject}
	} else {
		// An empty subject would admit anything the issuer mints; surface it as
		// the wildcard so the core validator fails it as unscoped.
		tp.Subjects = []string{"*"}
	}
	return tp, nil
}

// GrantedPolicies returns the Azure role definitions assigned to the identity.
//
// As on the other providers this checks assignment, not effective permission:
// it catches a role that was removed, not a custom role definition that was
// narrowed.
func (p *Provider) GrantedPolicies(ctx context.Context, ref cloudauth.MechanismRef) ([]string, error) {
	principalID := ref.ResourceIDs["service_principal_id"]
	if principalID == "" {
		principalID = ref.ResourceIDs["principal_id"]
	}
	if principalID == "" {
		return nil, fmt.Errorf("azure: mechanism ref %q has no service principal id; cannot list role assignments", ref.ID)
	}

	// Assignments are listed at subscription scope, which covers the scopes a
	// setup would have granted at or below it.
	scope := ref.ResourceIDs["role_assignment_scope"]
	if scope == "" {
		if sub := ref.ResourceIDs["subscription_id"]; sub != "" {
			scope = "/subscriptions/" + sub
		}
	}
	if scope == "" {
		return nil, fmt.Errorf("azure: mechanism ref %q has no subscription or scope to list role assignments in", ref.ID)
	}

	assignments, err := p.armClient.ListRoleAssignments(ctx, scope, principalID)
	if err != nil {
		return nil, fmt.Errorf("azure: listing role assignments for %s: %w", principalID, err)
	}

	roles := make([]string, 0, len(assignments))
	seen := map[string]bool{}
	for _, a := range assignments {
		if a == nil || a.RoleDefinitionID == "" || seen[a.RoleDefinitionID] {
			continue
		}
		seen[a.RoleDefinitionID] = true
		roles = append(roles, a.RoleDefinitionID)
	}
	return roles, nil
}

// recordExpectedTrust stores the intended issuer/subject/audience on the
// mechanism ref so a later Validate can compare the live federated credential
// against what was configured. Entra matches these case-sensitively, so they
// are stored verbatim with no normalization.
func recordExpectedTrust(resourceIDs map[string]string, spec *cloudauth.AzureFederatedCredentialSpec) {
	if spec == nil {
		return
	}
	if spec.Issuer != "" {
		resourceIDs["expected_issuer"] = spec.Issuer
	}
	if spec.Subject != "" {
		resourceIDs["expected_subject"] = spec.Subject
	}
	if len(spec.Audiences) > 0 {
		resourceIDs["expected_audience"] = spec.Audiences[0]
	}
}
