package azure

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/google/uuid"
)

// Azure Resource Manager: user-assigned managed identities, their federated
// identity credentials, and role assignments.

// identityResourceID builds the ARM resource id of a user-assigned identity.
func identityResourceID(subscriptionID, resourceGroup, name string) string {
	return fmt.Sprintf(
		"/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ManagedIdentity/userAssignedIdentities/%s",
		url.PathEscape(subscriptionID), url.PathEscape(resourceGroup), url.PathEscape(name))
}

// wireIdentity is the ARM shape of a user-assigned managed identity.
type wireIdentity struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	Location   string `json:"location,omitempty"`
	Properties struct {
		PrincipalID string `json:"principalId,omitempty"`
		ClientID    string `json:"clientId,omitempty"`
		TenantID    string `json:"tenantId,omitempty"`
	} `json:"properties,omitempty"`
}

func (i *wireIdentity) toDomain(resourceGroup string) *ManagedIdentity {
	return &ManagedIdentity{
		ID: i.ID, Name: i.Name, Location: i.Location,
		PrincipalID:   i.Properties.PrincipalID,
		ClientID:      i.Properties.ClientID,
		TenantID:      i.Properties.TenantID,
		ResourceGroup: resourceGroup,
	}
}

// GetManagedIdentity reads a user-assigned managed identity.
func (c *restClient) GetManagedIdentity(ctx context.Context, subscriptionID, resourceGroup, name string) (*ManagedIdentity, error) {
	endpoint := fmt.Sprintf("%s%s?api-version=%s",
		c.armURL, identityResourceID(subscriptionID, resourceGroup, name), armIdentityAPIVersion)
	var out wireIdentity
	if err := c.do(ctx, http.MethodGet, endpoint, armScope, nil, &out, name); err != nil {
		return nil, err
	}
	return out.toDomain(resourceGroup), nil
}

// CreateManagedIdentity creates a user-assigned managed identity.
func (c *restClient) CreateManagedIdentity(ctx context.Context, subscriptionID, resourceGroup, name, location string) (*ManagedIdentity, error) {
	if location == "" {
		return nil, fmt.Errorf("azure: location is required to create a managed identity")
	}
	endpoint := fmt.Sprintf("%s%s?api-version=%s",
		c.armURL, identityResourceID(subscriptionID, resourceGroup, name), armIdentityAPIVersion)
	var out wireIdentity
	body := map[string]any{"location": location}
	if err := c.do(ctx, http.MethodPut, endpoint, armScope, body, &out, name); err != nil {
		return nil, err
	}
	return out.toDomain(resourceGroup), nil
}

// DeleteManagedIdentity deletes a user-assigned managed identity.
func (c *restClient) DeleteManagedIdentity(ctx context.Context, subscriptionID, resourceGroup, name string) error {
	endpoint := fmt.Sprintf("%s%s?api-version=%s",
		c.armURL, identityResourceID(subscriptionID, resourceGroup, name), armIdentityAPIVersion)
	return c.do(ctx, http.MethodDelete, endpoint, armScope, nil, nil, name)
}

// GetManagedIdentityFederatedCredential reads one credential on an identity.
func (c *restClient) GetManagedIdentityFederatedCredential(ctx context.Context, subscriptionID, resourceGroup, identityName, credentialName string) (*FederatedIdentityCredential, error) {
	endpoint := fmt.Sprintf("%s%s/federatedIdentityCredentials/%s?api-version=%s",
		c.armURL, identityResourceID(subscriptionID, resourceGroup, identityName),
		url.PathEscape(credentialName), armIdentityAPIVersion)

	var out struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Properties struct {
			Issuer    string   `json:"issuer"`
			Subject   string   `json:"subject"`
			Audiences []string `json:"audiences"`
		} `json:"properties"`
	}
	if err := c.do(ctx, http.MethodGet, endpoint, armScope, nil, &out, credentialName); err != nil {
		return nil, err
	}
	return &FederatedIdentityCredential{
		ID: out.ID, Name: out.Name,
		Issuer: out.Properties.Issuer, Subject: out.Properties.Subject,
		Audiences: out.Properties.Audiences,
	}, nil
}

// CreateManagedIdentityFederatedCredential adds a credential to an identity.
//
// The 20-credential cap and the creation throttle apply to managed identities
// exactly as they do to applications.
func (c *restClient) CreateManagedIdentityFederatedCredential(ctx context.Context, subscriptionID, resourceGroup, identityName string, cred *FederatedIdentityCredential) (*FederatedIdentityCredential, error) {
	if err := validateFIC(cred); err != nil {
		return nil, err
	}

	existing, err := c.listManagedIdentityFederatedCredentials(ctx, subscriptionID, resourceGroup, identityName)
	if err != nil {
		return nil, fmt.Errorf("azure: counting existing federated credentials: %w", err)
	}
	if err := checkFICCapacity(existing, identityName); err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s%s/federatedIdentityCredentials/%s?api-version=%s",
		c.armURL, identityResourceID(subscriptionID, resourceGroup, identityName),
		url.PathEscape(cred.Name), armIdentityAPIVersion)

	// ARM nests the credential under "properties"; Graph does not.
	body := map[string]any{
		"properties": map[string]any{
			"issuer":    cred.Issuer,
			"subject":   cred.Subject,
			"audiences": cred.Audiences,
		},
	}
	var out struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := c.putFICPaced(ctx, endpoint, body, &out, cred.Name); err != nil {
		return nil, err
	}
	return &FederatedIdentityCredential{
		ID: out.ID, Name: cred.Name, Issuer: cred.Issuer,
		Subject: cred.Subject, Audiences: cred.Audiences,
	}, nil
}

// DeleteManagedIdentityFederatedCredential removes a credential from an identity.
func (c *restClient) DeleteManagedIdentityFederatedCredential(ctx context.Context, subscriptionID, resourceGroup, identityName, credentialName string) error {
	endpoint := fmt.Sprintf("%s%s/federatedIdentityCredentials/%s?api-version=%s",
		c.armURL, identityResourceID(subscriptionID, resourceGroup, identityName),
		url.PathEscape(credentialName), armIdentityAPIVersion)
	return c.do(ctx, http.MethodDelete, endpoint, armScope, nil, nil, credentialName)
}

// listManagedIdentityFederatedCredentials counts the credentials on an identity.
func (c *restClient) listManagedIdentityFederatedCredentials(ctx context.Context, subscriptionID, resourceGroup, identityName string) (int, error) {
	endpoint := fmt.Sprintf("%s%s/federatedIdentityCredentials?api-version=%s",
		c.armURL, identityResourceID(subscriptionID, resourceGroup, identityName), armIdentityAPIVersion)
	var page struct {
		Value []struct {
			Name string `json:"name"`
		} `json:"value"`
	}
	if err := c.do(ctx, http.MethodGet, endpoint, armScope, nil, &page, identityName); err != nil {
		return 0, err
	}
	return len(page.Value), nil
}

// putFICPaced is createFICPaced for ARM, which uses PUT with a nested body.
func (c *restClient) putFICPaced(ctx context.Context, endpoint string, body, out any, name string) error {
	c.ficMu.Lock()
	defer c.ficMu.Unlock()

	if !c.lastFIC.IsZero() {
		if wait := c.ficInterval - c.now().Sub(c.lastFIC); wait > 0 {
			if err := c.sleep(ctx, wait); err != nil {
				return err
			}
		}
	}
	err := c.do(ctx, http.MethodPut, endpoint, armScope, body, out, name)
	c.lastFIC = c.now()
	return err
}

// CreateRoleAssignment grants a role at a scope.
//
// The assignment name is a client-generated GUID, which is what makes this
// idempotent: re-running with the same inputs targets the same assignment and
// Azure answers 409 rather than creating a duplicate grant.
func (c *restClient) CreateRoleAssignment(ctx context.Context, scope, roleDefinitionID, principalID string) error {
	if scope == "" || roleDefinitionID == "" || principalID == "" {
		return fmt.Errorf("azure: scope, role definition and principal are required")
	}
	endpoint := fmt.Sprintf("%s/%s/providers/Microsoft.Authorization/roleAssignments/%s?api-version=%s",
		c.armURL, trimLeadingSlash(scope), uuid.New().String(), armRoleAPIVersion)

	body := map[string]any{
		"properties": map[string]any{
			"roleDefinitionId": roleDefinitionID,
			"principalId":      principalID,
			// Without this ARM rejects a brand-new service principal with
			// "principal does not exist", because directory replication has not
			// caught up with the object that was just created.
			"principalType": "ServicePrincipal",
		},
	}
	err := c.do(ctx, http.MethodPut, endpoint, armScope, body, nil, scope)

	// A 409 here means the grant already exists. That is the desired end state,
	// so it is success — treating it as failure would make setup non-idempotent.
	var apiErr *apiError
	if asAPIError(err, &apiErr) && apiErr.Conflict() {
		return nil
	}
	return err
}

// DeleteRoleAssignment removes a role assignment.
func (c *restClient) DeleteRoleAssignment(ctx context.Context, scope, roleAssignmentID string) error {
	endpoint := fmt.Sprintf("%s/%s/providers/Microsoft.Authorization/roleAssignments/%s?api-version=%s",
		c.armURL, trimLeadingSlash(scope), url.PathEscape(roleAssignmentID), armRoleAPIVersion)
	return c.do(ctx, http.MethodDelete, endpoint, armScope, nil, nil, roleAssignmentID)
}

// ListRoleAssignments lists assignments at a scope, optionally for one principal.
func (c *restClient) ListRoleAssignments(ctx context.Context, scope, principalID string) ([]*RoleAssignment, error) {
	endpoint := fmt.Sprintf("%s/%s/providers/Microsoft.Authorization/roleAssignments?api-version=%s",
		c.armURL, trimLeadingSlash(scope), armRoleAPIVersion)
	if principalID != "" {
		endpoint += "&$filter=" + url.QueryEscape(fmt.Sprintf("principalId eq '%s'", principalID))
	}

	var page struct {
		Value []struct {
			ID         string `json:"id"`
			Properties struct {
				RoleDefinitionID string `json:"roleDefinitionId"`
				PrincipalID      string `json:"principalId"`
				Scope            string `json:"scope"`
			} `json:"properties"`
		} `json:"value"`
	}
	if err := c.do(ctx, http.MethodGet, endpoint, armScope, nil, &page, scope); err != nil {
		return nil, err
	}

	out := make([]*RoleAssignment, 0, len(page.Value))
	for _, a := range page.Value {
		out = append(out, &RoleAssignment{
			ID:               a.ID,
			RoleDefinitionID: a.Properties.RoleDefinitionID,
			PrincipalID:      a.Properties.PrincipalID,
			Scope:            a.Properties.Scope,
		})
	}
	return out, nil
}

// trimLeadingSlash normalizes an ARM scope so it can be joined to the base URL
// without producing a double slash, which ARM answers with a confusing 400.
func trimLeadingSlash(scope string) string {
	for len(scope) > 0 && scope[0] == '/' {
		scope = scope[1:]
	}
	return scope
}
