// Package azure provides Azure lifecycle provider implementation.
package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/anirudhbiyani/cloud-auth/pkg/cloudauth"
)

// Provider implements cloudauth.LifecycleProvider for Azure.
type Provider struct {
	graphClient GraphClient
	armClient   ARMClient
	tokenClient TokenClient
}

// TokenClient abstracts Azure token acquisition operations.
type TokenClient interface {
	// ExchangeToken exchanges a federated identity token for an Azure AD token.
	ExchangeToken(ctx context.Context, input *ExchangeTokenInput) (*ExchangeTokenOutput, error)
	// GetManagedIdentityToken gets an access token from the Azure Instance Metadata Service.
	GetManagedIdentityToken(ctx context.Context, input *GetManagedIdentityTokenInput) (*GetManagedIdentityTokenOutput, error)
}

// GetManagedIdentityTokenInput contains parameters for getting a managed identity token.
type GetManagedIdentityTokenInput struct {
	// Resource is the Azure resource to get a token for.
	Resource string
	// ClientID is the client ID of a user-assigned managed identity (optional).
	ClientID string
}

// GetManagedIdentityTokenOutput contains the managed identity token.
type GetManagedIdentityTokenOutput struct {
	AccessToken  string
	ExpiresOn    time.Time
	Resource     string
	TokenType    string
	ClientID     string
}

// CrossCloudTokenOutput contains a token that can be used for cross-cloud authentication.
type CrossCloudTokenOutput struct {
	// Token is the token value (JWT for OIDC).
	Token string
	// TokenType describes the type of token.
	TokenType string
	// Audience is the intended audience for the token.
	Audience string
	// ExpiresAt is when the token expires.
	ExpiresAt time.Time
	// Issuer is the token issuer.
	Issuer string
}

// AWSRoleAssumptionInput contains parameters for generating a token for AWS role assumption.
type AWSRoleAssumptionInput struct {
	// TenantID is the Azure AD tenant ID.
	TenantID string
	// ClientID is the Azure AD application or managed identity client ID.
	ClientID string
	// RoleARN is the AWS IAM role ARN to assume.
	RoleARN string
	// UseManagedIdentity if true, uses Azure managed identity instead of app registration.
	UseManagedIdentity bool
}

// GCPWorkloadIdentityInput contains parameters for generating a token for GCP WIF.
type GCPWorkloadIdentityInput struct {
	// TenantID is the Azure AD tenant ID.
	TenantID string
	// ClientID is the Azure AD application or managed identity client ID.
	ClientID string
	// ProjectNumber is the GCP project number.
	ProjectNumber string
	// PoolID is the Workload Identity Pool ID.
	PoolID string
	// ProviderID is the provider ID within the pool.
	ProviderID string
	// UseManagedIdentity if true, uses Azure managed identity instead of app registration.
	UseManagedIdentity bool
}

// ExchangeTokenInput contains parameters for Azure AD token exchange.
type ExchangeTokenInput struct {
	// TenantID is the Azure AD tenant ID.
	TenantID string
	// ClientID is the client/application ID of the Azure AD app or managed identity.
	ClientID string
	// FederatedToken is the external identity token (JWT) from the federated IdP.
	FederatedToken string
	// Scope is the resource/scope to request access to.
	// e.g., "https://management.azure.com/.default" or "https://graph.microsoft.com/.default"
	Scope string
	// ClientAssertion is an alternative to FederatedToken for client credential flow.
	ClientAssertion string
	// ClientAssertionType specifies the type of client assertion.
	ClientAssertionType string
}

// ExchangeTokenOutput contains the response from Azure AD token exchange.
type ExchangeTokenOutput struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int // seconds
	ExtExpiresIn int // extended expiry in seconds
	ExpiresOn    time.Time
	Resource     string
}

// GraphClient abstracts Microsoft Graph API operations.
type GraphClient interface {
	// Application operations
	GetApplication(ctx context.Context, id string) (*Application, error)
	CreateApplication(ctx context.Context, app *Application) (*Application, error)
	UpdateApplication(ctx context.Context, id string, app *Application) error
	DeleteApplication(ctx context.Context, id string) error
	ListApplications(ctx context.Context) ([]*Application, error)

	// Service Principal operations
	GetServicePrincipal(ctx context.Context, id string) (*ServicePrincipal, error)
	CreateServicePrincipal(ctx context.Context, appID string) (*ServicePrincipal, error)
	DeleteServicePrincipal(ctx context.Context, id string) error

	// Federated Identity Credential operations
	GetFederatedIdentityCredential(ctx context.Context, appID, credentialID string) (*FederatedIdentityCredential, error)
	CreateFederatedIdentityCredential(ctx context.Context, appID string, cred *FederatedIdentityCredential) (*FederatedIdentityCredential, error)
	DeleteFederatedIdentityCredential(ctx context.Context, appID, credentialID string) error
	ListFederatedIdentityCredentials(ctx context.Context, appID string) ([]*FederatedIdentityCredential, error)
}

// ARMClient abstracts Azure Resource Manager operations.
type ARMClient interface {
	// Managed Identity operations
	GetManagedIdentity(ctx context.Context, subscriptionID, resourceGroup, name string) (*ManagedIdentity, error)
	CreateManagedIdentity(ctx context.Context, subscriptionID, resourceGroup, name, location string) (*ManagedIdentity, error)
	DeleteManagedIdentity(ctx context.Context, subscriptionID, resourceGroup, name string) error

	// Role Assignment operations
	CreateRoleAssignment(ctx context.Context, scope, roleDefinitionID, principalID string) error
	DeleteRoleAssignment(ctx context.Context, scope, roleAssignmentID string) error
	ListRoleAssignments(ctx context.Context, scope, principalID string) ([]*RoleAssignment, error)

	// Federated Credential for Managed Identity
	GetManagedIdentityFederatedCredential(ctx context.Context, subscriptionID, resourceGroup, identityName, credentialName string) (*FederatedIdentityCredential, error)
	CreateManagedIdentityFederatedCredential(ctx context.Context, subscriptionID, resourceGroup, identityName string, cred *FederatedIdentityCredential) (*FederatedIdentityCredential, error)
	DeleteManagedIdentityFederatedCredential(ctx context.Context, subscriptionID, resourceGroup, identityName, credentialName string) error
}

// Application represents an Azure AD application registration.
type Application struct {
	ID                   string
	AppID                string
	DisplayName          string
	IdentifierUris       []string
	SignInAudience       string
	FederatedCredentials []*FederatedIdentityCredential
}

// ServicePrincipal represents an Azure AD service principal.
type ServicePrincipal struct {
	ID          string
	AppID       string
	DisplayName string
	ObjectID    string
}

// FederatedIdentityCredential represents a federated identity credential.
type FederatedIdentityCredential struct {
	ID          string
	Name        string
	Issuer      string
	Subject     string
	Audiences   []string
	Description string
}

// ManagedIdentity represents an Azure managed identity.
type ManagedIdentity struct {
	ID           string
	Name         string
	PrincipalID  string
	ClientID     string
	TenantID     string
	Location     string
	ResourceGroup string
}

// RoleAssignment represents an Azure RBAC role assignment.
type RoleAssignment struct {
	ID               string
	RoleDefinitionID string
	PrincipalID      string
	Scope            string
}

// ProviderOption configures the Provider.
type ProviderOption func(*Provider)

// WithGraphClient sets the Graph client.
func WithGraphClient(client GraphClient) ProviderOption {
	return func(p *Provider) {
		p.graphClient = client
	}
}

// WithARMClient sets the ARM client.
func WithARMClient(client ARMClient) ProviderOption {
	return func(p *Provider) {
		p.armClient = client
	}
}

// WithTokenClient sets the token client for credential acquisition.
func WithTokenClient(client TokenClient) ProviderOption {
	return func(p *Provider) {
		p.tokenClient = client
	}
}

// New creates a new Azure provider.
func New(opts ...ProviderOption) *Provider {
	p := &Provider{}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Name implements cloudauth.Provider.
func (p *Provider) Name() cloudauth.CloudProvider {
	return cloudauth.ProviderAzure
}

// Capabilities implements cloudauth.Provider.
func (p *Provider) Capabilities() []cloudauth.Capability {
	return []cloudauth.Capability{
		cloudauth.CapabilityToken,
		cloudauth.CapabilitySetup,
		cloudauth.CapabilityValidate,
		cloudauth.CapabilityDelete,
		cloudauth.CapabilityDryRun,
		cloudauth.CapabilityFederationOIDC,
	}
}

// HasCapability implements cloudauth.Provider.
func (p *Provider) HasCapability(cap cloudauth.Capability) bool {
	for _, c := range p.Capabilities() {
		if c == cap {
			return true
		}
	}
	return false
}

// Setup implements cloudauth.LifecycleProvider.
func (p *Provider) Setup(ctx context.Context, spec cloudauth.MechanismSpec, opts cloudauth.SetupOptions) (*cloudauth.Outputs, error) {
	switch s := spec.(type) {
	case *cloudauth.AzureFederatedCredentialSpec:
		return p.setupFederatedCredential(ctx, s, opts)
	default:
		return nil, cloudauth.ErrValidation(fmt.Sprintf("unsupported spec type: %T", spec)).
			WithProvider(cloudauth.ProviderAzure)
	}
}

func (p *Provider) setupFederatedCredential(ctx context.Context, spec *cloudauth.AzureFederatedCredentialSpec, opts cloudauth.SetupOptions) (*cloudauth.Outputs, error) {
	var plan cloudauth.Plan
	resourceIDs := make(map[string]string)

	switch spec.IdentityType {
	case "app_registration":
		return p.setupAppRegistrationFederated(ctx, spec, opts, &plan, resourceIDs)
	case "managed_identity":
		return p.setupManagedIdentityFederated(ctx, spec, opts, &plan, resourceIDs)
	default:
		return nil, cloudauth.ErrValidation("invalid identity_type")
	}
}

func (p *Provider) setupAppRegistrationFederated(ctx context.Context, spec *cloudauth.AzureFederatedCredentialSpec, opts cloudauth.SetupOptions, plan *cloudauth.Plan, resourceIDs map[string]string) (*cloudauth.Outputs, error) {
	var appID string
	var appObjectID string
	var createdApp bool

	// Step 1: Get or create application
	if spec.ApplicationID != "" {
		if p.graphClient != nil {
			app, err := p.graphClient.GetApplication(ctx, spec.ApplicationID)
			if err != nil {
				return nil, cloudauth.ErrNotFound("application", spec.ApplicationID).WithCause(err)
			}
			appID = app.AppID
			appObjectID = app.ID
		} else {
			appID = spec.ApplicationID
			appObjectID = spec.ApplicationID
		}
	} else if spec.ApplicationDisplayName != "" {
		// Create new application
		action := cloudauth.PlannedAction{
			Operation:    "create",
			ResourceType: "application",
			Details:      map[string]interface{}{"display_name": spec.ApplicationDisplayName},
			Reversible:   true,
		}
		plan.Actions = append(plan.Actions, action)

		if !opts.DryRun {
			if p.graphClient == nil {
				return nil, cloudauth.ErrValidation("Azure Graph client not configured").
					WithProvider(cloudauth.ProviderAzure).
					WithDetail("hint", "Configure Azure credentials or use --dry-run")
			}

			app, err := p.graphClient.CreateApplication(ctx, &Application{
				DisplayName:    spec.ApplicationDisplayName,
				SignInAudience: "AzureADMyOrg",
			})
			if err != nil {
				return nil, cloudauth.ErrPermission("failed to create application").
					WithCause(err).WithProvider(cloudauth.ProviderAzure)
			}
			appID = app.AppID
			appObjectID = app.ID
			createdApp = true
		}
	}

	resourceIDs["app_id"] = appID
	resourceIDs["app_object_id"] = appObjectID
	resourceIDs["tenant_id"] = spec.TenantID

	// Step 2: Create service principal if we created the app
	if createdApp && !opts.DryRun {
		action := cloudauth.PlannedAction{
			Operation:    "create",
			ResourceType: "service-principal",
			Details:      map[string]interface{}{"app_id": appID},
			Reversible:   true,
		}
		plan.Actions = append(plan.Actions, action)

		sp, err := p.graphClient.CreateServicePrincipal(ctx, appID)
		if err != nil {
			// Rollback: delete application
			_ = p.graphClient.DeleteApplication(ctx, appObjectID)
			return nil, cloudauth.ErrPermission("failed to create service principal").
				WithCause(err).WithProvider(cloudauth.ProviderAzure)
		}
		resourceIDs["service_principal_id"] = sp.ID
	}

	// Step 3: Add federated identity credential
	action := cloudauth.PlannedAction{
		Operation:    "create",
		ResourceType: "federated-identity-credential",
		Details: map[string]interface{}{
			"name":    spec.FederatedCredentialName,
			"issuer":  spec.Issuer,
			"subject": spec.Subject,
		},
		Reversible: true,
	}
	plan.Actions = append(plan.Actions, action)

	if !opts.DryRun {
		audiences := spec.Audiences
		if len(audiences) == 0 {
			audiences = []string{"api://AzureADTokenExchange"}
		}

		cred, err := p.graphClient.CreateFederatedIdentityCredential(ctx, appObjectID, &FederatedIdentityCredential{
			Name:        spec.FederatedCredentialName,
			Issuer:      spec.Issuer,
			Subject:     spec.Subject,
			Audiences:   audiences,
			Description: "Created by cloud-auth",
		})
		if err != nil {
			// Rollback if we created the app
			if createdApp {
				_ = p.graphClient.DeleteApplication(ctx, appObjectID)
			}
			return nil, cloudauth.ErrPermission("failed to create federated credential").
				WithCause(err).WithProvider(cloudauth.ProviderAzure)
		}
		resourceIDs["federated_credential_id"] = cred.ID
	}

	// Step 4: Create role assignments if specified
	for _, ra := range spec.RoleAssignments {
		action := cloudauth.PlannedAction{
			Operation:    "create",
			ResourceType: "role-assignment",
			Details: map[string]interface{}{
				"role":  ra.RoleDefinitionID,
				"scope": ra.Scope,
			},
			Reversible: true,
		}
		plan.Actions = append(plan.Actions, action)

		if !opts.DryRun {
			spID := resourceIDs["service_principal_id"]
			if spID != "" {
				if err := p.armClient.CreateRoleAssignment(ctx, ra.Scope, ra.RoleDefinitionID, spID); err != nil {
					// Log warning but don't fail
					fmt.Printf("warning: failed to create role assignment: %v\n", err)
				}
			}
		}
	}

	ref := cloudauth.CreateMechanismRef(cloudauth.MechanismAzureFederatedCredential, cloudauth.ProviderAzure, resourceIDs)
	ref.Owned = createdApp // Only owned if we created the app

	if opts.DryRun {
		plan.Summary = fmt.Sprintf("Would create/update %d resources for Azure federated credential", len(plan.Actions))
		return &cloudauth.Outputs{
			Ref: ref,
			Values: map[string]string{
				"plan": plan.Summary,
			},
		}, nil
	}

	return &cloudauth.Outputs{
		Ref: ref,
		Values: map[string]string{
			"app_id":                    appID,
			"tenant_id":                 spec.TenantID,
			"federated_credential_name": spec.FederatedCredentialName,
		},
	}, nil
}

func (p *Provider) setupManagedIdentityFederated(ctx context.Context, spec *cloudauth.AzureFederatedCredentialSpec, opts cloudauth.SetupOptions, plan *cloudauth.Plan, resourceIDs map[string]string) (*cloudauth.Outputs, error) {
	var createdIdentity bool

	// Step 1: Get or create managed identity
	var mi *ManagedIdentity
	var identityExists bool
	if p.armClient != nil {
		var err error
		mi, err = p.armClient.GetManagedIdentity(ctx, spec.SubscriptionID, spec.ResourceGroup, spec.ManagedIdentityName)
		identityExists = err == nil
	}

	if !identityExists && spec.CreateManagedIdentity {
		action := cloudauth.PlannedAction{
			Operation:    "create",
			ResourceType: "managed-identity",
			Details: map[string]interface{}{
				"name":           spec.ManagedIdentityName,
				"resource_group": spec.ResourceGroup,
			},
			Reversible: true,
		}
		plan.Actions = append(plan.Actions, action)

		if !opts.DryRun {
			if p.armClient == nil {
				return nil, cloudauth.ErrValidation("Azure ARM client not configured").
					WithProvider(cloudauth.ProviderAzure).
					WithDetail("hint", "Configure Azure credentials or use --dry-run")
			}

			// Default to eastus, should be configurable
			var err error
			mi, err = p.armClient.CreateManagedIdentity(ctx, spec.SubscriptionID, spec.ResourceGroup, spec.ManagedIdentityName, "eastus")
			if err != nil {
				return nil, cloudauth.ErrPermission("failed to create managed identity").
					WithCause(err).WithProvider(cloudauth.ProviderAzure)
			}
			createdIdentity = true
		}
	} else if !identityExists && p.armClient != nil {
		return nil, cloudauth.ErrNotFound("managed-identity", spec.ManagedIdentityName)
	}

	if mi != nil {
		resourceIDs["managed_identity_id"] = mi.ID
		resourceIDs["client_id"] = mi.ClientID
		resourceIDs["principal_id"] = mi.PrincipalID
	}
	resourceIDs["tenant_id"] = spec.TenantID
	resourceIDs["subscription_id"] = spec.SubscriptionID
	resourceIDs["resource_group"] = spec.ResourceGroup
	resourceIDs["identity_name"] = spec.ManagedIdentityName

	// Step 2: Add federated credential
	action := cloudauth.PlannedAction{
		Operation:    "create",
		ResourceType: "federated-identity-credential",
		Details: map[string]interface{}{
			"name":    spec.FederatedCredentialName,
			"issuer":  spec.Issuer,
			"subject": spec.Subject,
		},
		Reversible: true,
	}
	plan.Actions = append(plan.Actions, action)

	if !opts.DryRun {
		audiences := spec.Audiences
		if len(audiences) == 0 {
			audiences = []string{"api://AzureADTokenExchange"}
		}

		cred, err := p.armClient.CreateManagedIdentityFederatedCredential(ctx,
			spec.SubscriptionID, spec.ResourceGroup, spec.ManagedIdentityName,
			&FederatedIdentityCredential{
				Name:      spec.FederatedCredentialName,
				Issuer:    spec.Issuer,
				Subject:   spec.Subject,
				Audiences: audiences,
			})
		if err != nil {
			if createdIdentity {
				_ = p.armClient.DeleteManagedIdentity(ctx, spec.SubscriptionID, spec.ResourceGroup, spec.ManagedIdentityName)
			}
			return nil, cloudauth.ErrPermission("failed to create federated credential").
				WithCause(err).WithProvider(cloudauth.ProviderAzure)
		}
		resourceIDs["federated_credential_id"] = cred.ID
	}

	// Step 3: Create role assignments
	for _, ra := range spec.RoleAssignments {
		action := cloudauth.PlannedAction{
			Operation:    "create",
			ResourceType: "role-assignment",
			Details: map[string]interface{}{
				"role":  ra.RoleDefinitionID,
				"scope": ra.Scope,
			},
			Reversible: true,
		}
		plan.Actions = append(plan.Actions, action)

		if !opts.DryRun && mi != nil {
			if err := p.armClient.CreateRoleAssignment(ctx, ra.Scope, ra.RoleDefinitionID, mi.PrincipalID); err != nil {
				fmt.Printf("warning: failed to create role assignment: %v\n", err)
			}
		}
	}

	ref := cloudauth.CreateMechanismRef(cloudauth.MechanismAzureFederatedCredential, cloudauth.ProviderAzure, resourceIDs)
	ref.Owned = createdIdentity

	if opts.DryRun {
		plan.Summary = fmt.Sprintf("Would create/update %d resources for Azure federated credential", len(plan.Actions))
		return &cloudauth.Outputs{
			Ref: ref,
			Values: map[string]string{
				"plan": plan.Summary,
			},
		}, nil
	}

	return &cloudauth.Outputs{
		Ref: ref,
		Values: map[string]string{
			"client_id":                 mi.ClientID,
			"tenant_id":                 spec.TenantID,
			"federated_credential_name": spec.FederatedCredentialName,
		},
	}, nil
}

// Validate implements cloudauth.LifecycleProvider.
func (p *Provider) Validate(ctx context.Context, ref cloudauth.MechanismRef, opts cloudauth.ValidateOptions) (*cloudauth.ValidationReport, error) {
	var validators []cloudauth.Validator

	switch ref.Type {
	case cloudauth.MechanismAzureFederatedCredential:
		if appID := ref.ResourceIDs["app_object_id"]; appID != "" {
			validators = append(validators, &appExistsValidator{client: p.graphClient, appID: appID})
			
			if credID := ref.ResourceIDs["federated_credential_id"]; credID != "" {
				validators = append(validators, &federatedCredentialExistsValidator{
					client: p.graphClient,
					appID:  appID,
					credID: credID,
				})
			}
		}

		if identityName := ref.ResourceIDs["identity_name"]; identityName != "" {
			validators = append(validators, &managedIdentityExistsValidator{
				client:         p.armClient,
				subscriptionID: ref.ResourceIDs["subscription_id"],
				resourceGroup:  ref.ResourceIDs["resource_group"],
				identityName:   identityName,
			})
		}
	}

	report := cloudauth.RunValidation(ctx, ref, validators)
	return report, nil
}

// Delete implements cloudauth.LifecycleProvider.
func (p *Provider) Delete(ctx context.Context, ref cloudauth.MechanismRef, opts cloudauth.DeleteOptions) error {
	if opts.DryRun {
		return nil
	}

	switch ref.Type {
	case cloudauth.MechanismAzureFederatedCredential:
		// Delete federated credential first
		if appID := ref.ResourceIDs["app_object_id"]; appID != "" {
			if credID := ref.ResourceIDs["federated_credential_id"]; credID != "" {
				if err := p.graphClient.DeleteFederatedIdentityCredential(ctx, appID, credID); err != nil {
					if !isNotFoundError(err) {
						return cloudauth.ErrPermission("failed to delete federated credential").WithCause(err)
					}
				}
			}

			// Delete application if owned
			if ref.Owned {
				if err := p.graphClient.DeleteApplication(ctx, appID); err != nil {
					if !isNotFoundError(err) {
						return cloudauth.ErrPermission("failed to delete application").WithCause(err)
					}
				}
			}
		}

		// For managed identity
		if identityName := ref.ResourceIDs["identity_name"]; identityName != "" {
			if credName := ref.ResourceIDs["federated_credential_name"]; credName != "" {
				err := p.armClient.DeleteManagedIdentityFederatedCredential(ctx,
					ref.ResourceIDs["subscription_id"],
					ref.ResourceIDs["resource_group"],
					identityName, credName)
				if err != nil && !isNotFoundError(err) {
					return cloudauth.ErrPermission("failed to delete federated credential").WithCause(err)
				}
			}

			// Delete managed identity if owned
			if ref.Owned {
				err := p.armClient.DeleteManagedIdentity(ctx,
					ref.ResourceIDs["subscription_id"],
					ref.ResourceIDs["resource_group"],
					identityName)
				if err != nil && !isNotFoundError(err) {
					return cloudauth.ErrPermission("failed to delete managed identity").WithCause(err)
				}
			}
		}
	}

	return nil
}

// Token implements cloudauth.TokenProvider.
// It exchanges a federated identity token (from an external IdP) for an Azure AD access token.
//
// TokenRequest fields:
//   - TargetIdentity: The Azure AD client/application ID or managed identity client ID (required)
//   - SourceIdentity: The federated identity token (JWT) from the external IdP (required)
//   - Audience: The tenant ID for Azure AD (required)
//   - Scopes: The Azure resource scopes to request (optional, defaults to ARM management)
//   - Duration: Not used (Azure controls token lifetime)
//
// The token exchange uses the OAuth 2.0 client credentials flow with federated credentials:
//
//	POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
//	grant_type=client_credentials
//	client_id={client_id}
//	client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
//	client_assertion={federated_token}
//	scope={scope}
func (p *Provider) Token(ctx context.Context, req cloudauth.TokenRequest) (*cloudauth.TokenResponse, error) {
	if p.tokenClient == nil {
		return nil, cloudauth.ErrValidation("Azure token client not configured").
			WithProvider(cloudauth.ProviderAzure).
			WithDetail("hint", "Configure Azure token client using WithTokenClient option")
	}

	// Validate required fields
	if req.TargetIdentity == "" {
		return nil, cloudauth.ErrValidation("TargetIdentity (client ID) is required").
			WithProvider(cloudauth.ProviderAzure)
	}

	if req.Audience == "" {
		return nil, cloudauth.ErrValidation("Audience (tenant ID) is required").
			WithProvider(cloudauth.ProviderAzure)
	}

	// The federated token should be passed via SourceIdentity
	federatedToken := req.SourceIdentity
	if federatedToken == "" {
		return nil, cloudauth.ErrValidation("SourceIdentity (federated token) is required").
			WithProvider(cloudauth.ProviderAzure).
			WithDetail("hint", "Pass the external IdP's JWT token in SourceIdentity field")
	}

	// Build scope from request scopes or use default
	scope := "https://management.azure.com/.default"
	if len(req.Scopes) > 0 {
		// Azure expects space-separated scopes
		scope = ""
		for i, s := range req.Scopes {
			if i > 0 {
				scope += " "
			}
			scope += s
		}
	}

	// Exchange the federated token for an Azure AD token
	input := &ExchangeTokenInput{
		TenantID:            req.Audience,
		ClientID:            req.TargetIdentity,
		FederatedToken:      federatedToken,
		Scope:               scope,
		ClientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
	}

	output, err := p.tokenClient.ExchangeToken(ctx, input)
	if err != nil {
		return nil, cloudauth.ErrAuth("failed to exchange federated token for Azure AD token").
			WithCause(err).
			WithProvider(cloudauth.ProviderAzure).
			WithResource("application", req.TargetIdentity)
	}

	// Build response with token details
	credentials := map[string]interface{}{
		"access_token": output.AccessToken,
		"token_type":   output.TokenType,
		"expires_in":   output.ExpiresIn,
		"expires_on":   output.ExpiresOn.Format(time.RFC3339),
		"resource":     output.Resource,
		"tenant_id":    req.Audience,
		"client_id":    req.TargetIdentity,
	}

	credentialsJSON, err := json.Marshal(credentials)
	if err != nil {
		return nil, cloudauth.ErrInternal("failed to marshal credentials").WithCause(err)
	}

	return &cloudauth.TokenResponse{
		Token:     string(credentialsJSON),
		ExpiresAt: output.ExpiresOn.Unix(),
		TokenType: output.TokenType,
		Scopes:    req.Scopes,
	}, nil
}

// GenerateAWSRoleAssumptionToken creates an OIDC identity token that can be used
// to assume an AWS IAM role via AssumeRoleWithWebIdentity.
//
// This enables Azure workloads to authenticate to AWS without using long-lived credentials.
// The token is obtained from Azure AD and can be validated by AWS.
//
// Prerequisites:
//   - AWS IAM role must trust the Azure AD OIDC issuer
//     (https://login.microsoftonline.com/{tenant_id}/v2.0 or https://sts.windows.net/{tenant_id}/)
//   - The Azure AD app must be configured with the correct audience for AWS
//
// Usage:
//
//	token, err := azureProvider.GenerateAWSRoleAssumptionToken(ctx, &AWSRoleAssumptionInput{
//	    TenantID: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
//	    ClientID: "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
//	    RoleARN:  "arn:aws:iam::123456789012:role/MyRole",
//	})
//	// Use token.Token with AWS provider's Token() method
func (p *Provider) GenerateAWSRoleAssumptionToken(ctx context.Context, input *AWSRoleAssumptionInput) (*CrossCloudTokenOutput, error) {
	if p.tokenClient == nil {
		return nil, cloudauth.ErrValidation("Azure token client not configured").
			WithProvider(cloudauth.ProviderAzure).
			WithDetail("hint", "Configure Azure token client using WithTokenClient option")
	}

	// Validate input
	if input.TenantID == "" {
		return nil, cloudauth.ErrValidation("TenantID is required").WithProvider(cloudauth.ProviderAzure)
	}
	if input.ClientID == "" {
		return nil, cloudauth.ErrValidation("ClientID is required").WithProvider(cloudauth.ProviderAzure)
	}
	if input.RoleARN == "" {
		return nil, cloudauth.ErrValidation("RoleARN is required").WithProvider(cloudauth.ProviderAzure)
	}

	// For AWS, we need to get a token with AWS STS as the audience
	// AWS expects the audience to be "sts.amazonaws.com"
	audience := "sts.amazonaws.com"

	var token string
	var expiresAt time.Time

	if input.UseManagedIdentity {
		// Get token from managed identity
		miTokenInput := &GetManagedIdentityTokenInput{
			Resource: audience,
			ClientID: input.ClientID,
		}

		miTokenOutput, err := p.tokenClient.GetManagedIdentityToken(ctx, miTokenInput)
		if err != nil {
			return nil, cloudauth.ErrAuth("failed to get managed identity token for AWS").
				WithCause(err).
				WithProvider(cloudauth.ProviderAzure)
		}

		token = miTokenOutput.AccessToken
		expiresAt = miTokenOutput.ExpiresOn
	} else {
		// For app registrations, we would need to use a different flow
		// Since we don't have the app secret, we need to be running in a context
		// where we can get an identity token (e.g., Azure Functions, AKS with workload identity)
		return nil, cloudauth.ErrValidation("App registration token generation requires running in an Azure environment with workload identity").
			WithProvider(cloudauth.ProviderAzure).
			WithDetail("hint", "Set UseManagedIdentity=true when running on Azure, or use workload identity federation")
	}

	return &CrossCloudTokenOutput{
		Token:     token,
		TokenType: "urn:ietf:params:oauth:token-type:jwt",
		Audience:  audience,
		ExpiresAt: expiresAt,
		Issuer:    fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", input.TenantID),
	}, nil
}

// GenerateGCPWorkloadIdentityToken creates an OIDC identity token that can be used
// with GCP Workload Identity Federation.
//
// This enables Azure workloads to authenticate to GCP without using long-lived credentials.
// The token is obtained from Azure AD and can be validated by GCP.
//
// Prerequisites:
//   - GCP Workload Identity Pool must have a provider configured to trust Azure AD
//   - The OIDC provider should be configured with issuer: https://login.microsoftonline.com/{tenant_id}/v2.0
//
// Usage:
//
//	token, err := azureProvider.GenerateGCPWorkloadIdentityToken(ctx, &GCPWorkloadIdentityInput{
//	    TenantID:      "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
//	    ClientID:      "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
//	    ProjectNumber: "123456789012",
//	    PoolID:        "my-pool",
//	    ProviderID:    "azure-provider",
//	})
//	// Use token.Token with GCP provider's Token() method
func (p *Provider) GenerateGCPWorkloadIdentityToken(ctx context.Context, input *GCPWorkloadIdentityInput) (*CrossCloudTokenOutput, error) {
	if p.tokenClient == nil {
		return nil, cloudauth.ErrValidation("Azure token client not configured").
			WithProvider(cloudauth.ProviderAzure).
			WithDetail("hint", "Configure Azure token client using WithTokenClient option")
	}

	// Validate input
	if input.TenantID == "" {
		return nil, cloudauth.ErrValidation("TenantID is required").WithProvider(cloudauth.ProviderAzure)
	}
	if input.ClientID == "" {
		return nil, cloudauth.ErrValidation("ClientID is required").WithProvider(cloudauth.ProviderAzure)
	}
	if input.ProjectNumber == "" {
		return nil, cloudauth.ErrValidation("ProjectNumber is required").WithProvider(cloudauth.ProviderAzure)
	}
	if input.PoolID == "" {
		return nil, cloudauth.ErrValidation("PoolID is required").WithProvider(cloudauth.ProviderAzure)
	}
	if input.ProviderID == "" {
		return nil, cloudauth.ErrValidation("ProviderID is required").WithProvider(cloudauth.ProviderAzure)
	}

	// Build the GCP audience (full resource name of the WIF provider)
	audience := fmt.Sprintf("//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s",
		input.ProjectNumber, input.PoolID, input.ProviderID)

	var token string
	var expiresAt time.Time

	if input.UseManagedIdentity {
		// Get token from managed identity
		miTokenInput := &GetManagedIdentityTokenInput{
			Resource: audience,
			ClientID: input.ClientID,
		}

		miTokenOutput, err := p.tokenClient.GetManagedIdentityToken(ctx, miTokenInput)
		if err != nil {
			return nil, cloudauth.ErrAuth("failed to get managed identity token for GCP").
				WithCause(err).
				WithProvider(cloudauth.ProviderAzure)
		}

		token = miTokenOutput.AccessToken
		expiresAt = miTokenOutput.ExpiresOn
	} else {
		// For app registrations, similar limitation as AWS
		return nil, cloudauth.ErrValidation("App registration token generation requires running in an Azure environment with workload identity").
			WithProvider(cloudauth.ProviderAzure).
			WithDetail("hint", "Set UseManagedIdentity=true when running on Azure, or use workload identity federation")
	}

	return &CrossCloudTokenOutput{
		Token:     token,
		TokenType: "urn:ietf:params:oauth:token-type:jwt",
		Audience:  audience,
		ExpiresAt: expiresAt,
		Issuer:    fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", input.TenantID),
	}, nil
}

// Helper functions

func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	return cloudauth.IsCategory(err, cloudauth.ErrCategoryNotFound)
}

// Validators

type appExistsValidator struct {
	client GraphClient
	appID  string
}

func (v *appExistsValidator) ID() string          { return "azure_app_exists" }
func (v *appExistsValidator) Name() string        { return "Application Exists" }
func (v *appExistsValidator) Description() string { return "Checks if the Azure AD application exists" }

func (v *appExistsValidator) Validate(ctx context.Context, ref cloudauth.MechanismRef) cloudauth.ValidationCheck {
	check := cloudauth.ValidationCheck{
		ID:          v.ID(),
		Name:        v.Name(),
		Description: v.Description(),
		Severity:    cloudauth.SeverityCritical,
		Evidence:    map[string]interface{}{"app_id": v.appID},
	}

	app, err := v.client.GetApplication(ctx, v.appID)
	if err != nil {
		check.Status = cloudauth.CheckStatusFailed
		check.Evidence["error"] = err.Error()
		check.Remediation = "Create the application or run setup again"
		return check
	}

	check.Status = cloudauth.CheckStatusPassed
	check.Evidence["display_name"] = app.DisplayName
	return check
}

type federatedCredentialExistsValidator struct {
	client GraphClient
	appID  string
	credID string
}

func (v *federatedCredentialExistsValidator) ID() string          { return "azure_federated_cred_exists" }
func (v *federatedCredentialExistsValidator) Name() string        { return "Federated Credential Exists" }
func (v *federatedCredentialExistsValidator) Description() string { return "Checks if the federated credential exists" }

func (v *federatedCredentialExistsValidator) Validate(ctx context.Context, ref cloudauth.MechanismRef) cloudauth.ValidationCheck {
	check := cloudauth.ValidationCheck{
		ID:          v.ID(),
		Name:        v.Name(),
		Description: v.Description(),
		Severity:    cloudauth.SeverityCritical,
		Evidence:    map[string]interface{}{"credential_id": v.credID},
	}

	cred, err := v.client.GetFederatedIdentityCredential(ctx, v.appID, v.credID)
	if err != nil {
		check.Status = cloudauth.CheckStatusFailed
		check.Evidence["error"] = err.Error()
		check.Remediation = "Create the federated credential or run setup again"
		return check
	}

	check.Status = cloudauth.CheckStatusPassed
	check.Evidence["issuer"] = cred.Issuer
	check.Evidence["subject"] = cred.Subject
	return check
}

type managedIdentityExistsValidator struct {
	client         ARMClient
	subscriptionID string
	resourceGroup  string
	identityName   string
}

func (v *managedIdentityExistsValidator) ID() string          { return "azure_mi_exists" }
func (v *managedIdentityExistsValidator) Name() string        { return "Managed Identity Exists" }
func (v *managedIdentityExistsValidator) Description() string { return "Checks if the managed identity exists" }

func (v *managedIdentityExistsValidator) Validate(ctx context.Context, ref cloudauth.MechanismRef) cloudauth.ValidationCheck {
	check := cloudauth.ValidationCheck{
		ID:          v.ID(),
		Name:        v.Name(),
		Description: v.Description(),
		Severity:    cloudauth.SeverityCritical,
		Evidence:    map[string]interface{}{"identity_name": v.identityName},
	}

	mi, err := v.client.GetManagedIdentity(ctx, v.subscriptionID, v.resourceGroup, v.identityName)
	if err != nil {
		check.Status = cloudauth.CheckStatusFailed
		check.Evidence["error"] = err.Error()
		check.Remediation = "Create the managed identity or run setup again"
		return check
	}

	check.Status = cloudauth.CheckStatusPassed
	check.Evidence["client_id"] = mi.ClientID
	check.Evidence["principal_id"] = mi.PrincipalID
	return check
}

func init() {
	// Register with default registry
	cloudauth.Register(New())
}

