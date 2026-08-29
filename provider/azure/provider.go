// Package azure provides Azure lifecycle provider implementation.
package azure

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// Provider implements core.LifecycleProvider for Azure.
type Provider struct {
	mu          sync.Mutex
	graphClient GraphClient
	armClient   ARMClient
	tokenClient TokenClient

	// resolveFailed caches a credential-resolution failure so the second call
	// reports the original cause rather than silently retrying a lookup that
	// will fail the same way.
	resolveFailed error
}

// resolve lazily builds the Graph and ARM clients from DefaultAzureCredential.
//
// Lazily, because init() registers this Provider into the global registry at
// import time, long before anyone has asked to talk to Azure. Building eagerly
// would make every import of this package depend on resolvable credentials.
// Injected clients always win.
func (p *Provider) resolve(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.graphClient != nil && p.armClient != nil && p.tokenClient != nil {
		return nil
	}
	if p.resolveFailed != nil {
		return p.resolveFailed
	}

	clients, err := NewClients(ctx)
	if err != nil {
		p.resolveFailed = err
		return err
	}
	if p.graphClient == nil {
		p.graphClient = clients.Graph
	}
	if p.armClient == nil {
		p.armClient = clients.ARM
	}
	if p.tokenClient == nil {
		p.tokenClient = clients.Token
	}
	return nil
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
	AccessToken string
	ExpiresOn   time.Time
	Resource    string
	TokenType   string
	ClientID    string
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
	ID            string
	Name          string
	PrincipalID   string
	ClientID      string
	TenantID      string
	Location      string
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

// Name implements core.Provider.
func (p *Provider) Name() core.Cloud {
	return core.Azure
}

// Capabilities implements core.Provider.
func (p *Provider) Capabilities() []core.Capability {
	return []core.Capability{
		core.CapabilitySetup,
		core.CapabilityValidate,
		core.CapabilityDelete,
		core.CapabilityDryRun,
		core.CapabilityFederationOIDC,
	}
}

// HasCapability implements core.Provider.
func (p *Provider) HasCapability(cap core.Capability) bool {
	for _, c := range p.Capabilities() {
		if c == cap {
			return true
		}
	}
	return false
}

// requireClients reports whether this provider can talk to Azure at all.
//
// The clients are injected, so an unconfigured Provider is the one init()
// registers. Setup's nil-check only covered the create-application branch: the
// path that fetched an existing application by ID, and the federated-credential
// call after it, dereferenced the nil field and panicked.
func (p *Provider) requireClients(ctx context.Context, needGraph, needARM bool) error {
	if err := p.resolve(ctx); err != nil {
		return core.ErrValidation("could not reach Azure: no usable credentials").
			WithCause(err).
			WithProvider(core.Azure).
			WithDetail("hint", "Run `az login`, or set AZURE_CLIENT_ID/AZURE_TENANT_ID with a federated "+
				"token file or client secret; --dry-run needs no credentials")
	}
	if needGraph && p.graphClient == nil {
		return core.ErrValidation("Azure Graph client not configured").
			WithProvider(core.Azure).
			WithDetail("hint", "Pass azure.WithGraphClient, or use --dry-run")
	}
	if needARM && p.armClient == nil {
		return core.ErrValidation("Azure ARM client not configured").
			WithProvider(core.Azure).
			WithDetail("hint", "Pass azure.WithARMClient, or use --dry-run")
	}
	return nil
}

// Setup implements core.LifecycleProvider.
func (p *Provider) Setup(ctx context.Context, spec core.MechanismSpec, opts core.SetupOptions) (*core.Outputs, error) {
	if !opts.DryRun {
		if err := p.requireClients(ctx, true, false); err != nil {
			return nil, err
		}
	}
	switch s := spec.(type) {
	case *core.AzureFederatedCredentialSpec:
		return p.setupFederatedCredential(ctx, s, opts)
	default:
		return nil, core.ErrValidation(fmt.Sprintf("unsupported spec type: %T", spec)).
			WithProvider(core.Azure)
	}
}

func (p *Provider) setupFederatedCredential(ctx context.Context, spec *core.AzureFederatedCredentialSpec, opts core.SetupOptions) (*core.Outputs, error) {
	var plan core.Plan
	resourceIDs := make(map[string]string)

	switch spec.IdentityType {
	case "app_registration":
		return p.setupAppRegistrationFederated(ctx, spec, opts, &plan, resourceIDs)
	case "managed_identity":
		return p.setupManagedIdentityFederated(ctx, spec, opts, &plan, resourceIDs)
	default:
		return nil, core.ErrValidation("invalid identity_type")
	}
}

func (p *Provider) setupAppRegistrationFederated(ctx context.Context, spec *core.AzureFederatedCredentialSpec, opts core.SetupOptions, plan *core.Plan, resourceIDs map[string]string) (*core.Outputs, error) {
	var appID string
	var appObjectID string
	var createdApp bool

	// Step 1: Get or create application
	if spec.ApplicationID != "" {
		if p.graphClient == nil {
			// The previous fallback assigned spec.ApplicationID to BOTH ids. In
			// Graph those are different identifiers — appId is the client id,
			// id is the object id — and every federated-credential call needs the
			// object id. Guessing one from the other targeted the wrong resource,
			// so resolve it or say we cannot.
			return nil, core.ErrValidation("cannot resolve the application's object id without a Graph client").
				WithProvider(core.Azure).
				WithResource("application", spec.ApplicationID).
				WithDetail("hint", "Pass azure.WithGraphClient, or use --dry-run")
		}
		app, err := p.graphClient.GetApplication(ctx, spec.ApplicationID)
		if err != nil {
			return nil, core.ErrNotFound("application", spec.ApplicationID).WithCause(err)
		}
		appID = app.AppID
		appObjectID = app.ID
		if appObjectID == "" {
			return nil, core.ErrInternal("Graph returned an application with no object id").
				WithResource("application", spec.ApplicationID)
		}
	} else if spec.ApplicationDisplayName != "" {
		// Create new application
		action := core.PlannedAction{
			Operation:    "create",
			ResourceType: "application",
			Details:      map[string]interface{}{"display_name": spec.ApplicationDisplayName},
			Reversible:   true,
		}
		plan.Actions = append(plan.Actions, action)

		if !opts.DryRun {
			if p.graphClient == nil {
				return nil, core.ErrValidation("Azure Graph client not configured").
					WithProvider(core.Azure).
					WithDetail("hint", "Configure Azure credentials or use --dry-run")
			}

			app, err := p.graphClient.CreateApplication(ctx, &Application{
				DisplayName:    spec.ApplicationDisplayName,
				SignInAudience: "AzureADMyOrg",
			})
			if err != nil {
				return nil, core.ErrPermission("failed to create application").
					WithCause(err).WithProvider(core.Azure)
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
		action := core.PlannedAction{
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
			return nil, core.ErrPermission("failed to create service principal").
				WithCause(err).WithProvider(core.Azure)
		}
		resourceIDs["service_principal_id"] = sp.ID
	}

	// Step 3: Add federated identity credential
	action := core.PlannedAction{
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
			return nil, core.ErrPermission("failed to create federated credential").
				WithCause(err).WithProvider(core.Azure)
		}
		resourceIDs["federated_credential_id"] = cred.ID
	}

	// Step 4: Create role assignments if specified.
	//
	// Failures are collected rather than printed: the identity exists and can
	// authenticate, but without these it has none of the permissions the spec
	// asked for, which surfaces later as a confusing authorization error far from
	// its cause. Reported through Outputs.Instructions so the caller learns about
	// it without losing the resource identifiers it needs to finish or clean up.
	var roleAssignmentErrs []error
	for _, ra := range spec.RoleAssignments {
		action := core.PlannedAction{
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
					roleAssignmentErrs = append(roleAssignmentErrs,
						fmt.Errorf("role %s on scope %s: %w", ra.RoleDefinitionID, ra.Scope, err))
				}
			}
		}
	}

	recordExpectedTrust(resourceIDs, spec)

	ref := core.CreateMechanismRef(core.MechanismAzureFederatedCredential, core.Azure, resourceIDs)
	ref.Owned = createdApp // Only owned if we created the app

	instructions := roleAssignmentWarnings(roleAssignmentErrs)

	if opts.DryRun {
		plan.Summary = fmt.Sprintf("Would create/update %d resources for Azure federated credential", len(plan.Actions))
		return &core.Outputs{
			Ref: ref,
			Values: map[string]string{
				"plan": plan.Summary,
			},
		}, nil
	}

	return &core.Outputs{
		Ref: ref,
		Values: map[string]string{
			"app_id":                    appID,
			"tenant_id":                 spec.TenantID,
			"federated_credential_name": spec.FederatedCredentialName,
		},
		Instructions: instructions,
	}, nil
}

// roleAssignmentWarnings renders collected role-assignment failures as
// caller-visible instructions.
//
// Not returned as an error: the federated credential itself was created, and
// failing the whole call would discard the resource identifiers the caller needs
// either to finish the job by hand or to clean up.
func roleAssignmentWarnings(errs []error) []string {
	if len(errs) == 0 {
		return nil
	}
	out := make([]string, 0, len(errs)+1)
	out = append(out, fmt.Sprintf("WARNING: the identity was created but %d role assignment(s) "+
		"failed, so it can authenticate without having the permissions this spec requested:", len(errs)))
	for _, err := range errs {
		out = append(out, "  - "+err.Error())
	}
	return out
}

func (p *Provider) setupManagedIdentityFederated(ctx context.Context, spec *core.AzureFederatedCredentialSpec, opts core.SetupOptions, plan *core.Plan, resourceIDs map[string]string) (*core.Outputs, error) {
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
		action := core.PlannedAction{
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
				return nil, core.ErrValidation("Azure ARM client not configured").
					WithProvider(core.Azure).
					WithDetail("hint", "Configure Azure credentials or use --dry-run")
			}

			// Default to eastus, should be configurable
			var err error
			mi, err = p.armClient.CreateManagedIdentity(ctx, spec.SubscriptionID, spec.ResourceGroup, spec.ManagedIdentityName, "eastus")
			if err != nil {
				return nil, core.ErrPermission("failed to create managed identity").
					WithCause(err).WithProvider(core.Azure)
			}
			createdIdentity = true
		}
	} else if !identityExists && p.armClient != nil {
		return nil, core.ErrNotFound("managed-identity", spec.ManagedIdentityName)
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
	action := core.PlannedAction{
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
			return nil, core.ErrPermission("failed to create federated credential").
				WithCause(err).WithProvider(core.Azure)
		}
		resourceIDs["federated_credential_id"] = cred.ID
	}

	// Step 3: Create role assignments
	// Collected, not printed — see roleAssignmentWarnings.
	var roleAssignmentErrs []error
	for _, ra := range spec.RoleAssignments {
		action := core.PlannedAction{
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
				roleAssignmentErrs = append(roleAssignmentErrs,
					fmt.Errorf("role %s on scope %s: %w", ra.RoleDefinitionID, ra.Scope, err))
			}
		}
	}

	recordExpectedTrust(resourceIDs, spec)

	ref := core.CreateMechanismRef(core.MechanismAzureFederatedCredential, core.Azure, resourceIDs)
	ref.Owned = createdIdentity

	if opts.DryRun {
		plan.Summary = fmt.Sprintf("Would create/update %d resources for Azure federated credential", len(plan.Actions))
		return &core.Outputs{
			Ref: ref,
			Values: map[string]string{
				"plan": plan.Summary,
			},
		}, nil
	}

	return &core.Outputs{
		Ref: ref,
		Values: map[string]string{
			"client_id":                 mi.ClientID,
			"tenant_id":                 spec.TenantID,
			"federated_credential_name": spec.FederatedCredentialName,
		},
		Instructions: roleAssignmentWarnings(roleAssignmentErrs),
	}, nil
}

// Validate implements core.LifecycleProvider.
func (p *Provider) Validate(ctx context.Context, ref core.MechanismRef, opts core.ValidateOptions) (*core.ValidationReport, error) {
	if err := p.requireClients(ctx, true, false); err != nil {
		return nil, err
	}
	var validators []core.Validator

	switch ref.Type {
	case core.MechanismAzureFederatedCredential:
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

		// Compare the live federated identity credential against the recorded
		// intent. Entra's matching is case-sensitive and exact, so a case-only
		// drift is reported explicitly rather than as a generic mismatch.
		expIssuer := ref.ResourceIDs["expected_issuer"]
		expSubject := ref.ResourceIDs["expected_subject"]
		expAudience := ref.ResourceIDs["expected_audience"]
		if expIssuer != "" || expSubject != "" || expAudience != "" {
			validators = append(validators, core.NewTrustPolicyMatchValidator(
				expIssuer, expAudience, expSubject,
				core.WithTrustPolicySource(p)))
		}
	}

	report := core.RunValidation(ctx, ref, validators)
	return report, nil
}

// Delete implements core.LifecycleProvider.
func (p *Provider) Delete(ctx context.Context, ref core.MechanismRef, opts core.DeleteOptions) error {
	if !opts.DryRun {
		if err := p.requireClients(ctx, true, false); err != nil {
			return err
		}
	}
	if opts.DryRun {
		return nil
	}

	switch ref.Type {
	case core.MechanismAzureFederatedCredential:
		// Delete federated credential first
		if appID := ref.ResourceIDs["app_object_id"]; appID != "" {
			if credID := ref.ResourceIDs["federated_credential_id"]; credID != "" {
				if err := p.graphClient.DeleteFederatedIdentityCredential(ctx, appID, credID); err != nil {
					if !isNotFoundError(err) {
						return core.ErrPermission("failed to delete federated credential").WithCause(err)
					}
				}
			}

			// Delete application if owned
			if ref.Owned {
				if err := p.graphClient.DeleteApplication(ctx, appID); err != nil {
					if !isNotFoundError(err) {
						return core.ErrPermission("failed to delete application").WithCause(err)
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
					return core.ErrPermission("failed to delete federated credential").WithCause(err)
				}
			}

			// Delete managed identity if owned
			if ref.Owned {
				err := p.armClient.DeleteManagedIdentity(ctx,
					ref.ResourceIDs["subscription_id"],
					ref.ResourceIDs["resource_group"],
					identityName)
				if err != nil && !isNotFoundError(err) {
					return core.ErrPermission("failed to delete managed identity").WithCause(err)
				}
			}
		}
	}

	return nil
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
		return nil, core.ErrValidation("Azure token client not configured").
			WithProvider(core.Azure).
			WithDetail("hint", "Configure Azure token client using WithTokenClient option")
	}

	// Validate input
	if input.TenantID == "" {
		return nil, core.ErrValidation("TenantID is required").WithProvider(core.Azure)
	}
	if input.ClientID == "" {
		return nil, core.ErrValidation("ClientID is required").WithProvider(core.Azure)
	}
	if input.RoleARN == "" {
		return nil, core.ErrValidation("RoleARN is required").WithProvider(core.Azure)
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
			return nil, core.ErrAuth("failed to get managed identity token for AWS").
				WithCause(err).
				WithProvider(core.Azure)
		}

		token = miTokenOutput.AccessToken
		expiresAt = miTokenOutput.ExpiresOn
	} else {
		// For app registrations, we would need to use a different flow
		// Since we don't have the app secret, we need to be running in a context
		// where we can get an identity token (e.g., Azure Functions, AKS with workload identity)
		return nil, core.ErrValidation("App registration token generation requires running in an Azure environment with workload identity").
			WithProvider(core.Azure).
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
		return nil, core.ErrValidation("Azure token client not configured").
			WithProvider(core.Azure).
			WithDetail("hint", "Configure Azure token client using WithTokenClient option")
	}

	// Validate input
	if input.TenantID == "" {
		return nil, core.ErrValidation("TenantID is required").WithProvider(core.Azure)
	}
	if input.ClientID == "" {
		return nil, core.ErrValidation("ClientID is required").WithProvider(core.Azure)
	}
	if input.ProjectNumber == "" {
		return nil, core.ErrValidation("ProjectNumber is required").WithProvider(core.Azure)
	}
	if input.PoolID == "" {
		return nil, core.ErrValidation("PoolID is required").WithProvider(core.Azure)
	}
	if input.ProviderID == "" {
		return nil, core.ErrValidation("ProviderID is required").WithProvider(core.Azure)
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
			return nil, core.ErrAuth("failed to get managed identity token for GCP").
				WithCause(err).
				WithProvider(core.Azure)
		}

		token = miTokenOutput.AccessToken
		expiresAt = miTokenOutput.ExpiresOn
	} else {
		// For app registrations, similar limitation as AWS
		return nil, core.ErrValidation("App registration token generation requires running in an Azure environment with workload identity").
			WithProvider(core.Azure).
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

// isNotFoundError reports whether err means "the resource is absent", as opposed
// to "we could not tell" — a distinction Setup's create-or-update decision and
// the delete path both depend on. A denied read is NOT evidence of absence.
//
// Both checks are typed. There is deliberately no substring fallback: the client
// in this package returns *apiError carrying Graph's own code, so absence never
// has to be recovered by matching English.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	if core.IsCategory(err, core.ErrCategoryNotFound) {
		return true
	}
	var notFound interface{ NotFound() bool }
	return errors.As(err, &notFound) && notFound.NotFound()
}

// Validators

type appExistsValidator struct {
	client GraphClient
	appID  string
}

func (v *appExistsValidator) ID() string          { return "azure_app_exists" }
func (v *appExistsValidator) Name() string        { return "Application Exists" }
func (v *appExistsValidator) Description() string { return "Checks if the Azure AD application exists" }

func (v *appExistsValidator) Validate(ctx context.Context, ref core.MechanismRef) core.ValidationCheck {
	check := core.ValidationCheck{
		ID:          v.ID(),
		Name:        v.Name(),
		Description: v.Description(),
		Severity:    core.SeverityCritical,
		Evidence:    map[string]interface{}{"app_id": v.appID},
	}

	app, err := v.client.GetApplication(ctx, v.appID)
	if err != nil {
		check.Status = core.CheckStatusFailed
		check.Evidence["error"] = err.Error()
		check.Remediation = "Create the application or run setup again"
		return check
	}

	check.Status = core.CheckStatusPassed
	check.Evidence["display_name"] = app.DisplayName
	return check
}

type federatedCredentialExistsValidator struct {
	client GraphClient
	appID  string
	credID string
}

func (v *federatedCredentialExistsValidator) ID() string   { return "azure_federated_cred_exists" }
func (v *federatedCredentialExistsValidator) Name() string { return "Federated Credential Exists" }
func (v *federatedCredentialExistsValidator) Description() string {
	return "Checks if the federated credential exists"
}

func (v *federatedCredentialExistsValidator) Validate(ctx context.Context, ref core.MechanismRef) core.ValidationCheck {
	check := core.ValidationCheck{
		ID:          v.ID(),
		Name:        v.Name(),
		Description: v.Description(),
		Severity:    core.SeverityCritical,
		Evidence:    map[string]interface{}{"credential_id": v.credID},
	}

	cred, err := v.client.GetFederatedIdentityCredential(ctx, v.appID, v.credID)
	if err != nil {
		check.Status = core.CheckStatusFailed
		check.Evidence["error"] = err.Error()
		check.Remediation = "Create the federated credential or run setup again"
		return check
	}

	check.Status = core.CheckStatusPassed
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

func (v *managedIdentityExistsValidator) ID() string   { return "azure_mi_exists" }
func (v *managedIdentityExistsValidator) Name() string { return "Managed Identity Exists" }
func (v *managedIdentityExistsValidator) Description() string {
	return "Checks if the managed identity exists"
}

func (v *managedIdentityExistsValidator) Validate(ctx context.Context, ref core.MechanismRef) core.ValidationCheck {
	check := core.ValidationCheck{
		ID:          v.ID(),
		Name:        v.Name(),
		Description: v.Description(),
		Severity:    core.SeverityCritical,
		Evidence:    map[string]interface{}{"identity_name": v.identityName},
	}

	mi, err := v.client.GetManagedIdentity(ctx, v.subscriptionID, v.resourceGroup, v.identityName)
	if err != nil {
		check.Status = core.CheckStatusFailed
		check.Evidence["error"] = err.Error()
		check.Remediation = "Create the managed identity or run setup again"
		return check
	}

	check.Status = core.CheckStatusPassed
	check.Evidence["client_id"] = mi.ClientID
	check.Evidence["principal_id"] = mi.PrincipalID
	return check
}

func init() {
	// Register with default registry
	core.Register(New())
}
