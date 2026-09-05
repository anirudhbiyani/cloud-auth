// Package gcp provides GCP lifecycle provider implementation.
package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/internal/jwt"
)

// Provider implements core.LifecycleProvider for GCP.
type Provider struct {
	mu        sync.Mutex
	iamClient IAMClient
	wifClient WorkloadIdentityClient
	stsClient STSClient

	// resolveFailed records that Application Default Credentials could not be resolved, so the next call reports the original cause instead of silently retrying a lookup that will fail the same way.
	resolveFailed error
}

// resolve lazily builds the REST clients from Application Default Credentials.
func (p *Provider) resolve(ctx context.Context, needWIF, needIAM bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Resolve only what is actually missing for THIS call.
	if (!needWIF || p.wifClient != nil) && (!needIAM || p.iamClient != nil) {
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
	if p.iamClient == nil {
		p.iamClient = clients.IAM
	}
	if p.wifClient == nil {
		p.wifClient = clients.Workload
	}
	if p.stsClient == nil {
		p.stsClient = clients.STS
	}
	return nil
}

// STSClient abstracts GCP Security Token Service operations for token exchange.
type STSClient interface {
	// ExchangeToken exchanges an external token for a GCP STS token.
	ExchangeToken(ctx context.Context, input *ExchangeTokenInput) (*ExchangeTokenOutput, error)
	// GenerateAccessToken generates an access token for a service account.
	GenerateAccessToken(ctx context.Context, input *GenerateAccessTokenInput) (*GenerateAccessTokenOutput, error)
	// GenerateIDToken generates an OIDC identity token for a service account.
	GenerateIDToken(ctx context.Context, input *GenerateIDTokenInput) (*GenerateIDTokenOutput, error)
}

// GenerateIDTokenInput contains parameters for generating an OIDC identity token.
type GenerateIDTokenInput struct {
	// ServiceAccountEmail is the email of the service account.
	ServiceAccountEmail string
	// Audience is the intended recipient of the token.
	Audience string
	// IncludeEmail if true, includes the service account email in the token.
	IncludeEmail bool
	// Delegates is an optional chain of service accounts for delegation.
	Delegates []string
}

// GenerateIDTokenOutput contains the generated identity token.
type GenerateIDTokenOutput struct {
	// Token is the OIDC identity token (JWT).
	Token string
}

// CrossCloudTokenOutput contains a token that can be used for cross-cloud authentication.
type CrossCloudTokenOutput struct {
	// Token is the token value (JWT for OIDC).
	Token string
	// TokenType describes the type of token (e.g., "urn:ietf:params:oauth:token-type:jwt").
	TokenType string
	// Audience is the intended audience for the token.
	Audience string
	// ExpiresAt is when the token expires.
	ExpiresAt time.Time
	// Issuer is the token issuer (e.g., "https://accounts.google.com").
	Issuer string
}

// AWSRoleAssumptionInput contains parameters for generating a token for AWS role assumption.
type AWSRoleAssumptionInput struct {
	// ServiceAccountEmail is the GCP service account to generate the token for.
	ServiceAccountEmail string
	// RoleARN is the AWS IAM role ARN to assume.
	RoleARN string
	// SessionName is the AWS role session name (optional).
	SessionName string
}

// AzureFederatedTokenInput contains parameters for generating a token for Azure federation.
type AzureFederatedTokenInput struct {
	// ServiceAccountEmail is the GCP service account to generate the token for.
	ServiceAccountEmail string
	// TenantID is the Azure AD tenant ID.
	TenantID string
	// ClientID is the Azure AD application client ID.
	ClientID string
	// Audience is the Azure AD audience (defaults to "api://AzureADTokenExchange").
	Audience string
}

// ExchangeTokenInput contains parameters for STS token exchange.
type ExchangeTokenInput struct {
	// Audience is the full resource name of the Workload Identity Pool provider.
	Audience string
	// GrantType is the grant type for token exchange (usually "urn:ietf:params:oauth:grant-type:token-exchange").
	GrantType string
	// RequestedTokenType is the type of token to return (usually "urn:ietf:params:oauth:token-type:access_token").
	RequestedTokenType string
	// SubjectToken is the external identity token (JWT, AWS signature, etc.).
	SubjectToken string
	// SubjectTokenType is the type of the subject token.
	SubjectTokenType string
	// Scope is the OAuth scope to request.
	Scope string
}

// ExchangeTokenOutput contains the response from STS token exchange.
type ExchangeTokenOutput struct {
	AccessToken     string
	IssuedTokenType string
	TokenType       string
	ExpiresIn       int // seconds
}

// GenerateAccessTokenInput contains parameters for generating a service account access token.
type GenerateAccessTokenInput struct {
	// ServiceAccountEmail is the email of the service account to impersonate.
	ServiceAccountEmail string
	// Scope is the OAuth scope(s) for the access token.
	Scope []string
	// Lifetime is the duration of the access token in seconds.
	Lifetime int
	// Delegates is an optional chain of service accounts for delegation.
	Delegates []string
}

// GenerateAccessTokenOutput contains the generated access token.
type GenerateAccessTokenOutput struct {
	AccessToken string
	ExpireTime  time.Time
}

// IAMClient abstracts GCP IAM operations for testing.
type IAMClient interface {
	// Service Account operations
	GetServiceAccount(ctx context.Context, name string) (*ServiceAccount, error)
	CreateServiceAccount(ctx context.Context, projectID, accountID, displayName string) (*ServiceAccount, error)
	DeleteServiceAccount(ctx context.Context, name string) error

	// IAM Policy operations
	GetIAMPolicy(ctx context.Context, resource string) (*IAMPolicy, error)
	SetIAMPolicy(ctx context.Context, resource string, policy *IAMPolicy) error
}

// WorkloadIdentityClient abstracts GCP Workload Identity operations.
type WorkloadIdentityClient interface {
	// Pool operations
	GetWorkloadIdentityPool(ctx context.Context, name string) (*WorkloadIdentityPool, error)
	// ListWorkloadIdentityPools enumerates the pools under a parent ("projects/<id>/locations/global").
	ListWorkloadIdentityPools(ctx context.Context, parent string) ([]*WorkloadIdentityPool, error)
	// ListWorkloadIdentityPoolProviders enumerates the providers in one pool.
	ListWorkloadIdentityPoolProviders(ctx context.Context, parent string) ([]*WorkloadIdentityPoolProvider, error)
	CreateWorkloadIdentityPool(ctx context.Context, parent, poolID string, pool *WorkloadIdentityPool) (*WorkloadIdentityPool, error)
	DeleteWorkloadIdentityPool(ctx context.Context, name string) error

	// Provider operations
	GetWorkloadIdentityPoolProvider(ctx context.Context, name string) (*WorkloadIdentityPoolProvider, error)
	CreateWorkloadIdentityPoolProvider(ctx context.Context, parent, providerID string, provider *WorkloadIdentityPoolProvider) (*WorkloadIdentityPoolProvider, error)
	DeleteWorkloadIdentityPoolProvider(ctx context.Context, name string) error
}

// ServiceAccount represents a GCP service account.
type ServiceAccount struct {
	Name        string
	ProjectID   string
	UniqueID    string
	Email       string
	DisplayName string
}

// IAMPolicy represents a GCP IAM policy.
type IAMPolicy struct {
	Bindings []*IAMBinding
	Etag     string
	Version  int
}

// IAMBinding represents a binding in an IAM policy.
type IAMBinding struct {
	Role      string
	Members   []string
	Condition *IAMCondition
}

// IAMCondition represents a condition in an IAM binding.
type IAMCondition struct {
	Title       string
	Description string
	Expression  string
}

// WorkloadIdentityPool represents a GCP Workload Identity Pool.
type WorkloadIdentityPool struct {
	Name        string
	DisplayName string
	Description string
	State       string
	Disabled    bool
}

// WorkloadIdentityPoolProvider represents a provider in a Workload Identity Pool.
type WorkloadIdentityPoolProvider struct {
	Name               string
	DisplayName        string
	Description        string
	State              string
	Disabled           bool
	AttributeMapping   map[string]string
	AttributeCondition string

	// AWS-specific
	AWS *AWSProviderConfig

	// OIDC-specific
	OIDC *OIDCProviderConfig
}

// AWSProviderConfig contains AWS-specific provider configuration.
type AWSProviderConfig struct {
	AccountID string
}

// OIDCProviderConfig contains OIDC-specific provider configuration.
type OIDCProviderConfig struct {
	IssuerURI        string
	AllowedAudiences []string
}

// ProviderOption configures the Provider.
type ProviderOption func(*Provider)

// WithIAMClient sets the IAM client.
func WithIAMClient(client IAMClient) ProviderOption {
	return func(p *Provider) {
		p.iamClient = client
	}
}

// WithWorkloadIdentityClient sets the Workload Identity client.
func WithWorkloadIdentityClient(client WorkloadIdentityClient) ProviderOption {
	return func(p *Provider) {
		p.wifClient = client
	}
}

// WithSTSClient sets the STS client for token operations.
func WithSTSClient(client STSClient) ProviderOption {
	return func(p *Provider) {
		p.stsClient = client
	}
}

// New creates a new GCP provider.
func New(opts ...ProviderOption) *Provider {
	p := &Provider{}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Name implements core.Provider.
func (p *Provider) Name() core.Cloud {
	return core.GCP
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

// requireClients reports whether this provider can talk to GCP at all.
func (p *Provider) requireClients(ctx context.Context, needWIF, needIAM bool) error {
	if err := p.resolve(ctx, needWIF, needIAM); err != nil {
		return core.ErrValidation("could not reach GCP: no usable credentials").
			WithCause(err).
			WithProvider(core.GCP).
			WithDetail("hint", "Set GOOGLE_APPLICATION_CREDENTIALS, run `gcloud auth application-default login`, "+
				"or pass gcp.WithIAMClient/WithWorkloadIdentityClient; --dry-run needs no credentials")
	}
	if needWIF && p.wifClient == nil {
		return core.ErrValidation("GCP Workload Identity client not configured").
			WithProvider(core.GCP).
			WithDetail("hint", "Pass gcp.WithWorkloadIdentityClient, or use --dry-run")
	}
	if needIAM && p.iamClient == nil {
		return core.ErrValidation("GCP IAM client not configured").
			WithProvider(core.GCP).
			WithDetail("hint", "Pass gcp.WithIAMClient, or use --dry-run")
	}
	return nil
}

// Setup implements core.LifecycleProvider.
func (p *Provider) Setup(ctx context.Context, spec core.MechanismSpec, opts core.SetupOptions) (*core.Outputs, error) {
	switch s := spec.(type) {
	case *core.GCPWorkloadIdentityPoolSpec:
		return p.setupWorkloadIdentityPool(ctx, s, opts)
	case *core.K8sServiceAccountFederationSpec:
		return p.setupK8sFederation(ctx, s, opts)
	default:
		return nil, core.ErrValidation(fmt.Sprintf("unsupported spec type: %T", spec)).
			WithProvider(core.GCP)
	}
}

func (p *Provider) setupWorkloadIdentityPool(ctx context.Context, spec *core.GCPWorkloadIdentityPoolSpec, opts core.SetupOptions) (*core.Outputs, error) {
	// A dry run plans without touching GCP, so it must not require credentials: planning is exactly what someone does before they have them.
	if !opts.DryRun {
		if err := p.requireClients(ctx, true, true); err != nil {
			return nil, err
		}
	}

	var plan core.Plan

	poolName := fmt.Sprintf("projects/%s/locations/global/workloadIdentityPools/%s",
		spec.ProjectNumber, spec.PoolID)
	providerName := fmt.Sprintf("%s/providers/%s", poolName, spec.ProviderID)

	// createdPool records that THIS run created the pool.
	createdPool := false

	// Step 1: Create or verify pool.
	poolExists, poolKnown := false, false
	if p.wifClient != nil {
		_, err := p.wifClient.GetWorkloadIdentityPool(ctx, poolName)
		switch {
		case err == nil:
			poolExists, poolKnown = true, true
		case isNotFoundError(err):
			poolExists, poolKnown = false, true
		default:
			// Unknown.
			poolExists, poolKnown = false, false
		}
	}

	if !poolExists {
		action := core.PlannedAction{
			Operation:    "create",
			ResourceType: "workload-identity-pool",
			Details: map[string]interface{}{
				"pool_id": spec.PoolID,
				"project": spec.ProjectID,
			},
			Reversible: true,
		}
		plan.Actions = append(plan.Actions, action)

		if !opts.DryRun {
			if p.wifClient == nil {
				return nil, core.ErrValidation("GCP Workload Identity client not configured").
					WithProvider(core.GCP).
					WithDetail("hint", "Configure GCP credentials or use --dry-run")
			}

			displayName := spec.PoolDisplayName
			if displayName == "" {
				displayName = spec.PoolID
			}

			_, err := p.wifClient.CreateWorkloadIdentityPool(ctx,
				fmt.Sprintf("projects/%s/locations/global", spec.ProjectNumber),
				spec.PoolID,
				&WorkloadIdentityPool{
					DisplayName: displayName,
					Description: "Created by cloud-auth",
				})
			if err != nil {
				return nil, core.ErrPermission("failed to create workload identity pool").
					WithCause(err).WithProvider(core.GCP)
			}
			createdPool = true
		}
	}

	// Step 2: Create or update provider.
	var providerExists bool
	if p.wifClient != nil {
		_, err := p.wifClient.GetWorkloadIdentityPoolProvider(ctx, providerName)
		providerExists = err == nil
	}

	if !providerExists {
		action := core.PlannedAction{
			Operation:    "create",
			ResourceType: "workload-identity-provider",
			Details: map[string]interface{}{
				"provider_id":   spec.ProviderID,
				"provider_type": spec.ProviderType,
			},
			Reversible: true,
		}
		plan.Actions = append(plan.Actions, action)

		if !opts.DryRun {
			providerConfig := &WorkloadIdentityPoolProvider{
				DisplayName:        spec.ProviderDisplayName,
				AttributeMapping:   spec.AttributeMapping,
				AttributeCondition: spec.AttributeCondition,
			}

			switch spec.ProviderType {
			case "aws":
				providerConfig.AWS = &AWSProviderConfig{
					AccountID: spec.AWSAccountID,
				}
			case "oidc":
				providerConfig.OIDC = &OIDCProviderConfig{
					IssuerURI:        spec.OIDCIssuerURL,
					AllowedAudiences: spec.AllowedAudiences,
				}
			}

			_, err := p.wifClient.CreateWorkloadIdentityPoolProvider(ctx, poolName, spec.ProviderID, providerConfig)
			if err != nil {
				// Roll the pool back only if THIS run created it.
				failure := core.ErrPermission("failed to create workload identity provider").
					WithCause(err).WithProvider(core.GCP)
				if createdPool {
					if delErr := p.wifClient.DeleteWorkloadIdentityPool(ctx, poolName); delErr != nil {
						return nil, &core.RollbackError{
							OriginalError:     failure,
							RollbackErrors:    []error{delErr},
							OrphanedResources: []string{poolName},
						}
					}
					return nil, failure
				}
				if !poolKnown {
					return nil, failure.WithDetail("note",
						"the pool was left in place: this run could not confirm whether it "+
							"existed beforehand, and deleting a pool it did not create would "+
							"revoke every identity federating through it")
				}
				return nil, failure
			}
		}
	}

	// Step 3: Create service account if requested
	if spec.CreateServiceAccount {
		saEmail := spec.ServiceAccountEmail
		parts := strings.Split(saEmail, "@")
		if len(parts) != 2 {
			return nil, core.ErrValidation("invalid service account email format")
		}
		accountID := parts[0]

		var saExists bool
		if p.iamClient != nil {
			_, err := p.iamClient.GetServiceAccount(ctx,
				fmt.Sprintf("projects/%s/serviceAccounts/%s", spec.ProjectID, saEmail))
			saExists = err == nil
		}

		if !saExists {
			action := core.PlannedAction{
				Operation:    "create",
				ResourceType: "service-account",
				Details:      map[string]interface{}{"email": saEmail},
				Reversible:   true,
			}
			plan.Actions = append(plan.Actions, action)

			if !opts.DryRun && p.iamClient != nil {
				_, err := p.iamClient.CreateServiceAccount(ctx, spec.ProjectID, accountID, "Cloud-auth managed SA")
				if err != nil {
					return nil, core.ErrPermission("failed to create service account").
						WithCause(err).WithProvider(core.GCP)
				}
			}
		}
	}

	// Step 4: Bind service account to workload identity
	action := core.PlannedAction{
		Operation:    "update",
		ResourceType: "iam-binding",
		Details: map[string]interface{}{
			"service_account": spec.ServiceAccountEmail,
			"pool":            poolName,
		},
		Reversible: true,
	}
	plan.Actions = append(plan.Actions, action)

	if !opts.DryRun && p.iamClient != nil {
		// Get current policy
		saResource := fmt.Sprintf("projects/%s/serviceAccounts/%s", spec.ProjectID, spec.ServiceAccountEmail)
		policy, err := p.iamClient.GetIAMPolicy(ctx, saResource)
		if err != nil {
			return nil, core.ErrPermission("failed to get service account IAM policy").WithCause(err)
		}

		// Add workload identity user binding, scoped as narrowly as the spec allows.
		principalSet := spec.ImpersonationPrincipal(poolName)

		// Check if binding already exists
		bindingExists := false
		for _, binding := range policy.Bindings {
			if binding.Role == "roles/iam.workloadIdentityUser" {
				for _, member := range binding.Members {
					if member == principalSet {
						bindingExists = true
						break
					}
				}
				if !bindingExists {
					binding.Members = append(binding.Members, principalSet)
					bindingExists = true
				}
				break
			}
		}

		if !bindingExists {
			policy.Bindings = append(policy.Bindings, &IAMBinding{
				Role:    "roles/iam.workloadIdentityUser",
				Members: []string{principalSet},
			})
		}

		if err := p.iamClient.SetIAMPolicy(ctx, saResource, policy); err != nil {
			return nil, core.ErrPermission("failed to set service account IAM policy").WithCause(err)
		}
	}

	// Build output
	resourceIDs := map[string]string{
		"pool_name":             poolName,
		"provider_name":         providerName,
		"service_account_email": spec.ServiceAccountEmail,
		"project_id":            spec.ProjectID,
		"project_number":        spec.ProjectNumber,
	}

	// Record what the trust was SUPPOSED to be so a later Validate can compare the live provider against the original intent (a widened attribute condition or a repointed issuer is otherwise undetectable).
	if spec.OIDCIssuerURL != "" {
		resourceIDs["expected_issuer"] = spec.OIDCIssuerURL
	}
	if len(spec.AllowedAudiences) > 0 {
		resourceIDs["expected_audience"] = spec.AllowedAudiences[0]
	}
	if spec.AttributeCondition != "" {
		resourceIDs["expected_attribute_condition"] = spec.AttributeCondition
	}
	if len(spec.ServiceAccountRoles) > 0 {
		resourceIDs["expected_roles"] = strings.Join(spec.ServiceAccountRoles, ",")
	}

	ref := core.CreateMechanismRef(core.MechanismGCPWorkloadIdentityPool, core.GCP, resourceIDs)

	if opts.DryRun {
		plan.Summary = fmt.Sprintf("Would create/update %d resources for GCP Workload Identity Pool", len(plan.Actions))
		return &core.Outputs{
			Ref: ref,
			Values: map[string]string{
				"plan": plan.Summary,
			},
		}, nil
	}

	// Build credentials file content for reference
	credentialsConfig, err := buildCredentialsConfig(spec)
	if err != nil {
		return nil, err
	}

	return &core.Outputs{
		Ref: ref,
		Values: map[string]string{
			"pool_name":          poolName,
			"provider_name":      providerName,
			"credentials_config": credentialsConfig,
			"impersonate_sa":     spec.ServiceAccountEmail,
		},
	}, nil
}

// Validate implements core.LifecycleProvider.
func (p *Provider) Validate(ctx context.Context, ref core.MechanismRef, opts core.ValidateOptions) (*core.ValidationReport, error) {
	if err := p.requireClients(ctx, true, true); err != nil {
		return nil, err
	}

	var validators []core.Validator

	switch ref.Type {
	case core.MechanismGCPWorkloadIdentityPool:
		poolName := ref.ResourceIDs["pool_name"]
		if poolName != "" {
			validators = append(validators, &poolExistsValidator{client: p.wifClient, name: poolName})
		}

		providerName := ref.ResourceIDs["provider_name"]
		if providerName != "" {
			validators = append(validators, &providerExistsValidator{client: p.wifClient, name: providerName})
		}

		saEmail := ref.ResourceIDs["service_account_email"]
		projectID := ref.ResourceIDs["project_id"]
		if saEmail != "" && projectID != "" {
			validators = append(validators, &serviceAccountExistsValidator{
				client:    p.iamClient,
				projectID: projectID,
				email:     saEmail,
			})
		}

		// Compare the live pool provider against the recorded intent.
		expIssuer := ref.ResourceIDs["expected_issuer"]
		expAudience := ref.ResourceIDs["expected_audience"]
		expSubject := firstCELLiteral(ref.ResourceIDs["expected_attribute_condition"])
		if providerName != "" && (expIssuer != "" || expAudience != "" || expSubject != "") {
			validators = append(validators, core.NewTrustPolicyMatchValidator(
				expIssuer, expAudience, expSubject,
				core.WithTrustPolicySource(p)))

			// Breadth is scored unconditionally, unlike the match check above: it needs no recorded intent, only the live policy.
			validators = append(validators, core.NewSubjectBreadthValidator(p))
		}

		if raw := ref.ResourceIDs["expected_roles"]; raw != "" && saEmail != "" {
			validators = append(validators, core.NewPermissionsValidator(
				strings.Split(raw, ","),
				core.WithGrantedPolicySource(p)))
		}
	}

	report := core.RunValidation(ctx, ref, validators)
	return report, nil
}

// Delete implements core.LifecycleProvider.
func (p *Provider) Delete(ctx context.Context, ref core.MechanismRef, opts core.DeleteOptions) error {
	switch ref.Type {
	case core.MechanismGCPWorkloadIdentityPool:
		return p.deleteWorkloadIdentityPool(ctx, ref, opts)
	default:
		return core.ErrValidation(fmt.Sprintf("unsupported mechanism type: %s", ref.Type))
	}
}

func (p *Provider) deleteWorkloadIdentityPool(ctx context.Context, ref core.MechanismRef, opts core.DeleteOptions) error {
	if opts.DryRun {
		return nil
	}
	if err := p.requireClients(ctx, true, false); err != nil {
		return err
	}

	// Delete in reverse order: provider -> pool -> optionally SA

	// Step 1: Delete provider
	if providerName := ref.ResourceIDs["provider_name"]; providerName != "" {
		if err := p.wifClient.DeleteWorkloadIdentityPoolProvider(ctx, providerName); err != nil {
			if !isNotFoundError(err) {
				return core.ErrPermission("failed to delete workload identity provider").WithCause(err)
			}
		}
	}

	// Step 2: Delete pool (if owned)
	if ref.Owned {
		if poolName := ref.ResourceIDs["pool_name"]; poolName != "" {
			if err := p.wifClient.DeleteWorkloadIdentityPool(ctx, poolName); err != nil {
				if !isNotFoundError(err) {
					return core.ErrPermission("failed to delete workload identity pool").WithCause(err)
				}
			}
		}
	}

	// Note: We don't delete the service account by default as it may be used elsewhere

	return nil
}

// GenerateAWSRoleAssumptionToken creates an OIDC identity token that can be used to assume an AWS IAM role via AssumeRoleWithWebIdentity.
func (p *Provider) GenerateAWSRoleAssumptionToken(ctx context.Context, input *AWSRoleAssumptionInput) (*CrossCloudTokenOutput, error) {
	if p.stsClient == nil {
		return nil, core.ErrValidation("GCP STS client not configured").
			WithProvider(core.GCP).
			WithDetail("hint", "Configure GCP STS client using WithSTSClient option")
	}

	// Validate input
	if input.ServiceAccountEmail == "" {
		return nil, core.ErrValidation("ServiceAccountEmail is required").WithProvider(core.GCP)
	}
	if input.RoleARN == "" {
		return nil, core.ErrValidation("RoleARN is required").WithProvider(core.GCP)
	}

	// For AWS, the audience should be "sts.amazonaws.com" (the standard AWS STS audience)
	audience := "sts.amazonaws.com"

	// Generate an OIDC identity token
	idTokenInput := &GenerateIDTokenInput{
		ServiceAccountEmail: input.ServiceAccountEmail,
		Audience:            audience,
		IncludeEmail:        true,
	}

	idTokenOutput, err := p.stsClient.GenerateIDToken(ctx, idTokenInput)
	if err != nil {
		return nil, core.ErrAuth("failed to generate identity token for AWS").
			WithCause(err).
			WithProvider(core.GCP).
			WithResource("service-account", input.ServiceAccountEmail)
	}

	// Read the real expiry rather than assuming an hour.
	expiresAt, err := tokenExpiry(idTokenOutput.Token)
	if err != nil {
		return nil, core.ErrInternal("generated identity token has no usable expiry").WithCause(err)
	}

	return &CrossCloudTokenOutput{
		Token:     idTokenOutput.Token,
		TokenType: "urn:ietf:params:oauth:token-type:jwt",
		Audience:  audience,
		ExpiresAt: expiresAt,
		Issuer:    "https://accounts.google.com",
	}, nil
}

// GenerateAzureFederatedToken creates an OIDC identity token that can be used to authenticate with Azure AD via federated credentials.
func (p *Provider) GenerateAzureFederatedToken(ctx context.Context, input *AzureFederatedTokenInput) (*CrossCloudTokenOutput, error) {
	if p.stsClient == nil {
		return nil, core.ErrValidation("GCP STS client not configured").
			WithProvider(core.GCP).
			WithDetail("hint", "Configure GCP STS client using WithSTSClient option")
	}

	// Validate input
	if input.ServiceAccountEmail == "" {
		return nil, core.ErrValidation("ServiceAccountEmail is required").WithProvider(core.GCP)
	}
	if input.TenantID == "" {
		return nil, core.ErrValidation("TenantID is required").WithProvider(core.GCP)
	}
	if input.ClientID == "" {
		return nil, core.ErrValidation("ClientID is required").WithProvider(core.GCP)
	}

	// For Azure federated credentials, the default audience is "api://AzureADTokenExchange"
	audience := input.Audience
	if audience == "" {
		audience = "api://AzureADTokenExchange"
	}

	// Generate an OIDC identity token
	idTokenInput := &GenerateIDTokenInput{
		ServiceAccountEmail: input.ServiceAccountEmail,
		Audience:            audience,
		IncludeEmail:        true,
	}

	idTokenOutput, err := p.stsClient.GenerateIDToken(ctx, idTokenInput)
	if err != nil {
		return nil, core.ErrAuth("failed to generate identity token for Azure").
			WithCause(err).
			WithProvider(core.GCP).
			WithResource("service-account", input.ServiceAccountEmail)
	}

	// Read the real expiry rather than assuming an hour.
	expiresAt, err := tokenExpiry(idTokenOutput.Token)
	if err != nil {
		return nil, core.ErrInternal("generated identity token has no usable expiry").WithCause(err)
	}

	return &CrossCloudTokenOutput{
		Token:     idTokenOutput.Token,
		TokenType: "urn:ietf:params:oauth:token-type:jwt",
		Audience:  audience,
		ExpiresAt: expiresAt,
		Issuer:    "https://accounts.google.com",
	}, nil
}

// tokenExpiry reads the exp claim from a minted identity token.
func tokenExpiry(token string) (time.Time, error) {
	claims, err := jwt.ParseUnverified(token)
	if err != nil {
		return time.Time{}, err
	}
	if claims.Expiry.IsZero() {
		return time.Time{}, fmt.Errorf("token carries no exp claim")
	}
	return claims.Expiry, nil
}

// Helper functions

// buildCredentialsConfig renders an external_account credential file, the shape GOOGLE_APPLICATION_CREDENTIALS expects.
func buildCredentialsConfig(spec *core.GCPWorkloadIdentityPoolSpec) (string, error) {
	type awsSource struct {
		EnvironmentID               string `json:"environment_id"`
		RegionURL                   string `json:"region_url"`
		URL                         string `json:"url"`
		IMDSv2SessionTokenURL       string `json:"imdsv2_session_token_url"`
		RegionalCredVerificationURL string `json:"regional_cred_verification_url"`
	}
	type fileSource struct {
		File string `json:"file"`
	}

	cfg := struct {
		Type                           string      `json:"type"`
		Audience                       string      `json:"audience"`
		SubjectTokenType               string      `json:"subject_token_type"`
		ServiceAccountImpersonationURL string      `json:"service_account_impersonation_url,omitempty"`
		TokenURL                       string      `json:"token_url"`
		CredentialSource               interface{} `json:"credential_source,omitempty"`
	}{
		Type: "external_account",
		Audience: fmt.Sprintf(
			"//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s",
			spec.ProjectNumber, spec.PoolID, spec.ProviderID),
		SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
		TokenURL:         "https://sts.googleapis.com/v1/token",
	}
	if spec.ServiceAccountEmail != "" {
		cfg.ServiceAccountImpersonationURL = fmt.Sprintf(
			"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken",
			url.PathEscape(spec.ServiceAccountEmail))
	}

	switch spec.ProviderType {
	case "aws":
		cfg.SubjectTokenType = "urn:ietf:params:aws:token-type:aws4_request"
		cfg.CredentialSource = awsSource{
			EnvironmentID: "aws1",
			RegionURL:     "http://169.254.169.254/latest/meta-data/placement/availability-zone",
			URL:           "http://169.254.169.254/latest/meta-data/iam/security-credentials",
			// Without this, the Google client uses IMDSv1 and fails on any instance configured for IMDSv2 only.
			IMDSv2SessionTokenURL:       "http://169.254.169.254/latest/api/token",
			RegionalCredVerificationURL: "https://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15",
		}
	case "oidc":
		cfg.CredentialSource = fileSource{File: "/var/run/secrets/tokens/gcp-token"}
	}

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("gcp: rendering credential config: %w", err)
	}
	return string(out), nil
}

// isNotFoundError reports whether err means "the resource is absent", as opposed to "we could not tell" — a distinction Setup's create-or-update decision and the rollback both depend on.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	if core.IsCategory(err, core.ErrCategoryNotFound) {
		return true
	}
	var apiErr interface{ NotFound() bool }
	if errors.As(err, &apiErr) && apiErr.NotFound() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") ||
		strings.Contains(msg, "notfound") ||
		strings.Contains(msg, "404")
}

// Validators

type poolExistsValidator struct {
	client WorkloadIdentityClient
	name   string
}

func (v *poolExistsValidator) ID() string   { return "gcp_wif_pool_exists" }
func (v *poolExistsValidator) Name() string { return "Workload Identity Pool Exists" }
func (v *poolExistsValidator) Description() string {
	return "Checks if the Workload Identity Pool exists"
}

func (v *poolExistsValidator) Validate(ctx context.Context, ref core.MechanismRef) core.ValidationCheck {
	check := core.NewCheck(v, core.SeverityCritical)
	check.Evidence["pool_name"] = v.name

	pool, err := v.client.GetWorkloadIdentityPool(ctx, v.name)
	if err != nil {
		check.Status = core.CheckStatusFailed
		check.Evidence["error"] = err.Error()
		check.Remediation = "Create the Workload Identity Pool or run setup again"
		return check
	}

	check.Status = core.CheckStatusPassed
	check.Evidence["state"] = pool.State
	check.Evidence["disabled"] = pool.Disabled
	return check
}

type providerExistsValidator struct {
	client WorkloadIdentityClient
	name   string
}

func (v *providerExistsValidator) ID() string   { return "gcp_wif_provider_exists" }
func (v *providerExistsValidator) Name() string { return "Workload Identity Provider Exists" }
func (v *providerExistsValidator) Description() string {
	return "Checks if the Workload Identity Provider exists"
}

func (v *providerExistsValidator) Validate(ctx context.Context, ref core.MechanismRef) core.ValidationCheck {
	check := core.NewCheck(v, core.SeverityCritical)
	check.Evidence["provider_name"] = v.name

	provider, err := v.client.GetWorkloadIdentityPoolProvider(ctx, v.name)
	if err != nil {
		check.Status = core.CheckStatusFailed
		check.Evidence["error"] = err.Error()
		check.Remediation = "Create the Workload Identity Provider or run setup again"
		return check
	}

	check.Status = core.CheckStatusPassed
	check.Evidence["state"] = provider.State
	return check
}

type serviceAccountExistsValidator struct {
	client    IAMClient
	projectID string
	email     string
}

func (v *serviceAccountExistsValidator) ID() string   { return "gcp_sa_exists" }
func (v *serviceAccountExistsValidator) Name() string { return "Service Account Exists" }
func (v *serviceAccountExistsValidator) Description() string {
	return "Checks if the Service Account exists"
}

func (v *serviceAccountExistsValidator) Validate(ctx context.Context, ref core.MechanismRef) core.ValidationCheck {
	check := core.NewCheck(v, core.SeverityCritical)
	check.Evidence["email"] = v.email

	saName := fmt.Sprintf("projects/%s/serviceAccounts/%s", v.projectID, v.email)
	sa, err := v.client.GetServiceAccount(ctx, saName)
	if err != nil {
		check.Status = core.CheckStatusFailed
		check.Evidence["error"] = err.Error()
		check.Remediation = "Create the Service Account or run setup again"
		return check
	}

	check.Status = core.CheckStatusPassed
	check.Evidence["unique_id"] = sa.UniqueID
	return check
}

func init() {
	// Register with default registry Panic rather than discard: Register fails only on a duplicate name, which is a programming error, and the alternative is a provider that silently does not exist.
	if err := core.Register(New()); err != nil {
		panic("cloud-auth/provider/gcp: registering the GCP provider: " + err.Error())
	}
}
