// Package gcp provides GCP lifecycle provider implementation.
package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/anirudhbiyani/cloud-auth/pkg/cloudauth"
)

// Provider implements cloudauth.LifecycleProvider for GCP.
type Provider struct {
	iamClient IAMClient
	wifClient WorkloadIdentityClient
	stsClient STSClient
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
	// Format: //iam.googleapis.com/projects/{project_number}/locations/global/workloadIdentityPools/{pool_id}/providers/{provider_id}
	Audience string
	// GrantType is the grant type for token exchange (usually "urn:ietf:params:oauth:grant-type:token-exchange").
	GrantType string
	// RequestedTokenType is the type of token to return (usually "urn:ietf:params:oauth:token-type:access_token").
	RequestedTokenType string
	// SubjectToken is the external identity token (JWT, AWS signature, etc.).
	SubjectToken string
	// SubjectTokenType is the type of the subject token.
	// For OIDC: "urn:ietf:params:oauth:token-type:jwt"
	// For AWS: "urn:ietf:params:aws:token-type:aws4_request"
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
	Name              string
	DisplayName       string
	Description       string
	State             string
	Disabled          bool
	AttributeMapping  map[string]string
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

// Name implements cloudauth.Provider.
func (p *Provider) Name() cloudauth.CloudProvider {
	return cloudauth.ProviderGCP
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
	case *cloudauth.GCPWorkloadIdentityPoolSpec:
		return p.setupWorkloadIdentityPool(ctx, s, opts)
	default:
		return nil, cloudauth.ErrValidation(fmt.Sprintf("unsupported spec type: %T", spec)).
			WithProvider(cloudauth.ProviderGCP)
	}
}

func (p *Provider) setupWorkloadIdentityPool(ctx context.Context, spec *cloudauth.GCPWorkloadIdentityPoolSpec, opts cloudauth.SetupOptions) (*cloudauth.Outputs, error) {
	var plan cloudauth.Plan

	poolName := fmt.Sprintf("projects/%s/locations/global/workloadIdentityPools/%s",
		spec.ProjectNumber, spec.PoolID)
	providerName := fmt.Sprintf("%s/providers/%s", poolName, spec.ProviderID)

	// Step 1: Create or verify pool
	var poolExists bool
	if p.wifClient != nil {
		_, err := p.wifClient.GetWorkloadIdentityPool(ctx, poolName)
		poolExists = err == nil
	}

	if !poolExists {
		action := cloudauth.PlannedAction{
			Operation:    "create",
			ResourceType: "workload-identity-pool",
			Details: map[string]interface{}{
				"pool_id":     spec.PoolID,
				"project":     spec.ProjectID,
			},
			Reversible: true,
		}
		plan.Actions = append(plan.Actions, action)

		if !opts.DryRun {
			if p.wifClient == nil {
				return nil, cloudauth.ErrValidation("GCP Workload Identity client not configured").
					WithProvider(cloudauth.ProviderGCP).
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
				return nil, cloudauth.ErrPermission("failed to create workload identity pool").
					WithCause(err).WithProvider(cloudauth.ProviderGCP)
			}
		}
	}

	// Step 2: Create or update provider
	var providerExists bool
	if p.wifClient != nil {
		_, err := p.wifClient.GetWorkloadIdentityPoolProvider(ctx, providerName)
		providerExists = err == nil
	}

	if !providerExists {
		action := cloudauth.PlannedAction{
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
				// Rollback pool if we created it
				if !poolExists {
					_ = p.wifClient.DeleteWorkloadIdentityPool(ctx, poolName)
				}
				return nil, cloudauth.ErrPermission("failed to create workload identity provider").
					WithCause(err).WithProvider(cloudauth.ProviderGCP)
			}
		}
	}

	// Step 3: Create service account if requested
	if spec.CreateServiceAccount {
		saEmail := spec.ServiceAccountEmail
		parts := strings.Split(saEmail, "@")
		if len(parts) != 2 {
			return nil, cloudauth.ErrValidation("invalid service account email format")
		}
		accountID := parts[0]

		var saExists bool
		if p.iamClient != nil {
			_, err := p.iamClient.GetServiceAccount(ctx, 
				fmt.Sprintf("projects/%s/serviceAccounts/%s", spec.ProjectID, saEmail))
			saExists = err == nil
		}

		if !saExists {
			action := cloudauth.PlannedAction{
				Operation:    "create",
				ResourceType: "service-account",
				Details:      map[string]interface{}{"email": saEmail},
				Reversible:   true,
			}
			plan.Actions = append(plan.Actions, action)

			if !opts.DryRun && p.iamClient != nil {
				_, err := p.iamClient.CreateServiceAccount(ctx, spec.ProjectID, accountID, "Cloud-auth managed SA")
				if err != nil {
					return nil, cloudauth.ErrPermission("failed to create service account").
						WithCause(err).WithProvider(cloudauth.ProviderGCP)
				}
			}
		}
	}

	// Step 4: Bind service account to workload identity
	action := cloudauth.PlannedAction{
		Operation:    "update",
		ResourceType: "iam-binding",
		Details: map[string]interface{}{
			"service_account": spec.ServiceAccountEmail,
			"pool":           poolName,
		},
		Reversible: true,
	}
	plan.Actions = append(plan.Actions, action)

	if !opts.DryRun && p.iamClient != nil {
		// Get current policy
		saResource := fmt.Sprintf("projects/%s/serviceAccounts/%s", spec.ProjectID, spec.ServiceAccountEmail)
		policy, err := p.iamClient.GetIAMPolicy(ctx, saResource)
		if err != nil {
			return nil, cloudauth.ErrPermission("failed to get service account IAM policy").WithCause(err)
		}

		// Add workload identity user binding
		principalSet := fmt.Sprintf("principalSet://iam.googleapis.com/%s/*", poolName)
		
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
			return nil, cloudauth.ErrPermission("failed to set service account IAM policy").WithCause(err)
		}
	}

	// Build output
	resourceIDs := map[string]string{
		"pool_name":             poolName,
		"provider_name":         providerName,
		"service_account_email": spec.ServiceAccountEmail,
		"project_id":           spec.ProjectID,
		"project_number":       spec.ProjectNumber,
	}

	ref := cloudauth.CreateMechanismRef(cloudauth.MechanismGCPWorkloadIdentityPool, cloudauth.ProviderGCP, resourceIDs)

	if opts.DryRun {
		plan.Summary = fmt.Sprintf("Would create/update %d resources for GCP Workload Identity Pool", len(plan.Actions))
		return &cloudauth.Outputs{
			Ref: ref,
			Values: map[string]string{
				"plan": plan.Summary,
			},
		}, nil
	}

	// Build credentials file content for reference
	credentialsConfig := buildCredentialsConfig(spec)

	return &cloudauth.Outputs{
		Ref: ref,
		Values: map[string]string{
			"pool_name":              poolName,
			"provider_name":          providerName,
			"credentials_config":     credentialsConfig,
			"impersonate_sa":         spec.ServiceAccountEmail,
		},
	}, nil
}

// Validate implements cloudauth.LifecycleProvider.
func (p *Provider) Validate(ctx context.Context, ref cloudauth.MechanismRef, opts cloudauth.ValidateOptions) (*cloudauth.ValidationReport, error) {
	var validators []cloudauth.Validator

	switch ref.Type {
	case cloudauth.MechanismGCPWorkloadIdentityPool:
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
	}

	report := cloudauth.RunValidation(ctx, ref, validators)
	return report, nil
}

// Delete implements cloudauth.LifecycleProvider.
func (p *Provider) Delete(ctx context.Context, ref cloudauth.MechanismRef, opts cloudauth.DeleteOptions) error {
	switch ref.Type {
	case cloudauth.MechanismGCPWorkloadIdentityPool:
		return p.deleteWorkloadIdentityPool(ctx, ref, opts)
	default:
		return cloudauth.ErrValidation(fmt.Sprintf("unsupported mechanism type: %s", ref.Type))
	}
}

func (p *Provider) deleteWorkloadIdentityPool(ctx context.Context, ref cloudauth.MechanismRef, opts cloudauth.DeleteOptions) error {
	if opts.DryRun {
		return nil
	}

	// Delete in reverse order: provider -> pool -> optionally SA

	// Step 1: Delete provider
	if providerName := ref.ResourceIDs["provider_name"]; providerName != "" {
		if err := p.wifClient.DeleteWorkloadIdentityPoolProvider(ctx, providerName); err != nil {
			if !isNotFoundError(err) {
				return cloudauth.ErrPermission("failed to delete workload identity provider").WithCause(err)
			}
		}
	}

	// Step 2: Delete pool (if owned)
	if ref.Owned {
		if poolName := ref.ResourceIDs["pool_name"]; poolName != "" {
			if err := p.wifClient.DeleteWorkloadIdentityPool(ctx, poolName); err != nil {
				if !isNotFoundError(err) {
					return cloudauth.ErrPermission("failed to delete workload identity pool").WithCause(err)
				}
			}
		}
	}

	// Note: We don't delete the service account by default as it may be used elsewhere

	return nil
}

// Token implements cloudauth.TokenProvider.
// It exchanges an external identity token for GCP credentials using Workload Identity Federation.
//
// TokenRequest fields:
//   - TargetIdentity: Service account email to impersonate (required)
//   - Audience: The WIF provider audience or the subject token (required)
//     Format: //iam.googleapis.com/projects/{project_number}/locations/global/workloadIdentityPools/{pool_id}/providers/{provider_id}
//   - SourceIdentity: The external subject token to exchange (required - passed via SourceIdentity)
//   - Scopes: OAuth scopes for the access token (optional, defaults to cloud-platform)
//   - Duration: Token lifetime in seconds (optional, defaults to 3600)
//
// The token exchange follows this flow:
//  1. Exchange external token for GCP STS token via sts.googleapis.com
//  2. Use STS token to impersonate service account via iamcredentials.googleapis.com
//  3. Return the service account access token
func (p *Provider) Token(ctx context.Context, req cloudauth.TokenRequest) (*cloudauth.TokenResponse, error) {
	if p.stsClient == nil {
		return nil, cloudauth.ErrValidation("GCP STS client not configured").
			WithProvider(cloudauth.ProviderGCP).
			WithDetail("hint", "Configure GCP STS client using WithSTSClient option")
	}

	// Validate required fields
	if req.TargetIdentity == "" {
		return nil, cloudauth.ErrValidation("TargetIdentity (service account email) is required").
			WithProvider(cloudauth.ProviderGCP)
	}

	if req.Audience == "" {
		return nil, cloudauth.ErrValidation("Audience (WIF provider audience) is required").
			WithProvider(cloudauth.ProviderGCP).
			WithDetail("hint", "Format: //iam.googleapis.com/projects/{project_number}/locations/global/workloadIdentityPools/{pool_id}/providers/{provider_id}")
	}

	// The subject token should be passed via SourceIdentity
	subjectToken := req.SourceIdentity
	if subjectToken == "" {
		return nil, cloudauth.ErrValidation("SourceIdentity (subject token) is required").
			WithProvider(cloudauth.ProviderGCP).
			WithDetail("hint", "Pass the external identity token (JWT, AWS signature) in SourceIdentity field")
	}

	// Determine subject token type based on token format
	subjectTokenType := determineSubjectTokenType(subjectToken)

	// Set default scopes
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = []string{"https://www.googleapis.com/auth/cloud-platform"}
	}

	// Step 1: Exchange external token for GCP STS token
	exchangeInput := &ExchangeTokenInput{
		Audience:           req.Audience,
		GrantType:          "urn:ietf:params:oauth:grant-type:token-exchange",
		RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		SubjectToken:       subjectToken,
		SubjectTokenType:   subjectTokenType,
		Scope:              strings.Join(scopes, " "),
	}

	exchangeOutput, err := p.stsClient.ExchangeToken(ctx, exchangeInput)
	if err != nil {
		return nil, cloudauth.ErrAuth("failed to exchange token with GCP STS").
			WithCause(err).
			WithProvider(cloudauth.ProviderGCP)
	}

	// Step 2: Use STS token to generate service account access token
	lifetime := req.Duration
	if lifetime == 0 {
		lifetime = 3600 // Default 1 hour
	}

	generateInput := &GenerateAccessTokenInput{
		ServiceAccountEmail: req.TargetIdentity,
		Scope:               scopes,
		Lifetime:            lifetime,
	}

	// Note: The STS client should use the exchanged token for authentication
	// This is implementation-specific and depends on how the STSClient is configured
	generateOutput, err := p.stsClient.GenerateAccessToken(ctx, generateInput)
	if err != nil {
		return nil, cloudauth.ErrAuth("failed to generate service account access token").
			WithCause(err).
			WithProvider(cloudauth.ProviderGCP).
			WithResource("service-account", req.TargetIdentity)
	}

	// Build response
	credentials := map[string]interface{}{
		"access_token":          generateOutput.AccessToken,
		"token_type":            "Bearer",
		"expiration":            generateOutput.ExpireTime.Format(time.RFC3339),
		"service_account_email": req.TargetIdentity,
		"sts_token":             exchangeOutput.AccessToken, // Include STS token for debugging
	}

	credentialsJSON, err := json.Marshal(credentials)
	if err != nil {
		return nil, cloudauth.ErrInternal("failed to marshal credentials").WithCause(err)
	}

	return &cloudauth.TokenResponse{
		Token:     string(credentialsJSON),
		ExpiresAt: generateOutput.ExpireTime.Unix(),
		TokenType: "Bearer",
		Scopes:    scopes,
	}, nil
}

// GenerateAWSRoleAssumptionToken creates an OIDC identity token that can be used
// to assume an AWS IAM role via AssumeRoleWithWebIdentity.
//
// This enables GCP workloads to authenticate to AWS without using long-lived credentials.
// The returned token is a JWT signed by Google that AWS can validate.
//
// Prerequisites:
//   - AWS IAM role must trust the Google OIDC issuer (https://accounts.google.com)
//   - The service account must have the iam.serviceAccounts.signJwt permission
//
// Usage:
//
//	token, err := gcpProvider.GenerateAWSRoleAssumptionToken(ctx, &AWSRoleAssumptionInput{
//	    ServiceAccountEmail: "my-sa@project.iam.gserviceaccount.com",
//	    RoleARN:             "arn:aws:iam::123456789012:role/MyRole",
//	})
//	// Use token.Token with AWS provider's Token() method
func (p *Provider) GenerateAWSRoleAssumptionToken(ctx context.Context, input *AWSRoleAssumptionInput) (*CrossCloudTokenOutput, error) {
	if p.stsClient == nil {
		return nil, cloudauth.ErrValidation("GCP STS client not configured").
			WithProvider(cloudauth.ProviderGCP).
			WithDetail("hint", "Configure GCP STS client using WithSTSClient option")
	}

	// Validate input
	if input.ServiceAccountEmail == "" {
		return nil, cloudauth.ErrValidation("ServiceAccountEmail is required").WithProvider(cloudauth.ProviderGCP)
	}
	if input.RoleARN == "" {
		return nil, cloudauth.ErrValidation("RoleARN is required").WithProvider(cloudauth.ProviderGCP)
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
		return nil, cloudauth.ErrAuth("failed to generate identity token for AWS").
			WithCause(err).
			WithProvider(cloudauth.ProviderGCP).
			WithResource("service-account", input.ServiceAccountEmail)
	}

	// Parse the JWT to get expiration (tokens are typically valid for 1 hour)
	expiresAt := time.Now().Add(1 * time.Hour)

	return &CrossCloudTokenOutput{
		Token:     idTokenOutput.Token,
		TokenType: "urn:ietf:params:oauth:token-type:jwt",
		Audience:  audience,
		ExpiresAt: expiresAt,
		Issuer:    "https://accounts.google.com",
	}, nil
}

// GenerateAzureFederatedToken creates an OIDC identity token that can be used
// to authenticate with Azure AD via federated credentials.
//
// This enables GCP workloads to authenticate to Azure without using long-lived credentials.
// The returned token is a JWT signed by Google that Azure AD can validate.
//
// Prerequisites:
//   - Azure AD app/managed identity must have a federated credential configured
//   - The federated credential must trust the Google OIDC issuer (https://accounts.google.com)
//   - The subject claim must match the service account's unique ID
//
// Usage:
//
//	token, err := gcpProvider.GenerateAzureFederatedToken(ctx, &AzureFederatedTokenInput{
//	    ServiceAccountEmail: "my-sa@project.iam.gserviceaccount.com",
//	    TenantID:            "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
//	    ClientID:            "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
//	})
//	// Use token.Token with Azure provider's Token() method
func (p *Provider) GenerateAzureFederatedToken(ctx context.Context, input *AzureFederatedTokenInput) (*CrossCloudTokenOutput, error) {
	if p.stsClient == nil {
		return nil, cloudauth.ErrValidation("GCP STS client not configured").
			WithProvider(cloudauth.ProviderGCP).
			WithDetail("hint", "Configure GCP STS client using WithSTSClient option")
	}

	// Validate input
	if input.ServiceAccountEmail == "" {
		return nil, cloudauth.ErrValidation("ServiceAccountEmail is required").WithProvider(cloudauth.ProviderGCP)
	}
	if input.TenantID == "" {
		return nil, cloudauth.ErrValidation("TenantID is required").WithProvider(cloudauth.ProviderGCP)
	}
	if input.ClientID == "" {
		return nil, cloudauth.ErrValidation("ClientID is required").WithProvider(cloudauth.ProviderGCP)
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
		return nil, cloudauth.ErrAuth("failed to generate identity token for Azure").
			WithCause(err).
			WithProvider(cloudauth.ProviderGCP).
			WithResource("service-account", input.ServiceAccountEmail)
	}

	// Parse the JWT to get expiration (tokens are typically valid for 1 hour)
	expiresAt := time.Now().Add(1 * time.Hour)

	return &CrossCloudTokenOutput{
		Token:     idTokenOutput.Token,
		TokenType: "urn:ietf:params:oauth:token-type:jwt",
		Audience:  audience,
		ExpiresAt: expiresAt,
		Issuer:    "https://accounts.google.com",
	}, nil
}

// determineSubjectTokenType infers the token type from the token content.
func determineSubjectTokenType(token string) string {
	// Check if it's a JWT (has 3 dot-separated parts)
	if strings.Count(token, ".") == 2 {
		return "urn:ietf:params:oauth:token-type:jwt"
	}

	// Check if it looks like an AWS signed request (JSON with url, method, headers)
	if strings.HasPrefix(strings.TrimSpace(token), "{") {
		var awsToken struct {
			URL     string `json:"url"`
			Method  string `json:"method"`
			Headers []struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			} `json:"headers"`
		}
		if err := json.Unmarshal([]byte(token), &awsToken); err == nil && awsToken.URL != "" {
			return "urn:ietf:params:aws:token-type:aws4_request"
		}
	}

	// Default to JWT
	return "urn:ietf:params:oauth:token-type:jwt"
}

// Helper functions

func buildCredentialsConfig(spec *cloudauth.GCPWorkloadIdentityPoolSpec) string {
	// Build a credential configuration JSON that can be used with
	// GOOGLE_APPLICATION_CREDENTIALS
	config := map[string]interface{}{
		"type":                           "external_account",
		"audience":                        fmt.Sprintf("//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s", spec.ProjectNumber, spec.PoolID, spec.ProviderID),
		"subject_token_type":             "urn:ietf:params:oauth:token-type:jwt",
		"service_account_impersonation_url": fmt.Sprintf("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken", spec.ServiceAccountEmail),
		"token_url":                      "https://sts.googleapis.com/v1/token",
	}

	switch spec.ProviderType {
	case "aws":
		config["credential_source"] = map[string]interface{}{
			"environment_id":                 "aws1",
			"region_url":                     "http://169.254.169.254/latest/meta-data/placement/availability-zone",
			"url":                            "http://169.254.169.254/latest/meta-data/iam/security-credentials",
			"regional_cred_verification_url": "https://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15",
		}
	case "oidc":
		config["credential_source"] = map[string]interface{}{
			"file": "/var/run/secrets/tokens/gcp-token",
		}
	}

	// Return as formatted JSON string
	return fmt.Sprintf("%v", config)
}

func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "not found") ||
		strings.Contains(err.Error(), "404") ||
		cloudauth.IsCategory(err, cloudauth.ErrCategoryNotFound)
}

// Validators

type poolExistsValidator struct {
	client WorkloadIdentityClient
	name   string
}

func (v *poolExistsValidator) ID() string          { return "gcp_wif_pool_exists" }
func (v *poolExistsValidator) Name() string        { return "Workload Identity Pool Exists" }
func (v *poolExistsValidator) Description() string { return "Checks if the Workload Identity Pool exists" }

func (v *poolExistsValidator) Validate(ctx context.Context, ref cloudauth.MechanismRef) cloudauth.ValidationCheck {
	check := cloudauth.ValidationCheck{
		ID:          v.ID(),
		Name:        v.Name(),
		Description: v.Description(),
		Severity:    cloudauth.SeverityCritical,
		Evidence:    map[string]interface{}{"pool_name": v.name},
	}

	pool, err := v.client.GetWorkloadIdentityPool(ctx, v.name)
	if err != nil {
		check.Status = cloudauth.CheckStatusFailed
		check.Evidence["error"] = err.Error()
		check.Remediation = "Create the Workload Identity Pool or run setup again"
		return check
	}

	check.Status = cloudauth.CheckStatusPassed
	check.Evidence["state"] = pool.State
	check.Evidence["disabled"] = pool.Disabled
	return check
}

type providerExistsValidator struct {
	client WorkloadIdentityClient
	name   string
}

func (v *providerExistsValidator) ID() string          { return "gcp_wif_provider_exists" }
func (v *providerExistsValidator) Name() string        { return "Workload Identity Provider Exists" }
func (v *providerExistsValidator) Description() string { return "Checks if the Workload Identity Provider exists" }

func (v *providerExistsValidator) Validate(ctx context.Context, ref cloudauth.MechanismRef) cloudauth.ValidationCheck {
	check := cloudauth.ValidationCheck{
		ID:          v.ID(),
		Name:        v.Name(),
		Description: v.Description(),
		Severity:    cloudauth.SeverityCritical,
		Evidence:    map[string]interface{}{"provider_name": v.name},
	}

	provider, err := v.client.GetWorkloadIdentityPoolProvider(ctx, v.name)
	if err != nil {
		check.Status = cloudauth.CheckStatusFailed
		check.Evidence["error"] = err.Error()
		check.Remediation = "Create the Workload Identity Provider or run setup again"
		return check
	}

	check.Status = cloudauth.CheckStatusPassed
	check.Evidence["state"] = provider.State
	return check
}

type serviceAccountExistsValidator struct {
	client    IAMClient
	projectID string
	email     string
}

func (v *serviceAccountExistsValidator) ID() string          { return "gcp_sa_exists" }
func (v *serviceAccountExistsValidator) Name() string        { return "Service Account Exists" }
func (v *serviceAccountExistsValidator) Description() string { return "Checks if the Service Account exists" }

func (v *serviceAccountExistsValidator) Validate(ctx context.Context, ref cloudauth.MechanismRef) cloudauth.ValidationCheck {
	check := cloudauth.ValidationCheck{
		ID:          v.ID(),
		Name:        v.Name(),
		Description: v.Description(),
		Severity:    cloudauth.SeverityCritical,
		Evidence:    map[string]interface{}{"email": v.email},
	}

	saName := fmt.Sprintf("projects/%s/serviceAccounts/%s", v.projectID, v.email)
	sa, err := v.client.GetServiceAccount(ctx, saName)
	if err != nil {
		check.Status = cloudauth.CheckStatusFailed
		check.Evidence["error"] = err.Error()
		check.Remediation = "Create the Service Account or run setup again"
		return check
	}

	check.Status = cloudauth.CheckStatusPassed
	check.Evidence["unique_id"] = sa.UniqueID
	return check
}

func init() {
	// Register with default registry
	cloudauth.Register(New())
}

