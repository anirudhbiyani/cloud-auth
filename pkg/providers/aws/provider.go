// Package aws provides AWS lifecycle provider implementation.
package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/anirudhbiyani/cloud-auth/pkg/cloudauth"
)

// Provider implements cloudauth.LifecycleProvider for AWS.
type Provider struct {
	client    IAMClient
	stsClient STSClient
}

// STSClient abstracts AWS STS operations for token acquisition.
type STSClient interface {
	// AssumeRoleWithWebIdentity exchanges an OIDC token for AWS credentials.
	AssumeRoleWithWebIdentity(ctx context.Context, input *AssumeRoleWithWebIdentityInput) (*AssumeRoleWithWebIdentityOutput, error)
	// GetCallerIdentity returns details about the IAM identity making the call.
	GetCallerIdentity(ctx context.Context) (*GetCallerIdentityOutput, error)
	// SignRequest signs an HTTP request using AWS SigV4.
	SignRequest(ctx context.Context, input *SignRequestInput) (*SignRequestOutput, error)
}

// GetCallerIdentityOutput contains the response from GetCallerIdentity.
type GetCallerIdentityOutput struct {
	Account string
	ARN     string
	UserID  string
}

// SignRequestInput contains parameters for signing an HTTP request.
type SignRequestInput struct {
	Method  string
	URL     string
	Headers map[string]string
	Region  string
	Service string
}

// SignRequestOutput contains the signed request details.
type SignRequestOutput struct {
	URL     string
	Method  string
	Headers []SignedHeader
}

// SignedHeader represents a header in the signed request.
type SignedHeader struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// CrossCloudTokenOutput contains a token that can be used for cross-cloud authentication.
type CrossCloudTokenOutput struct {
	// Token is the token value (format depends on target cloud).
	Token string
	// TokenType describes the type of token.
	TokenType string
	// Audience is the intended audience for the token.
	Audience string
	// ExpiresAt is when the token expires (if applicable).
	ExpiresAt time.Time
}

// GCPWorkloadIdentityInput contains parameters for generating a GCP WIF token.
type GCPWorkloadIdentityInput struct {
	// ProjectNumber is the GCP project number (not project ID).
	ProjectNumber string
	// PoolID is the Workload Identity Pool ID.
	PoolID string
	// ProviderID is the provider ID within the pool.
	ProviderID string
	// Region is the AWS region (optional, uses default if empty).
	Region string
}

// AzureFederatedTokenInput contains parameters for generating an Azure federated token.
// Note: AWS cannot directly generate tokens for Azure as Azure requires OIDC tokens
// and AWS doesn't expose an OIDC endpoint. This is included for API completeness.
type AzureFederatedTokenInput struct {
	// TenantID is the Azure AD tenant ID.
	TenantID string
	// ClientID is the Azure AD application client ID.
	ClientID string
}

// AssumeRoleWithWebIdentityInput contains parameters for AssumeRoleWithWebIdentity.
type AssumeRoleWithWebIdentityInput struct {
	RoleARN          string
	RoleSessionName  string
	WebIdentityToken string
	DurationSeconds  int32
	Policy           string
	PolicyARNs       []string
}

// AssumeRoleWithWebIdentityOutput contains the response from AssumeRoleWithWebIdentity.
type AssumeRoleWithWebIdentityOutput struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
	AssumedRoleUser *AssumedRoleUser
}

// AssumedRoleUser contains information about the assumed role.
type AssumedRoleUser struct {
	ARN           string
	AssumedRoleID string
}

// IAMClient abstracts AWS IAM operations for testing.
type IAMClient interface {
	// Role operations
	GetRole(ctx context.Context, roleName string) (*Role, error)
	CreateRole(ctx context.Context, input *CreateRoleInput) (*Role, error)
	UpdateAssumeRolePolicy(ctx context.Context, roleName string, policy string) error
	DeleteRole(ctx context.Context, roleName string) error
	TagRole(ctx context.Context, roleName string, tags map[string]string) error

	// Policy operations
	AttachRolePolicy(ctx context.Context, roleName, policyARN string) error
	DetachRolePolicy(ctx context.Context, roleName, policyARN string) error
	PutRolePolicy(ctx context.Context, roleName, policyName, policyDocument string) error
	DeleteRolePolicy(ctx context.Context, roleName, policyName string) error
	ListAttachedRolePolicies(ctx context.Context, roleName string) ([]string, error)
	ListRolePolicies(ctx context.Context, roleName string) ([]string, error)

	// OIDC Provider operations
	GetOpenIDConnectProvider(ctx context.Context, arn string) (*OIDCProvider, error)
	CreateOpenIDConnectProvider(ctx context.Context, input *CreateOIDCProviderInput) (string, error)
	DeleteOpenIDConnectProvider(ctx context.Context, arn string) error
	ListOpenIDConnectProviders(ctx context.Context) ([]string, error)
}

// Role represents an AWS IAM role.
type Role struct {
	ARN                      string
	RoleName                 string
	AssumeRolePolicyDocument string
	Description              string
	MaxSessionDuration       int
	Tags                     map[string]string
}

// OIDCProvider represents an AWS IAM OIDC provider.
type OIDCProvider struct {
	ARN             string
	URL             string
	ClientIDList    []string
	ThumbprintList  []string
	Tags            map[string]string
}

// CreateRoleInput contains parameters for creating an IAM role.
type CreateRoleInput struct {
	RoleName                 string
	AssumeRolePolicyDocument string
	Description              string
	MaxSessionDuration       int
	PermissionsBoundary      string
	Tags                     map[string]string
}

// CreateOIDCProviderInput contains parameters for creating an OIDC provider.
type CreateOIDCProviderInput struct {
	URL            string
	ClientIDList   []string
	ThumbprintList []string
	Tags           map[string]string
}

// ProviderOption configures the Provider.
type ProviderOption func(*Provider)

// WithIAMClient sets the IAM client.
func WithIAMClient(client IAMClient) ProviderOption {
	return func(p *Provider) {
		p.client = client
	}
}

// WithSTSClient sets the STS client for token operations.
func WithSTSClient(client STSClient) ProviderOption {
	return func(p *Provider) {
		p.stsClient = client
	}
}

// New creates a new AWS provider.
func New(opts ...ProviderOption) *Provider {
	p := &Provider{}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Name implements cloudauth.Provider.
func (p *Provider) Name() cloudauth.CloudProvider {
	return cloudauth.ProviderAWS
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
	case *cloudauth.AWSRoleTrustOIDCSpec:
		return p.setupRoleTrustOIDC(ctx, s, opts)
	default:
		return nil, cloudauth.ErrValidation(fmt.Sprintf("unsupported spec type: %T", spec)).
			WithProvider(cloudauth.ProviderAWS)
	}
}

// setupRoleTrustOIDC creates or updates an AWS IAM role with OIDC trust.
func (p *Provider) setupRoleTrustOIDC(ctx context.Context, spec *cloudauth.AWSRoleTrustOIDCSpec, opts cloudauth.SetupOptions) (*cloudauth.Outputs, error) {
	var plan cloudauth.Plan
	var createdResources []string
	var oidcProviderARN string

	// Determine role name
	roleName := spec.RoleName
	if spec.RoleARN != "" {
		parts := strings.Split(spec.RoleARN, "/")
		roleName = parts[len(parts)-1]
	}

	// Step 1: Handle OIDC provider
	if spec.OIDCProviderARN != "" {
		oidcProviderARN = spec.OIDCProviderARN
	} else if spec.OIDCProviderURL != "" {
		// Check if provider already exists
		existingARN, err := p.findOIDCProviderByURL(ctx, spec.OIDCProviderURL)
		if err != nil {
			return nil, err
		}

		if existingARN != "" {
			oidcProviderARN = existingARN
		} else {
			// Need to create OIDC provider
			action := cloudauth.PlannedAction{
				Operation:    "create",
				ResourceType: "iam:oidc-provider",
				Details: map[string]interface{}{
					"url":      spec.OIDCProviderURL,
					"audience": spec.Audience,
				},
				Reversible: true,
			}
			plan.Actions = append(plan.Actions, action)

			if !opts.DryRun {
				thumbprint, err := getOIDCThumbprint(spec.OIDCProviderURL)
				if err != nil {
					return nil, cloudauth.ErrNetwork("failed to get OIDC thumbprint").WithCause(err)
				}

				arn, err := p.client.CreateOpenIDConnectProvider(ctx, &CreateOIDCProviderInput{
					URL:            spec.OIDCProviderURL,
					ClientIDList:   []string{spec.Audience},
					ThumbprintList: []string{thumbprint},
					Tags:           mergeTags(spec.Tags, opts.Tags),
				})
				if err != nil {
					return nil, cloudauth.ErrPermission("failed to create OIDC provider").
						WithCause(err).WithProvider(cloudauth.ProviderAWS)
				}
				oidcProviderARN = arn
				createdResources = append(createdResources, oidcProviderARN)
			}
		}
	}

	// Step 2: Create or update IAM role
	var existingRole *Role
	var roleExists bool
	if p.client != nil {
		var roleErr error
		existingRole, roleErr = p.client.GetRole(ctx, roleName)
		roleExists = roleErr == nil && existingRole != nil
	}

	if roleExists && existingRole != nil {
		// Update existing role
		action := cloudauth.PlannedAction{
			Operation:    "update",
			ResourceType: "iam:role",
			ResourceID:   existingRole.ARN,
			Details:      map[string]interface{}{"role_name": roleName},
			Reversible:   true,
		}
		plan.Actions = append(plan.Actions, action)
	} else {
		// Create new role
		action := cloudauth.PlannedAction{
			Operation:    "create",
			ResourceType: "iam:role",
			Details:      map[string]interface{}{"role_name": roleName},
			Reversible:   true,
		}
		plan.Actions = append(plan.Actions, action)
	}

	var roleARN string
	if !opts.DryRun {
		// Require client for non-dry-run operations
		if p.client == nil {
			return nil, cloudauth.ErrValidation("AWS IAM client not configured").
				WithProvider(cloudauth.ProviderAWS).
				WithDetail("hint", "Configure AWS credentials or use --dry-run")
		}

		// Build trust policy
		trustPolicy := buildTrustPolicy(oidcProviderARN, spec)
		trustPolicyJSON, err := json.Marshal(trustPolicy)
		if err != nil {
			return nil, cloudauth.ErrInternal("failed to marshal trust policy").WithCause(err)
		}

		if roleExists {
			// Update trust policy
			if err := p.client.UpdateAssumeRolePolicy(ctx, roleName, string(trustPolicyJSON)); err != nil {
				return nil, cloudauth.ErrPermission("failed to update role trust policy").
					WithCause(err).WithResource("iam:role", roleName)
			}
			roleARN = existingRole.ARN
		} else {
			// Create role
			description := spec.Description
			if description == "" {
				description = fmt.Sprintf("Cross-cloud auth role for %s federation", spec.Source)
			}

			maxDuration := spec.MaxSessionDuration
			if maxDuration == 0 {
				maxDuration = 3600
			}

			role, err := p.client.CreateRole(ctx, &CreateRoleInput{
				RoleName:                 roleName,
				AssumeRolePolicyDocument: string(trustPolicyJSON),
				Description:              description,
				MaxSessionDuration:       maxDuration,
				PermissionsBoundary:      spec.PermissionsBoundary,
				Tags:                     mergeTags(spec.Tags, opts.Tags),
			})
			if err != nil {
				// Rollback: delete OIDC provider if we created it
				if len(createdResources) > 0 {
					for _, res := range createdResources {
						_ = p.client.DeleteOpenIDConnectProvider(ctx, res)
					}
				}
				return nil, cloudauth.ErrPermission("failed to create role").
					WithCause(err).WithResource("iam:role", roleName)
			}
			roleARN = role.ARN
			createdResources = append(createdResources, roleARN)
		}

		// Step 3: Attach policies
		for _, policyARN := range spec.PolicyARNs {
			if err := p.client.AttachRolePolicy(ctx, roleName, policyARN); err != nil {
				// Rollback on error
				rollbackErr := p.rollback(ctx, createdResources, roleExists)
				return nil, &cloudauth.RollbackError{
					OriginalError:     cloudauth.ErrPermission("failed to attach policy").WithCause(err),
					RollbackErrors:    rollbackErr,
					CleanedResources:  nil, // Would be populated by rollback
					OrphanedResources: createdResources,
				}
			}
		}

		// Step 4: Add inline policy if specified
		if spec.InlinePolicy != "" {
			if err := p.client.PutRolePolicy(ctx, roleName, "cloud-auth-inline-policy", spec.InlinePolicy); err != nil {
				rollbackErr := p.rollback(ctx, createdResources, roleExists)
				return nil, &cloudauth.RollbackError{
					OriginalError:  cloudauth.ErrPermission("failed to add inline policy").WithCause(err),
					RollbackErrors: rollbackErr,
				}
			}
		}
	}

	// Build output
	resourceIDs := map[string]string{
		"role_arn":  roleARN,
		"role_name": roleName,
	}
	if oidcProviderARN != "" {
		resourceIDs["oidc_provider_arn"] = oidcProviderARN
	}

	ref := cloudauth.CreateMechanismRef(cloudauth.MechanismAWSRoleTrustOIDC, cloudauth.ProviderAWS, resourceIDs)

	if opts.DryRun {
		plan.Summary = fmt.Sprintf("Would create/update %d resources for AWS OIDC trust", len(plan.Actions))
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
			"role_arn":          roleARN,
			"oidc_provider_arn": oidcProviderARN,
		},
	}, nil
}

// Validate implements cloudauth.LifecycleProvider.
func (p *Provider) Validate(ctx context.Context, ref cloudauth.MechanismRef, opts cloudauth.ValidateOptions) (*cloudauth.ValidationReport, error) {
	var validators []cloudauth.Validator

	// Add standard validators based on mechanism type
	switch ref.Type {
	case cloudauth.MechanismAWSRoleTrustOIDC:
		roleName := ref.ResourceIDs["role_name"]
		if roleName == "" {
			return nil, cloudauth.ErrValidation("role_name not found in mechanism ref")
		}

		// Role exists validator
		validators = append(validators, &roleExistsValidator{client: p.client, roleName: roleName})

		// Trust policy validator
		if oidcARN := ref.ResourceIDs["oidc_provider_arn"]; oidcARN != "" {
			validators = append(validators, &oidcProviderExistsValidator{client: p.client, arn: oidcARN})
		}
	}

	report := cloudauth.RunValidation(ctx, ref, validators)
	return report, nil
}

// Delete implements cloudauth.LifecycleProvider.
func (p *Provider) Delete(ctx context.Context, ref cloudauth.MechanismRef, opts cloudauth.DeleteOptions) error {
	switch ref.Type {
	case cloudauth.MechanismAWSRoleTrustOIDC:
		return p.deleteRoleTrustOIDC(ctx, ref, opts)
	default:
		return cloudauth.ErrValidation(fmt.Sprintf("unsupported mechanism type: %s", ref.Type))
	}
}

func (p *Provider) deleteRoleTrustOIDC(ctx context.Context, ref cloudauth.MechanismRef, opts cloudauth.DeleteOptions) error {
	roleName := ref.ResourceIDs["role_name"]
	if roleName == "" {
		return cloudauth.ErrValidation("role_name not found in mechanism ref")
	}

	if opts.DryRun {
		return nil // Would just return the plan
	}

	// Step 1: Detach all managed policies
	attachedPolicies, err := p.client.ListAttachedRolePolicies(ctx, roleName)
	if err == nil {
		for _, policyARN := range attachedPolicies {
			if err := p.client.DetachRolePolicy(ctx, roleName, policyARN); err != nil {
				return cloudauth.ErrPermission("failed to detach policy").
					WithCause(err).WithResource("iam:policy", policyARN)
			}
		}
	}

	// Step 2: Delete all inline policies
	inlinePolicies, err := p.client.ListRolePolicies(ctx, roleName)
	if err == nil {
		for _, policyName := range inlinePolicies {
			if err := p.client.DeleteRolePolicy(ctx, roleName, policyName); err != nil {
				return cloudauth.ErrPermission("failed to delete inline policy").
					WithCause(err).WithResource("iam:inline-policy", policyName)
			}
		}
	}

	// Step 3: Delete the role
	if err := p.client.DeleteRole(ctx, roleName); err != nil {
		// Check if already deleted (idempotent)
		if !isNotFoundError(err) {
			return cloudauth.ErrPermission("failed to delete role").
				WithCause(err).WithResource("iam:role", roleName)
		}
	}

	// Step 4: Optionally delete OIDC provider if owned
	if ref.Owned {
		if oidcARN := ref.ResourceIDs["oidc_provider_arn"]; oidcARN != "" {
			if err := p.client.DeleteOpenIDConnectProvider(ctx, oidcARN); err != nil {
				if !isNotFoundError(err) {
					return cloudauth.ErrPermission("failed to delete OIDC provider").
						WithCause(err).WithResource("iam:oidc-provider", oidcARN)
				}
			}
		}
	}

	return nil
}

// Token implements cloudauth.TokenProvider.
// It exchanges an OIDC/JWT token for AWS credentials using AssumeRoleWithWebIdentity.
//
// TokenRequest fields:
//   - TargetIdentity: The ARN of the IAM role to assume (required)
//   - SourceIdentity: Used as the role session name (optional, defaults to "cloud-auth-session")
//   - Audience: The web identity token/JWT to exchange (required - passed via Audience field)
//   - Duration: Session duration in seconds (optional, defaults to 3600)
//
// Returns AWS credentials as a JSON-encoded string in TokenResponse.Token containing:
//   - access_key_id, secret_access_key, session_token
func (p *Provider) Token(ctx context.Context, req cloudauth.TokenRequest) (*cloudauth.TokenResponse, error) {
	if p.stsClient == nil {
		return nil, cloudauth.ErrValidation("AWS STS client not configured").
			WithProvider(cloudauth.ProviderAWS).
			WithDetail("hint", "Configure AWS STS client using WithSTSClient option")
	}

	// Validate required fields
	if req.TargetIdentity == "" {
		return nil, cloudauth.ErrValidation("TargetIdentity (role ARN) is required").
			WithProvider(cloudauth.ProviderAWS)
	}

	// The web identity token should be passed - we use Audience field for the token
	// since it's the most semantically appropriate field in TokenRequest
	webIdentityToken := req.Audience
	if webIdentityToken == "" {
		return nil, cloudauth.ErrValidation("Audience (web identity token) is required").
			WithProvider(cloudauth.ProviderAWS).
			WithDetail("hint", "Pass the OIDC/JWT token in the Audience field")
	}

	// Set defaults
	roleSessionName := req.SourceIdentity
	if roleSessionName == "" {
		roleSessionName = "cloud-auth-session"
	}

	// Sanitize session name (must match [\w+=,.@-]*)
	roleSessionName = sanitizeSessionName(roleSessionName)

	durationSeconds := int32(req.Duration)
	if durationSeconds == 0 {
		durationSeconds = 3600 // Default 1 hour
	}

	// Call STS AssumeRoleWithWebIdentity
	input := &AssumeRoleWithWebIdentityInput{
		RoleARN:          req.TargetIdentity,
		RoleSessionName:  roleSessionName,
		WebIdentityToken: webIdentityToken,
		DurationSeconds:  durationSeconds,
	}

	output, err := p.stsClient.AssumeRoleWithWebIdentity(ctx, input)
	if err != nil {
		return nil, cloudauth.ErrAuth("failed to assume role with web identity").
			WithCause(err).
			WithProvider(cloudauth.ProviderAWS).
			WithResource("iam:role", req.TargetIdentity)
	}

	// Build credentials response as JSON
	credentials := map[string]interface{}{
		"access_key_id":     output.AccessKeyID,
		"secret_access_key": output.SecretAccessKey,
		"session_token":     output.SessionToken,
		"expiration":        output.Expiration.Format(time.RFC3339),
	}

	if output.AssumedRoleUser != nil {
		credentials["assumed_role_arn"] = output.AssumedRoleUser.ARN
		credentials["assumed_role_id"] = output.AssumedRoleUser.AssumedRoleID
	}

	credentialsJSON, err := json.Marshal(credentials)
	if err != nil {
		return nil, cloudauth.ErrInternal("failed to marshal credentials").WithCause(err)
	}

	return &cloudauth.TokenResponse{
		Token:     string(credentialsJSON),
		ExpiresAt: output.Expiration.Unix(),
		TokenType: "aws-credentials",
		Scopes:    req.Scopes,
	}, nil
}

// GenerateGCPWorkloadIdentityToken creates a signed AWS STS GetCallerIdentity request
// that can be used with GCP Workload Identity Federation.
//
// This enables AWS workloads to authenticate to GCP without using long-lived credentials.
// The returned token is a JSON object containing the signed request that GCP STS can validate.
//
// Usage:
//
//	token, err := awsProvider.GenerateGCPWorkloadIdentityToken(ctx, &GCPWorkloadIdentityInput{
//	    ProjectNumber: "123456789012",
//	    PoolID:        "my-pool",
//	    ProviderID:    "aws-provider",
//	})
//	// Use token.Token with GCP provider's Token() method
func (p *Provider) GenerateGCPWorkloadIdentityToken(ctx context.Context, input *GCPWorkloadIdentityInput) (*CrossCloudTokenOutput, error) {
	if p.stsClient == nil {
		return nil, cloudauth.ErrValidation("AWS STS client not configured").
			WithProvider(cloudauth.ProviderAWS).
			WithDetail("hint", "Configure AWS STS client using WithSTSClient option")
	}

	// Validate input
	if input.ProjectNumber == "" {
		return nil, cloudauth.ErrValidation("ProjectNumber is required").WithProvider(cloudauth.ProviderAWS)
	}
	if input.PoolID == "" {
		return nil, cloudauth.ErrValidation("PoolID is required").WithProvider(cloudauth.ProviderAWS)
	}
	if input.ProviderID == "" {
		return nil, cloudauth.ErrValidation("ProviderID is required").WithProvider(cloudauth.ProviderAWS)
	}

	// Build the GCP audience (full resource name of the WIF provider)
	audience := fmt.Sprintf("//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s",
		input.ProjectNumber, input.PoolID, input.ProviderID)

	// Set default region
	region := input.Region
	if region == "" {
		region = "us-east-1"
	}

	// Create the STS GetCallerIdentity request to sign
	stsURL := fmt.Sprintf("https://sts.%s.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15", region)

	// Sign the request with the x-goog-cloud-target-resource header
	signInput := &SignRequestInput{
		Method:  "POST",
		URL:     stsURL,
		Region:  region,
		Service: "sts",
		Headers: map[string]string{
			"x-goog-cloud-target-resource": audience,
		},
	}

	signOutput, err := p.stsClient.SignRequest(ctx, signInput)
	if err != nil {
		return nil, cloudauth.ErrAuth("failed to sign request for GCP WIF").
			WithCause(err).WithProvider(cloudauth.ProviderAWS)
	}

	// Build the token in the format expected by GCP
	token := map[string]interface{}{
		"url":     signOutput.URL,
		"method":  signOutput.Method,
		"headers": signOutput.Headers,
	}

	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return nil, cloudauth.ErrInternal("failed to marshal GCP WIF token").WithCause(err)
	}

	return &CrossCloudTokenOutput{
		Token:     string(tokenJSON),
		TokenType: "urn:ietf:params:aws:token-type:aws4_request",
		Audience:  audience,
		// AWS signed requests are valid for a short time (typically 15 minutes)
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}, nil
}

// GenerateAzureFederatedToken attempts to generate a token for Azure federation.
// Note: AWS does not expose an OIDC token endpoint, so direct AWS → Azure federation
// is not natively supported. This method returns an error explaining the limitation.
//
// For AWS → Azure authentication, consider:
//  1. Using an intermediate identity broker (e.g., HashiCorp Vault)
//  2. Running your workload in a container with an OIDC-capable identity provider
//  3. Using AWS Lambda with GitHub Actions OIDC as an intermediary
func (p *Provider) GenerateAzureFederatedToken(ctx context.Context, input *AzureFederatedTokenInput) (*CrossCloudTokenOutput, error) {
	return nil, cloudauth.ErrValidation("AWS → Azure direct federation is not supported").
		WithProvider(cloudauth.ProviderAWS).
		WithDetail("reason", "AWS does not expose an OIDC token endpoint that Azure can consume").
		WithDetail("alternatives", "Use an identity broker like Vault, or use a service that provides OIDC tokens")
}

// sanitizeSessionName removes invalid characters from role session name.
// AWS requires session names to match [\w+=,.@-]*
func sanitizeSessionName(name string) string {
	var result strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '_' || r == '+' || r == '=' || r == ',' || r == '.' || r == '@' || r == '-' {
			result.WriteRune(r)
		}
	}
	sanitized := result.String()
	if sanitized == "" {
		return "cloud-auth-session"
	}
	// AWS limits session name to 64 characters
	if len(sanitized) > 64 {
		sanitized = sanitized[:64]
	}
	return sanitized
}

// Helper functions

func (p *Provider) findOIDCProviderByURL(ctx context.Context, url string) (string, error) {
	// If no client configured, return empty (will create new provider)
	if p.client == nil {
		return "", nil
	}

	providers, err := p.client.ListOpenIDConnectProviders(ctx)
	if err != nil {
		return "", err
	}

	for _, arn := range providers {
		provider, err := p.client.GetOpenIDConnectProvider(ctx, arn)
		if err != nil {
			continue
		}
		if provider.URL == url || provider.URL == strings.TrimSuffix(url, "/") {
			return arn, nil
		}
	}
	return "", nil
}

func (p *Provider) rollback(ctx context.Context, resources []string, roleExisted bool) []error {
	var errors []error
	for _, res := range resources {
		if strings.Contains(res, ":oidc-provider/") {
			if err := p.client.DeleteOpenIDConnectProvider(ctx, res); err != nil {
				errors = append(errors, err)
			}
		} else if strings.Contains(res, ":role/") && !roleExisted {
			parts := strings.Split(res, "/")
			roleName := parts[len(parts)-1]
			if err := p.client.DeleteRole(ctx, roleName); err != nil {
				errors = append(errors, err)
			}
		}
	}
	return errors
}

func buildTrustPolicy(oidcProviderARN string, spec *cloudauth.AWSRoleTrustOIDCSpec) map[string]interface{} {
	condition := map[string]interface{}{
		"StringEquals": map[string]string{
			oidcProviderARN + ":aud": spec.Audience,
		},
	}

	if spec.Subject != "" {
		conditionKey := "StringEquals"
		if spec.SubjectCondition != "" {
			conditionKey = spec.SubjectCondition
		}
		condition[conditionKey].(map[string]string)[oidcProviderARN+":sub"] = spec.Subject
	}

	return map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []map[string]interface{}{
			{
				"Effect": "Allow",
				"Principal": map[string]string{
					"Federated": oidcProviderARN,
				},
				"Action": "sts:AssumeRoleWithWebIdentity",
				"Condition": condition,
			},
		},
	}
}

func mergeTags(base, overlay map[string]string) map[string]string {
	result := make(map[string]string)
	for k, v := range base {
		result[k] = v
	}
	for k, v := range overlay {
		result[k] = v
	}
	// Add standard cloud-auth tag
	result["managed-by"] = "cloud-auth"
	return result
}

func getOIDCThumbprint(url string) (string, error) {
	// Simplified - in production would actually fetch and compute thumbprint
	// For well-known providers, use known thumbprints
	knownThumbprints := map[string]string{
		"https://token.actions.githubusercontent.com": "6938fd4d98bab03faadb97b34396831e3780aea1",
		"https://accounts.google.com":                 "08745487e891c19e3078c1f2a07e452950ef36f6",
	}

	if thumb, ok := knownThumbprints[url]; ok {
		return thumb, nil
	}

	// TODO: Implement actual thumbprint calculation
	return "0000000000000000000000000000000000000000", nil
}

func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "NoSuchEntity") ||
		strings.Contains(err.Error(), "not found") ||
		cloudauth.IsCategory(err, cloudauth.ErrCategoryNotFound)
}

// Validators

type roleExistsValidator struct {
	client   IAMClient
	roleName string
}

func (v *roleExistsValidator) ID() string          { return "aws_role_exists" }
func (v *roleExistsValidator) Name() string        { return "AWS Role Exists" }
func (v *roleExistsValidator) Description() string { return "Checks if the IAM role exists" }

func (v *roleExistsValidator) Validate(ctx context.Context, ref cloudauth.MechanismRef) cloudauth.ValidationCheck {
	check := cloudauth.ValidationCheck{
		ID:          v.ID(),
		Name:        v.Name(),
		Description: v.Description(),
		Severity:    cloudauth.SeverityCritical,
		Evidence:    map[string]interface{}{"role_name": v.roleName},
	}

	role, err := v.client.GetRole(ctx, v.roleName)
	if err != nil {
		check.Status = cloudauth.CheckStatusFailed
		check.Evidence["error"] = err.Error()
		check.Remediation = "Create the IAM role or run setup again"
		return check
	}

	check.Status = cloudauth.CheckStatusPassed
	check.Evidence["role_arn"] = role.ARN
	return check
}

type oidcProviderExistsValidator struct {
	client IAMClient
	arn    string
}

func (v *oidcProviderExistsValidator) ID() string          { return "aws_oidc_provider_exists" }
func (v *oidcProviderExistsValidator) Name() string        { return "OIDC Provider Exists" }
func (v *oidcProviderExistsValidator) Description() string { return "Checks if the OIDC provider exists" }

func (v *oidcProviderExistsValidator) Validate(ctx context.Context, ref cloudauth.MechanismRef) cloudauth.ValidationCheck {
	check := cloudauth.ValidationCheck{
		ID:          v.ID(),
		Name:        v.Name(),
		Description: v.Description(),
		Severity:    cloudauth.SeverityCritical,
		Evidence:    map[string]interface{}{"oidc_provider_arn": v.arn},
	}

	provider, err := v.client.GetOpenIDConnectProvider(ctx, v.arn)
	if err != nil {
		check.Status = cloudauth.CheckStatusFailed
		check.Evidence["error"] = err.Error()
		check.Remediation = "Create the OIDC provider or run setup again"
		return check
	}

	check.Status = cloudauth.CheckStatusPassed
	check.Evidence["url"] = provider.URL
	return check
}

func init() {
	// Register with default registry
	cloudauth.Register(New())
}

