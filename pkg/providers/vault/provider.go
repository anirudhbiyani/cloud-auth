// Package vault provides HashiCorp Vault identity broker provider implementation.
package vault

import (
	"context"
	"fmt"
	"time"

	"github.com/anirudhbiyani/cloud-auth/pkg/cloudauth"
)

// Provider implements cloudauth.LifecycleProvider for HashiCorp Vault.
type Provider struct {
	client VaultClient
}

// VaultClient abstracts Vault API operations for testing.
type VaultClient interface {
	// Auth method operations
	EnableAuthMethod(ctx context.Context, path string, methodType string, config *AuthMethodConfig) error
	DisableAuthMethod(ctx context.Context, path string) error
	ReadAuthMethod(ctx context.Context, path string) (*AuthMethod, error)
	TuneAuthMethod(ctx context.Context, path string, config *AuthMethodConfig) error

	// JWT/OIDC Auth operations
	WriteJWTRole(ctx context.Context, path, roleName string, role *JWTRole) error
	ReadJWTRole(ctx context.Context, path, roleName string) (*JWTRole, error)
	DeleteJWTRole(ctx context.Context, path, roleName string) error
	WriteJWTConfig(ctx context.Context, path string, config *JWTAuthConfig) error
	ReadJWTConfig(ctx context.Context, path string) (*JWTAuthConfig, error)

	// AWS Auth operations
	WriteAWSRole(ctx context.Context, path, roleName string, role *AWSRole) error
	ReadAWSRole(ctx context.Context, path, roleName string) (*AWSRole, error)
	DeleteAWSRole(ctx context.Context, path, roleName string) error
	WriteAWSConfig(ctx context.Context, path string, config *AWSAuthConfig) error

	// Secrets Engine operations
	EnableSecretsEngine(ctx context.Context, path, engineType string, config *SecretsEngineConfig) error
	DisableSecretsEngine(ctx context.Context, path string) error

	// AWS Secrets Engine operations
	WriteAWSSecretsRole(ctx context.Context, path, roleName string, role *AWSSecretsRole) error
	ReadAWSSecretsRole(ctx context.Context, path, roleName string) (*AWSSecretsRole, error)
	GenerateAWSCredentials(ctx context.Context, path, roleName string) (*AWSCredentials, error)
	GenerateAWSCredentialsWithTTL(ctx context.Context, path, roleName, ttl string) (*AWSCredentials, error)
	GenerateAWSSTSCredentials(ctx context.Context, path, roleName, roleARN, ttl string) (*AWSCredentials, error)

	// GCP Secrets Engine operations
	GenerateGCPAccessToken(ctx context.Context, path, roleName string) (*GCPAccessToken, error)
	GenerateGCPServiceAccountKey(ctx context.Context, path, roleName string) (*GCPServiceAccountKey, error)

	// Azure Secrets Engine operations
	GenerateAzureCredentials(ctx context.Context, path, roleName string) (*AzureCredentials, error)

	// Policy operations
	WritePolicy(ctx context.Context, name, policy string) error
	DeletePolicy(ctx context.Context, name string) error
	ReadPolicy(ctx context.Context, name string) (string, error)

	// Token operations
	CreateToken(ctx context.Context, opts *CreateTokenOptions) (*TokenResponse, error)
}

// AuthMethod represents a Vault auth method.
type AuthMethod struct {
	Type        string
	Path        string
	Description string
	Config      *AuthMethodConfig
}

// AuthMethodConfig contains auth method configuration.
type AuthMethodConfig struct {
	DefaultLeaseTTL string
	MaxLeaseTTL     string
	Description     string
}

// JWTRole represents a Vault JWT auth role.
type JWTRole struct {
	RoleType          string   `json:"role_type,omitempty"`
	BoundAudiences    []string `json:"bound_audiences,omitempty"`
	BoundSubject      string   `json:"bound_subject,omitempty"`
	BoundClaims       map[string]interface{} `json:"bound_claims,omitempty"`
	ClaimMappings     map[string]string `json:"claim_mappings,omitempty"`
	UserClaim         string   `json:"user_claim,omitempty"`
	GroupsClaim       string   `json:"groups_claim,omitempty"`
	TokenPolicies     []string `json:"token_policies,omitempty"`
	TokenTTL          int      `json:"token_ttl,omitempty"`
	TokenMaxTTL       int      `json:"token_max_ttl,omitempty"`
	TokenBoundCIDRs   []string `json:"token_bound_cidrs,omitempty"`
	AllowedRedirectURIs []string `json:"allowed_redirect_uris,omitempty"`
}

// JWTAuthConfig contains JWT auth method configuration.
type JWTAuthConfig struct {
	OIDCDiscoveryURL   string   `json:"oidc_discovery_url,omitempty"`
	OIDCClientID       string   `json:"oidc_client_id,omitempty"`
	OIDCClientSecret   string   `json:"oidc_client_secret,omitempty"`
	JWKSUrl            string   `json:"jwks_url,omitempty"`
	JWKSCAPEM          string   `json:"jwks_ca_pem,omitempty"`
	JWTValidationPubKeys []string `json:"jwt_validation_pubkeys,omitempty"`
	BoundIssuer        string   `json:"bound_issuer,omitempty"`
	DefaultRole        string   `json:"default_role,omitempty"`
}

// AWSRole represents a Vault AWS auth role.
type AWSRole struct {
	AuthType                    string   `json:"auth_type,omitempty"`
	BoundAccountID              []string `json:"bound_account_id,omitempty"`
	BoundIAMPrincipalARN        []string `json:"bound_iam_principal_arn,omitempty"`
	BoundIAMRoleARN             []string `json:"bound_iam_role_arn,omitempty"`
	BoundEC2InstanceID          []string `json:"bound_ec2_instance_id,omitempty"`
	BoundRegion                 []string `json:"bound_region,omitempty"`
	BoundVPCID                  []string `json:"bound_vpc_id,omitempty"`
	BoundSubnetID               []string `json:"bound_subnet_id,omitempty"`
	InferredAWSRegion           string   `json:"inferred_aws_region,omitempty"`
	InferredEntityType          string   `json:"inferred_entity_type,omitempty"`
	TokenPolicies               []string `json:"token_policies,omitempty"`
	TokenTTL                    int      `json:"token_ttl,omitempty"`
	TokenMaxTTL                 int      `json:"token_max_ttl,omitempty"`
	ResolveAWSUniqueIDs         bool     `json:"resolve_aws_unique_ids,omitempty"`
}

// AWSAuthConfig contains AWS auth method configuration.
type AWSAuthConfig struct {
	AccessKey         string   `json:"access_key,omitempty"`
	SecretKey         string   `json:"secret_key,omitempty"`
	IAMServerIDHeader string   `json:"iam_server_id_header_value,omitempty"`
	STSEndpoint       string   `json:"sts_endpoint,omitempty"`
	STSRegion         string   `json:"sts_region,omitempty"`
	AllowedSTSHeaders []string `json:"allowed_sts_header_values,omitempty"`
}

// SecretsEngineConfig contains secrets engine configuration.
type SecretsEngineConfig struct {
	DefaultLeaseTTL string
	MaxLeaseTTL     string
	Description     string
}

// AWSSecretsRole represents a Vault AWS secrets engine role.
type AWSSecretsRole struct {
	CredentialType      string   `json:"credential_type"`
	RoleARNs            []string `json:"role_arns,omitempty"`
	PolicyARNs          []string `json:"policy_arns,omitempty"`
	PolicyDocument      string   `json:"policy_document,omitempty"`
	IAMGroups           []string `json:"iam_groups,omitempty"`
	DefaultSTSTTL       int      `json:"default_sts_ttl,omitempty"`
	MaxSTSTTL           int      `json:"max_sts_ttl,omitempty"`
	UserPath            string   `json:"user_path,omitempty"`
	PermissionsBoundary string   `json:"permissions_boundary_arn,omitempty"`
}

// AWSCredentials represents generated AWS credentials.
type AWSCredentials struct {
	AccessKey     string
	SecretKey     string
	SessionToken  string
	LeaseDuration int
	LeaseID       string
}

// GCPAccessToken represents a generated GCP access token.
type GCPAccessToken struct {
	Token         string
	ExpiresAtSeconds int64
	TokenTTL      int
	LeaseID       string
	LeaseDuration int
}

// GCPServiceAccountKey represents a generated GCP service account key.
type GCPServiceAccountKey struct {
	PrivateKeyData string // Base64-encoded JSON key
	KeyAlgorithm   string
	KeyType        string
	LeaseID        string
	LeaseDuration  int
}

// AzureCredentials represents generated Azure credentials.
type AzureCredentials struct {
	ClientID      string
	ClientSecret  string
	LeaseDuration int
	LeaseID       string
}

// CreateTokenOptions contains options for creating a Vault token.
type CreateTokenOptions struct {
	Policies     []string
	TTL          string
	DisplayName  string
	NumUses      int
	Renewable    bool
	Metadata     map[string]string
}

// TokenResponse contains a created Vault token.
type TokenResponse struct {
	Token         string
	Accessor      string
	LeaseDuration int
	Renewable     bool
	Policies      []string
}

// CrossCloudTokenOutput contains credentials for cross-cloud authentication.
type CrossCloudTokenOutput struct {
	// Token is the primary credential (access token or access key).
	Token string
	// Secret is the secondary credential if applicable (secret key).
	Secret string
	// SessionToken is an optional session token (for AWS STS).
	SessionToken string
	// TokenType describes the type of credentials.
	TokenType string
	// ExpiresAt is when the credentials expire.
	ExpiresAt time.Time
	// Provider is the target cloud provider.
	Provider cloudauth.CloudProvider
	// LeaseID is the Vault lease ID for renewal/revocation.
	LeaseID string
}

// GenerateAWSCredentialsInput contains parameters for generating AWS credentials via Vault.
type GenerateAWSCredentialsInput struct {
	// SecretsEnginePath is the path to the AWS secrets engine (default: "aws").
	SecretsEnginePath string
	// RoleName is the name of the AWS secrets engine role.
	RoleName string
	// TTL is the requested credential TTL (optional).
	TTL string
	// RoleARN is for assuming a specific AWS role (STS credentials only).
	RoleARN string
}

// GenerateAzureCredentialsInput contains parameters for generating Azure credentials via Vault.
type GenerateAzureCredentialsInput struct {
	// SecretsEnginePath is the path to the Azure secrets engine (default: "azure").
	SecretsEnginePath string
	// RoleName is the name of the Azure secrets engine role.
	RoleName string
}

// GenerateGCPCredentialsInput contains parameters for generating GCP credentials via Vault.
type GenerateGCPCredentialsInput struct {
	// SecretsEnginePath is the path to the GCP secrets engine (default: "gcp").
	SecretsEnginePath string
	// RoleName is the name of the GCP secrets engine role.
	RoleName string
	// KeyType is the type of key to generate ("access_token" or "service_account_key").
	KeyType string
}

// VaultBrokerSpec specifies a Vault identity broker configuration.
type VaultBrokerSpec struct {
	// VaultAddress is the Vault server address.
	VaultAddress string `json:"vault_address" yaml:"vault_address"`

	// AuthMethodPath is the path for the auth method.
	AuthMethodPath string `json:"auth_method_path" yaml:"auth_method_path"`

	// AuthMethodType is the type of auth method ("jwt", "aws", etc.).
	AuthMethodType string `json:"auth_method_type" yaml:"auth_method_type"`

	// RoleName is the name of the role to create.
	RoleName string `json:"role_name" yaml:"role_name"`

	// JWTConfig is for JWT/OIDC auth methods.
	JWTConfig *JWTAuthConfig `json:"jwt_config,omitempty" yaml:"jwt_config,omitempty"`

	// JWTRole is the JWT role configuration.
	JWTRole *JWTRole `json:"jwt_role,omitempty" yaml:"jwt_role,omitempty"`

	// AWSConfig is for AWS auth methods.
	AWSConfig *AWSAuthConfig `json:"aws_config,omitempty" yaml:"aws_config,omitempty"`

	// AWSRole is the AWS role configuration.
	AWSRole *AWSRole `json:"aws_role,omitempty" yaml:"aws_role,omitempty"`

	// Policies to grant to authenticated entities.
	Policies []string `json:"policies,omitempty" yaml:"policies,omitempty"`

	// PolicyDocument is an inline policy to create.
	PolicyDocument string `json:"policy_document,omitempty" yaml:"policy_document,omitempty"`

	// Source identifies the source identity provider.
	Source cloudauth.CloudProvider `json:"source" yaml:"source"`
}

// Type implements cloudauth.MechanismSpec.
func (s *VaultBrokerSpec) Type() cloudauth.MechanismType {
	return "vault_broker"
}

// Validate implements cloudauth.MechanismSpec.
func (s *VaultBrokerSpec) Validate() error {
	if s.VaultAddress == "" {
		return fmt.Errorf("vault_address is required")
	}
	if s.AuthMethodPath == "" {
		return fmt.Errorf("auth_method_path is required")
	}
	if s.AuthMethodType == "" {
		return fmt.Errorf("auth_method_type is required")
	}
	if s.RoleName == "" {
		return fmt.Errorf("role_name is required")
	}

	switch s.AuthMethodType {
	case "jwt", "oidc":
		if s.JWTConfig == nil && s.JWTRole == nil {
			return fmt.Errorf("jwt_config or jwt_role is required for JWT auth")
		}
	case "aws":
		if s.AWSRole == nil {
			return fmt.Errorf("aws_role is required for AWS auth")
		}
	default:
		return fmt.Errorf("unsupported auth_method_type: %s", s.AuthMethodType)
	}

	return nil
}

// SourceProvider implements cloudauth.MechanismSpec.
func (s *VaultBrokerSpec) SourceProvider() cloudauth.CloudProvider {
	return s.Source
}

// TargetProvider implements cloudauth.MechanismSpec.
func (s *VaultBrokerSpec) TargetProvider() cloudauth.CloudProvider {
	return cloudauth.ProviderVault
}

// ProviderOption configures the Provider.
type ProviderOption func(*Provider)

// WithVaultClient sets the Vault client.
func WithVaultClient(client VaultClient) ProviderOption {
	return func(p *Provider) {
		p.client = client
	}
}

// New creates a new Vault provider.
func New(opts ...ProviderOption) *Provider {
	p := &Provider{}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Name implements cloudauth.Provider.
func (p *Provider) Name() cloudauth.CloudProvider {
	return cloudauth.ProviderVault
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
	vaultSpec, ok := spec.(*VaultBrokerSpec)
	if !ok {
		return nil, cloudauth.ErrValidation(fmt.Sprintf("unsupported spec type: %T", spec)).
			WithProvider(cloudauth.ProviderVault)
	}

	var plan cloudauth.Plan
	resourceIDs := make(map[string]string)

	resourceIDs["vault_address"] = vaultSpec.VaultAddress
	resourceIDs["auth_path"] = vaultSpec.AuthMethodPath
	resourceIDs["role_name"] = vaultSpec.RoleName

	// Step 1: Enable auth method if not exists
	_, err := p.client.ReadAuthMethod(ctx, vaultSpec.AuthMethodPath)
	authExists := err == nil

	if !authExists {
		action := cloudauth.PlannedAction{
			Operation:    "create",
			ResourceType: "auth-method",
			Details: map[string]interface{}{
				"path": vaultSpec.AuthMethodPath,
				"type": vaultSpec.AuthMethodType,
			},
			Reversible: true,
		}
		plan.Actions = append(plan.Actions, action)

		if !opts.DryRun {
			err := p.client.EnableAuthMethod(ctx, vaultSpec.AuthMethodPath, vaultSpec.AuthMethodType, nil)
			if err != nil {
				return nil, cloudauth.ErrPermission("failed to enable auth method").
					WithCause(err).WithProvider(cloudauth.ProviderVault)
			}
		}
	}

	// Step 2: Configure auth method
	if vaultSpec.JWTConfig != nil {
		action := cloudauth.PlannedAction{
			Operation:    "update",
			ResourceType: "jwt-config",
			Details:      map[string]interface{}{"path": vaultSpec.AuthMethodPath},
			Reversible:   true,
		}
		plan.Actions = append(plan.Actions, action)

		if !opts.DryRun {
			if err := p.client.WriteJWTConfig(ctx, vaultSpec.AuthMethodPath, vaultSpec.JWTConfig); err != nil {
				return nil, cloudauth.ErrPermission("failed to configure JWT auth").
					WithCause(err).WithProvider(cloudauth.ProviderVault)
			}
		}
	}

	if vaultSpec.AWSConfig != nil {
		action := cloudauth.PlannedAction{
			Operation:    "update",
			ResourceType: "aws-config",
			Details:      map[string]interface{}{"path": vaultSpec.AuthMethodPath},
			Reversible:   true,
		}
		plan.Actions = append(plan.Actions, action)

		if !opts.DryRun {
			if err := p.client.WriteAWSConfig(ctx, vaultSpec.AuthMethodPath, vaultSpec.AWSConfig); err != nil {
				return nil, cloudauth.ErrPermission("failed to configure AWS auth").
					WithCause(err).WithProvider(cloudauth.ProviderVault)
			}
		}
	}

	// Step 3: Create role
	action := cloudauth.PlannedAction{
		Operation:    "create",
		ResourceType: "auth-role",
		Details: map[string]interface{}{
			"path": vaultSpec.AuthMethodPath,
			"name": vaultSpec.RoleName,
		},
		Reversible: true,
	}
	plan.Actions = append(plan.Actions, action)

	if !opts.DryRun {
		switch vaultSpec.AuthMethodType {
		case "jwt", "oidc":
			if vaultSpec.JWTRole != nil {
				if err := p.client.WriteJWTRole(ctx, vaultSpec.AuthMethodPath, vaultSpec.RoleName, vaultSpec.JWTRole); err != nil {
					return nil, cloudauth.ErrPermission("failed to create JWT role").
						WithCause(err).WithProvider(cloudauth.ProviderVault)
				}
			}
		case "aws":
			if vaultSpec.AWSRole != nil {
				if err := p.client.WriteAWSRole(ctx, vaultSpec.AuthMethodPath, vaultSpec.RoleName, vaultSpec.AWSRole); err != nil {
					return nil, cloudauth.ErrPermission("failed to create AWS role").
						WithCause(err).WithProvider(cloudauth.ProviderVault)
				}
			}
		}
	}

	// Step 4: Create policy if specified
	if vaultSpec.PolicyDocument != "" {
		policyName := "cloud-auth-" + vaultSpec.RoleName
		action := cloudauth.PlannedAction{
			Operation:    "create",
			ResourceType: "policy",
			Details:      map[string]interface{}{"name": policyName},
			Reversible:   true,
		}
		plan.Actions = append(plan.Actions, action)

		if !opts.DryRun {
			if err := p.client.WritePolicy(ctx, policyName, vaultSpec.PolicyDocument); err != nil {
				return nil, cloudauth.ErrPermission("failed to create policy").
					WithCause(err).WithProvider(cloudauth.ProviderVault)
			}
			resourceIDs["policy_name"] = policyName
		}
	}

	ref := cloudauth.CreateMechanismRef("vault_broker", cloudauth.ProviderVault, resourceIDs)
	ref.Owned = !authExists // Only own if we created the auth method

	if opts.DryRun {
		plan.Summary = fmt.Sprintf("Would create/update %d Vault resources", len(plan.Actions))
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
			"auth_path": vaultSpec.AuthMethodPath,
			"role_name": vaultSpec.RoleName,
		},
		Instructions: []string{
			fmt.Sprintf("Authenticate via: vault write auth/%s/login role=%s jwt=<token>", vaultSpec.AuthMethodPath, vaultSpec.RoleName),
		},
	}, nil
}

// Validate implements cloudauth.LifecycleProvider.
func (p *Provider) Validate(ctx context.Context, ref cloudauth.MechanismRef, opts cloudauth.ValidateOptions) (*cloudauth.ValidationReport, error) {
	var validators []cloudauth.Validator

	authPath := ref.ResourceIDs["auth_path"]
	roleName := ref.ResourceIDs["role_name"]

	if authPath != "" {
		validators = append(validators, &authMethodExistsValidator{
			client: p.client,
			path:   authPath,
		})
	}

	if authPath != "" && roleName != "" {
		validators = append(validators, &roleExistsValidator{
			client:   p.client,
			authPath: authPath,
			roleName: roleName,
		})
	}

	report := cloudauth.RunValidation(ctx, ref, validators)
	return report, nil
}

// Delete implements cloudauth.LifecycleProvider.
func (p *Provider) Delete(ctx context.Context, ref cloudauth.MechanismRef, opts cloudauth.DeleteOptions) error {
	if opts.DryRun {
		return nil
	}

	authPath := ref.ResourceIDs["auth_path"]
	roleName := ref.ResourceIDs["role_name"]

	// Delete role first
	if authPath != "" && roleName != "" {
		// Try both JWT and AWS role deletion
		_ = p.client.DeleteJWTRole(ctx, authPath, roleName)
		_ = p.client.DeleteAWSRole(ctx, authPath, roleName)
	}

	// Delete policy if we created one
	if policyName := ref.ResourceIDs["policy_name"]; policyName != "" {
		_ = p.client.DeletePolicy(ctx, policyName)
	}

	// Disable auth method if owned
	if ref.Owned && authPath != "" {
		if err := p.client.DisableAuthMethod(ctx, authPath); err != nil {
			return cloudauth.ErrPermission("failed to disable auth method").WithCause(err)
		}
	}

	return nil
}

// Token implements cloudauth.TokenProvider.
func (p *Provider) Token(ctx context.Context, req cloudauth.TokenRequest) (*cloudauth.TokenResponse, error) {
	// Create a Vault token
	opts := &CreateTokenOptions{
		DisplayName: req.SourceIdentity,
		TTL:         fmt.Sprintf("%ds", req.Duration),
		Renewable:   true,
	}

	resp, err := p.client.CreateToken(ctx, opts)
	if err != nil {
		return nil, cloudauth.ErrAuth("failed to create Vault token").WithCause(err)
	}

	return &cloudauth.TokenResponse{
		Token:     resp.Token,
		ExpiresAt: int64(resp.LeaseDuration),
		TokenType: "service",
		Scopes:    resp.Policies,
	}, nil
}

// GenerateAWSCredentials generates AWS credentials using Vault's AWS secrets engine.
//
// Vault can generate three types of AWS credentials:
//   - IAM User credentials (long-lived, not recommended)
//   - STS AssumeRole credentials (temporary, role-based)
//   - STS Federation Token credentials (temporary, user-based)
//
// This enables any Vault-authenticated entity to obtain AWS credentials without
// having direct access to AWS IAM.
//
// Prerequisites:
//   - AWS secrets engine must be enabled at the specified path
//   - A role must be configured with appropriate permissions
//   - Vault must have AWS credentials configured for the secrets engine
//
// Usage:
//
//	creds, err := vaultProvider.GenerateAWSCredentials(ctx, &GenerateAWSCredentialsInput{
//	    SecretsEnginePath: "aws",
//	    RoleName:          "my-role",
//	})
func (p *Provider) GenerateAWSCredentials(ctx context.Context, input *GenerateAWSCredentialsInput) (*CrossCloudTokenOutput, error) {
	if p.client == nil {
		return nil, cloudauth.ErrValidation("Vault client not configured").
			WithProvider(cloudauth.ProviderVault).
			WithDetail("hint", "Configure Vault client using WithVaultClient option")
	}

	// Validate input
	if input.RoleName == "" {
		return nil, cloudauth.ErrValidation("RoleName is required").WithProvider(cloudauth.ProviderVault)
	}

	path := input.SecretsEnginePath
	if path == "" {
		path = "aws"
	}

	var creds *AWSCredentials
	var err error

	if input.RoleARN != "" {
		// Generate STS credentials with role assumption
		creds, err = p.client.GenerateAWSSTSCredentials(ctx, path, input.RoleName, input.RoleARN, input.TTL)
	} else if input.TTL != "" {
		creds, err = p.client.GenerateAWSCredentialsWithTTL(ctx, path, input.RoleName, input.TTL)
	} else {
		creds, err = p.client.GenerateAWSCredentials(ctx, path, input.RoleName)
	}

	if err != nil {
		return nil, cloudauth.ErrAuth("failed to generate AWS credentials from Vault").
			WithCause(err).
			WithProvider(cloudauth.ProviderVault).
			WithResource("vault:aws-secrets-role", input.RoleName)
	}

	expiresAt := time.Now().Add(time.Duration(creds.LeaseDuration) * time.Second)

	return &CrossCloudTokenOutput{
		Token:        creds.AccessKey,
		Secret:       creds.SecretKey,
		SessionToken: creds.SessionToken,
		TokenType:    "aws-credentials",
		ExpiresAt:    expiresAt,
		Provider:     cloudauth.ProviderAWS,
		LeaseID:      creds.LeaseID,
	}, nil
}

// GenerateGCPCredentials generates GCP credentials using Vault's GCP secrets engine.
//
// Vault can generate two types of GCP credentials:
//   - OAuth2 access tokens (temporary, short-lived)
//   - Service account keys (longer-lived, but should be rotated)
//
// Prerequisites:
//   - GCP secrets engine must be enabled at the specified path
//   - A role must be configured with appropriate permissions
//   - Vault must have a GCP service account configured for the secrets engine
//
// Usage:
//
//	creds, err := vaultProvider.GenerateGCPCredentials(ctx, &GenerateGCPCredentialsInput{
//	    SecretsEnginePath: "gcp",
//	    RoleName:          "my-role",
//	    KeyType:           "access_token",
//	})
func (p *Provider) GenerateGCPCredentials(ctx context.Context, input *GenerateGCPCredentialsInput) (*CrossCloudTokenOutput, error) {
	if p.client == nil {
		return nil, cloudauth.ErrValidation("Vault client not configured").
			WithProvider(cloudauth.ProviderVault).
			WithDetail("hint", "Configure Vault client using WithVaultClient option")
	}

	// Validate input
	if input.RoleName == "" {
		return nil, cloudauth.ErrValidation("RoleName is required").WithProvider(cloudauth.ProviderVault)
	}

	path := input.SecretsEnginePath
	if path == "" {
		path = "gcp"
	}

	keyType := input.KeyType
	if keyType == "" {
		keyType = "access_token" // Default to access tokens (more secure)
	}

	switch keyType {
	case "access_token":
		token, err := p.client.GenerateGCPAccessToken(ctx, path, input.RoleName)
		if err != nil {
			return nil, cloudauth.ErrAuth("failed to generate GCP access token from Vault").
				WithCause(err).
				WithProvider(cloudauth.ProviderVault).
				WithResource("vault:gcp-secrets-role", input.RoleName)
		}

		expiresAt := time.Unix(token.ExpiresAtSeconds, 0)

		return &CrossCloudTokenOutput{
			Token:     token.Token,
			TokenType: "gcp-access-token",
			ExpiresAt: expiresAt,
			Provider:  cloudauth.ProviderGCP,
			LeaseID:   token.LeaseID,
		}, nil

	case "service_account_key":
		key, err := p.client.GenerateGCPServiceAccountKey(ctx, path, input.RoleName)
		if err != nil {
			return nil, cloudauth.ErrAuth("failed to generate GCP service account key from Vault").
				WithCause(err).
				WithProvider(cloudauth.ProviderVault).
				WithResource("vault:gcp-secrets-role", input.RoleName)
		}

		expiresAt := time.Now().Add(time.Duration(key.LeaseDuration) * time.Second)

		return &CrossCloudTokenOutput{
			Token:     key.PrivateKeyData, // Base64-encoded JSON key
			TokenType: "gcp-service-account-key",
			ExpiresAt: expiresAt,
			Provider:  cloudauth.ProviderGCP,
			LeaseID:   key.LeaseID,
		}, nil

	default:
		return nil, cloudauth.ErrValidation(fmt.Sprintf("unsupported key type: %s, use 'access_token' or 'service_account_key'", keyType)).
			WithProvider(cloudauth.ProviderVault)
	}
}

// GenerateAzureCredentials generates Azure credentials using Vault's Azure secrets engine.
//
// Vault generates Azure service principal credentials (client ID and secret) that can be
// used to authenticate to Azure services.
//
// Prerequisites:
//   - Azure secrets engine must be enabled at the specified path
//   - A role must be configured with appropriate Azure AD permissions
//   - Vault must have Azure credentials configured for the secrets engine
//
// Usage:
//
//	creds, err := vaultProvider.GenerateAzureCredentials(ctx, &GenerateAzureCredentialsInput{
//	    SecretsEnginePath: "azure",
//	    RoleName:          "my-role",
//	})
func (p *Provider) GenerateAzureCredentials(ctx context.Context, input *GenerateAzureCredentialsInput) (*CrossCloudTokenOutput, error) {
	if p.client == nil {
		return nil, cloudauth.ErrValidation("Vault client not configured").
			WithProvider(cloudauth.ProviderVault).
			WithDetail("hint", "Configure Vault client using WithVaultClient option")
	}

	// Validate input
	if input.RoleName == "" {
		return nil, cloudauth.ErrValidation("RoleName is required").WithProvider(cloudauth.ProviderVault)
	}

	path := input.SecretsEnginePath
	if path == "" {
		path = "azure"
	}

	creds, err := p.client.GenerateAzureCredentials(ctx, path, input.RoleName)
	if err != nil {
		return nil, cloudauth.ErrAuth("failed to generate Azure credentials from Vault").
			WithCause(err).
			WithProvider(cloudauth.ProviderVault).
			WithResource("vault:azure-secrets-role", input.RoleName)
	}

	expiresAt := time.Now().Add(time.Duration(creds.LeaseDuration) * time.Second)

	return &CrossCloudTokenOutput{
		Token:     creds.ClientID,
		Secret:    creds.ClientSecret,
		TokenType: "azure-credentials",
		ExpiresAt: expiresAt,
		Provider:  cloudauth.ProviderAzure,
		LeaseID:   creds.LeaseID,
	}, nil
}

// Validators

type authMethodExistsValidator struct {
	client VaultClient
	path   string
}

func (v *authMethodExistsValidator) ID() string          { return "vault_auth_exists" }
func (v *authMethodExistsValidator) Name() string        { return "Auth Method Exists" }
func (v *authMethodExistsValidator) Description() string { return "Checks if the Vault auth method is enabled" }

func (v *authMethodExistsValidator) Validate(ctx context.Context, ref cloudauth.MechanismRef) cloudauth.ValidationCheck {
	check := cloudauth.ValidationCheck{
		ID:          v.ID(),
		Name:        v.Name(),
		Description: v.Description(),
		Severity:    cloudauth.SeverityCritical,
		Evidence:    map[string]interface{}{"path": v.path},
	}

	authMethod, err := v.client.ReadAuthMethod(ctx, v.path)
	if err != nil {
		check.Status = cloudauth.CheckStatusFailed
		check.Evidence["error"] = err.Error()
		check.Remediation = "Enable the auth method or run setup again"
		return check
	}

	check.Status = cloudauth.CheckStatusPassed
	check.Evidence["type"] = authMethod.Type
	return check
}

type roleExistsValidator struct {
	client   VaultClient
	authPath string
	roleName string
}

func (v *roleExistsValidator) ID() string          { return "vault_role_exists" }
func (v *roleExistsValidator) Name() string        { return "Auth Role Exists" }
func (v *roleExistsValidator) Description() string { return "Checks if the Vault auth role exists" }

func (v *roleExistsValidator) Validate(ctx context.Context, ref cloudauth.MechanismRef) cloudauth.ValidationCheck {
	check := cloudauth.ValidationCheck{
		ID:          v.ID(),
		Name:        v.Name(),
		Description: v.Description(),
		Severity:    cloudauth.SeverityCritical,
		Evidence: map[string]interface{}{
			"auth_path": v.authPath,
			"role_name": v.roleName,
		},
	}

	// Try JWT role first
	jwtRole, err := v.client.ReadJWTRole(ctx, v.authPath, v.roleName)
	if err == nil && jwtRole != nil {
		check.Status = cloudauth.CheckStatusPassed
		check.Evidence["role_type"] = "jwt"
		return check
	}

	// Try AWS role
	awsRole, err := v.client.ReadAWSRole(ctx, v.authPath, v.roleName)
	if err == nil && awsRole != nil {
		check.Status = cloudauth.CheckStatusPassed
		check.Evidence["role_type"] = "aws"
		return check
	}

	check.Status = cloudauth.CheckStatusFailed
	check.Remediation = "Create the auth role or run setup again"
	return check
}

func init() {
	cloudauth.Register(New())
}

