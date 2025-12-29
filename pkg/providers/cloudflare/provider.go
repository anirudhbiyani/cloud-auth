// Package cloudflare provides Cloudflare Access lifecycle provider implementation.
package cloudflare

import (
	"context"
	"fmt"
	"time"

	"github.com/anirudhbiyani/cloud-auth/pkg/cloudauth"
)

// Provider implements cloudauth.Provider for Cloudflare Access.
type Provider struct {
	client APIClient
}

// APIClient abstracts Cloudflare API operations for testing.
type APIClient interface {
	// Access Service Token operations
	GetAccessServiceToken(ctx context.Context, accountID, tokenID string) (*AccessServiceToken, error)
	CreateAccessServiceToken(ctx context.Context, accountID, name string, duration int) (*AccessServiceToken, error)
	UpdateAccessServiceToken(ctx context.Context, accountID, tokenID, name string) (*AccessServiceToken, error)
	DeleteAccessServiceToken(ctx context.Context, accountID, tokenID string) error
	ListAccessServiceTokens(ctx context.Context, accountID string) ([]*AccessServiceToken, error)

	// Access Application operations
	GetAccessApplication(ctx context.Context, accountID, appID string) (*AccessApplication, error)
	CreateAccessApplication(ctx context.Context, accountID string, app *AccessApplication) (*AccessApplication, error)
	UpdateAccessApplication(ctx context.Context, accountID, appID string, app *AccessApplication) (*AccessApplication, error)
	DeleteAccessApplication(ctx context.Context, accountID, appID string) error

	// Access Policy operations
	GetAccessPolicy(ctx context.Context, accountID, appID, policyID string) (*AccessPolicy, error)
	CreateAccessPolicy(ctx context.Context, accountID, appID string, policy *AccessPolicy) (*AccessPolicy, error)
	DeleteAccessPolicy(ctx context.Context, accountID, appID, policyID string) error
}

// AccessServiceToken represents a Cloudflare Access service token.
type AccessServiceToken struct {
	ID           string
	Name         string
	ClientID     string
	ClientSecret string // Only returned on creation
	ExpiresAt    int64
	Duration     int
}

// AccessApplication represents a Cloudflare Access application.
type AccessApplication struct {
	ID                   string
	Name                 string
	Domain               string
	Type                 string // "self_hosted", "saas", "ssh", etc.
	SessionDuration      string
	AllowedIdps          []string
	AutoRedirectToIdentity bool
	CorsHeaders          *CORSHeaders
}

// CORSHeaders represents CORS configuration.
type CORSHeaders struct {
	AllowedOrigins  []string
	AllowedMethods  []string
	AllowedHeaders  []string
	AllowCredentials bool
}

// AccessPolicy represents a Cloudflare Access policy.
type AccessPolicy struct {
	ID         string
	Name       string
	Precedence int
	Decision   string // "allow", "deny", "non_identity", "bypass"
	Include    []AccessRule
	Exclude    []AccessRule
	Require    []AccessRule
}

// AccessRule represents a rule in an Access policy.
type AccessRule struct {
	ServiceToken *ServiceTokenRule `json:"service_token,omitempty"`
	Email        *EmailRule        `json:"email,omitempty"`
	EmailDomain  *EmailDomainRule  `json:"email_domain,omitempty"`
	Everyone     *EveryoneRule     `json:"everyone,omitempty"`
	IP           *IPRule           `json:"ip,omitempty"`
}

type ServiceTokenRule struct {
	TokenID string `json:"token_id"`
}

type EmailRule struct {
	Email string `json:"email"`
}

type EmailDomainRule struct {
	Domain string `json:"domain"`
}

type EveryoneRule struct{}

type IPRule struct {
	IP string `json:"ip"`
}

// CloudflareAccessSpec specifies a Cloudflare Access configuration.
type CloudflareAccessSpec struct {
	// AccountID is the Cloudflare account ID.
	AccountID string `json:"account_id" yaml:"account_id"`

	// TokenName is the name for the service token.
	TokenName string `json:"token_name" yaml:"token_name"`

	// TokenDuration is the token validity duration in days.
	TokenDuration int `json:"token_duration,omitempty" yaml:"token_duration,omitempty"`

	// Application configuration (optional - creates an Access application).
	ApplicationName   string `json:"application_name,omitempty" yaml:"application_name,omitempty"`
	ApplicationDomain string `json:"application_domain,omitempty" yaml:"application_domain,omitempty"`

	// Source identifies where this token will be used from.
	Source cloudauth.CloudProvider `json:"source" yaml:"source"`
}

// Type implements cloudauth.MechanismSpec.
func (s *CloudflareAccessSpec) Type() cloudauth.MechanismType {
	return "cloudflare_access"
}

// Validate implements cloudauth.MechanismSpec.
func (s *CloudflareAccessSpec) Validate() error {
	if s.AccountID == "" {
		return fmt.Errorf("account_id is required")
	}
	if s.TokenName == "" {
		return fmt.Errorf("token_name is required")
	}
	if s.TokenDuration < 0 {
		return fmt.Errorf("token_duration must be positive")
	}
	return nil
}

// SourceProvider implements cloudauth.MechanismSpec.
func (s *CloudflareAccessSpec) SourceProvider() cloudauth.CloudProvider {
	return s.Source
}

// TargetProvider implements cloudauth.MechanismSpec.
func (s *CloudflareAccessSpec) TargetProvider() cloudauth.CloudProvider {
	return cloudauth.ProviderCloudflare
}

// ProviderOption configures the Provider.
type ProviderOption func(*Provider)

// WithAPIClient sets the API client.
func WithAPIClient(client APIClient) ProviderOption {
	return func(p *Provider) {
		p.client = client
	}
}

// New creates a new Cloudflare provider.
func New(opts ...ProviderOption) *Provider {
	p := &Provider{}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Name implements cloudauth.Provider.
func (p *Provider) Name() cloudauth.CloudProvider {
	return cloudauth.ProviderCloudflare
}

// Capabilities implements cloudauth.Provider.
func (p *Provider) Capabilities() []cloudauth.Capability {
	return []cloudauth.Capability{
		cloudauth.CapabilityToken,
		cloudauth.CapabilitySetup,
		cloudauth.CapabilityValidate,
		cloudauth.CapabilityDelete,
		cloudauth.CapabilityDryRun,
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
	cfSpec, ok := spec.(*CloudflareAccessSpec)
	if !ok {
		return nil, cloudauth.ErrValidation(fmt.Sprintf("unsupported spec type: %T", spec)).
			WithProvider(cloudauth.ProviderCloudflare)
	}

	var plan cloudauth.Plan
	resourceIDs := make(map[string]string)

	// Step 1: Create service token
	action := cloudauth.PlannedAction{
		Operation:    "create",
		ResourceType: "access-service-token",
		Details: map[string]interface{}{
			"name":     cfSpec.TokenName,
			"duration": cfSpec.TokenDuration,
		},
		Reversible: true,
	}
	plan.Actions = append(plan.Actions, action)

	var token *AccessServiceToken
	if !opts.DryRun {
		duration := cfSpec.TokenDuration
		if duration == 0 {
			duration = 365 // Default to 1 year
		}

		var err error
		token, err = p.client.CreateAccessServiceToken(ctx, cfSpec.AccountID, cfSpec.TokenName, duration)
		if err != nil {
			return nil, cloudauth.ErrPermission("failed to create service token").
				WithCause(err).WithProvider(cloudauth.ProviderCloudflare)
		}
		resourceIDs["token_id"] = token.ID
		resourceIDs["account_id"] = cfSpec.AccountID

		// Handle secret
		if opts.SecretSink != nil && token.ClientSecret != "" {
			secretRef, err := opts.SecretSink.StoreSecret(ctx, "cloudflare-token-"+token.ID, []byte(token.ClientSecret))
			if err != nil {
				// Delete the token on failure
				_ = p.client.DeleteAccessServiceToken(ctx, cfSpec.AccountID, token.ID)
				return nil, cloudauth.ErrInternal("failed to store token secret").WithCause(err)
			}
			resourceIDs["client_secret_ref"] = secretRef.ID
		}
	}

	// Step 2: Create application if specified
	var appID string
	if cfSpec.ApplicationName != "" && cfSpec.ApplicationDomain != "" {
		action := cloudauth.PlannedAction{
			Operation:    "create",
			ResourceType: "access-application",
			Details: map[string]interface{}{
				"name":   cfSpec.ApplicationName,
				"domain": cfSpec.ApplicationDomain,
			},
			Reversible: true,
		}
		plan.Actions = append(plan.Actions, action)

		if !opts.DryRun {
			app, err := p.client.CreateAccessApplication(ctx, cfSpec.AccountID, &AccessApplication{
				Name:   cfSpec.ApplicationName,
				Domain: cfSpec.ApplicationDomain,
				Type:   "self_hosted",
			})
			if err != nil {
				// Cleanup token
				_ = p.client.DeleteAccessServiceToken(ctx, cfSpec.AccountID, token.ID)
				return nil, cloudauth.ErrPermission("failed to create application").
					WithCause(err).WithProvider(cloudauth.ProviderCloudflare)
			}
			appID = app.ID
			resourceIDs["application_id"] = appID

			// Create policy allowing the service token
			_, err = p.client.CreateAccessPolicy(ctx, cfSpec.AccountID, appID, &AccessPolicy{
				Name:       cfSpec.TokenName + "-policy",
				Precedence: 1,
				Decision:   "non_identity",
				Include: []AccessRule{
					{ServiceToken: &ServiceTokenRule{TokenID: token.ID}},
				},
			})
			if err != nil {
				// Cleanup
				_ = p.client.DeleteAccessApplication(ctx, cfSpec.AccountID, appID)
				_ = p.client.DeleteAccessServiceToken(ctx, cfSpec.AccountID, token.ID)
				return nil, cloudauth.ErrPermission("failed to create policy").
					WithCause(err).WithProvider(cloudauth.ProviderCloudflare)
			}
		}
	}

	ref := cloudauth.CreateMechanismRef("cloudflare_access", cloudauth.ProviderCloudflare, resourceIDs)

	if opts.DryRun {
		plan.Summary = fmt.Sprintf("Would create %d Cloudflare Access resources", len(plan.Actions))
		return &cloudauth.Outputs{
			Ref: ref,
			Values: map[string]string{
				"plan": plan.Summary,
			},
		}, nil
	}

	outputs := &cloudauth.Outputs{
		Ref: ref,
		Values: map[string]string{
			"token_id":  token.ID,
			"client_id": token.ClientID,
		},
		Instructions: []string{
			fmt.Sprintf("Set CF-Access-Client-Id header to: %s", token.ClientID),
			"Set CF-Access-Client-Secret header to the secret value (stored in secret sink)",
		},
	}

	if appID != "" {
		outputs.Values["application_id"] = appID
	}

	return outputs, nil
}

// Validate implements cloudauth.LifecycleProvider.
func (p *Provider) Validate(ctx context.Context, ref cloudauth.MechanismRef, opts cloudauth.ValidateOptions) (*cloudauth.ValidationReport, error) {
	var validators []cloudauth.Validator

	accountID := ref.ResourceIDs["account_id"]
	tokenID := ref.ResourceIDs["token_id"]
	if accountID != "" && tokenID != "" {
		validators = append(validators, &tokenExistsValidator{
			client:    p.client,
			accountID: accountID,
			tokenID:   tokenID,
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

	accountID := ref.ResourceIDs["account_id"]

	// Delete application first
	if appID := ref.ResourceIDs["application_id"]; appID != "" {
		if err := p.client.DeleteAccessApplication(ctx, accountID, appID); err != nil {
			if !isNotFoundError(err) {
				return cloudauth.ErrPermission("failed to delete application").WithCause(err)
			}
		}
	}

	// Delete token
	if tokenID := ref.ResourceIDs["token_id"]; tokenID != "" {
		if err := p.client.DeleteAccessServiceToken(ctx, accountID, tokenID); err != nil {
			if !isNotFoundError(err) {
				return cloudauth.ErrPermission("failed to delete service token").WithCause(err)
			}
		}
	}

	return nil
}

// Token implements cloudauth.TokenProvider.
// Note: Cloudflare Access uses static service tokens, not dynamic token acquisition.
// Use GetServiceTokenCredentials to retrieve stored service token credentials.
func (p *Provider) Token(ctx context.Context, req cloudauth.TokenRequest) (*cloudauth.TokenResponse, error) {
	return nil, cloudauth.ErrValidation("Cloudflare Access uses static service tokens, not dynamic token acquisition").
		WithProvider(cloudauth.ProviderCloudflare).
		WithDetail("hint", "Use GetServiceTokenCredentials() to retrieve stored service token credentials")
}

// ServiceTokenCredentials contains Cloudflare Access service token credentials.
type ServiceTokenCredentials struct {
	// ClientID is the CF-Access-Client-Id header value.
	ClientID string
	// ClientSecret is the CF-Access-Client-Secret header value.
	ClientSecret string
	// TokenID is the unique identifier of the service token.
	TokenID string
	// Name is the display name of the service token.
	Name string
	// ExpiresAt is when the service token expires.
	ExpiresAt time.Time
}

// GetServiceTokenCredentialsInput contains parameters for retrieving service token credentials.
type GetServiceTokenCredentialsInput struct {
	// AccountID is the Cloudflare account ID.
	AccountID string
	// TokenID is the service token ID.
	TokenID string
}

// GetServiceTokenCredentials retrieves service token credentials for use in cross-cloud/cross-service authentication.
//
// Cloudflare Access service tokens are static credentials that can be used to authenticate
// machine-to-machine requests to Cloudflare Access-protected applications.
//
// Note: The ClientSecret is only returned during token creation. If you need the secret,
// you must retrieve it from where it was originally stored (e.g., secret manager, environment variable).
//
// Usage in requests:
//
//	// Add these headers to authenticate with Cloudflare Access
//	req.Header.Set("CF-Access-Client-Id", creds.ClientID)
//	req.Header.Set("CF-Access-Client-Secret", "<secret-from-storage>")
//
// Cross-cloud authentication:
// Cloudflare Access tokens can be used to authenticate FROM any cloud provider TO Cloudflare-protected services.
// Simply include the headers in your requests from AWS Lambda, GCP Cloud Functions, Azure Functions, etc.
func (p *Provider) GetServiceTokenCredentials(ctx context.Context, input *GetServiceTokenCredentialsInput) (*ServiceTokenCredentials, error) {
	if p.client == nil {
		return nil, cloudauth.ErrValidation("Cloudflare API client not configured").
			WithProvider(cloudauth.ProviderCloudflare).
			WithDetail("hint", "Configure Cloudflare API client using WithAPIClient option")
	}

	// Validate input
	if input.AccountID == "" {
		return nil, cloudauth.ErrValidation("AccountID is required").WithProvider(cloudauth.ProviderCloudflare)
	}
	if input.TokenID == "" {
		return nil, cloudauth.ErrValidation("TokenID is required").WithProvider(cloudauth.ProviderCloudflare)
	}

	token, err := p.client.GetAccessServiceToken(ctx, input.AccountID, input.TokenID)
	if err != nil {
		return nil, cloudauth.ErrAuth("failed to retrieve service token").
			WithCause(err).
			WithProvider(cloudauth.ProviderCloudflare).
			WithResource("cloudflare:service-token", input.TokenID)
	}

	return &ServiceTokenCredentials{
		ClientID:  token.ClientID,
		TokenID:   token.ID,
		Name:      token.Name,
		ExpiresAt: time.Unix(token.ExpiresAt, 0),
		// Note: ClientSecret is not returned by the API after creation
		// It must be retrieved from where it was originally stored
	}, nil
}

// GenerateServiceTokenHeaders generates the HTTP headers needed to authenticate
// with a Cloudflare Access-protected application.
//
// This is a convenience method that formats the credentials into ready-to-use HTTP headers.
//
// Usage:
//
//	headers := cfProvider.GenerateServiceTokenHeaders(clientID, clientSecret)
//	for key, value := range headers {
//	    req.Header.Set(key, value)
//	}
func (p *Provider) GenerateServiceTokenHeaders(clientID, clientSecret string) map[string]string {
	return map[string]string{
		"CF-Access-Client-Id":     clientID,
		"CF-Access-Client-Secret": clientSecret,
	}
}

// Helper

func isNotFoundError(err error) bool {
	return cloudauth.IsCategory(err, cloudauth.ErrCategoryNotFound)
}

// Validators

type tokenExistsValidator struct {
	client    APIClient
	accountID string
	tokenID   string
}

func (v *tokenExistsValidator) ID() string          { return "cf_token_exists" }
func (v *tokenExistsValidator) Name() string        { return "Service Token Exists" }
func (v *tokenExistsValidator) Description() string { return "Checks if the Cloudflare Access service token exists" }

func (v *tokenExistsValidator) Validate(ctx context.Context, ref cloudauth.MechanismRef) cloudauth.ValidationCheck {
	check := cloudauth.ValidationCheck{
		ID:          v.ID(),
		Name:        v.Name(),
		Description: v.Description(),
		Severity:    cloudauth.SeverityCritical,
		Evidence:    map[string]interface{}{"token_id": v.tokenID},
	}

	token, err := v.client.GetAccessServiceToken(ctx, v.accountID, v.tokenID)
	if err != nil {
		check.Status = cloudauth.CheckStatusFailed
		check.Evidence["error"] = err.Error()
		check.Remediation = "Create a new service token or run setup again"
		return check
	}

	check.Status = cloudauth.CheckStatusPassed
	check.Evidence["name"] = token.Name
	check.Evidence["expires_at"] = token.ExpiresAt
	return check
}

func init() {
	cloudauth.Register(New())
}

