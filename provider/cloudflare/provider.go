// Package cloudflare provides Cloudflare Access lifecycle provider implementation.
package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// Provider implements core.Provider for Cloudflare Access.
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
	ID                     string
	Name                   string
	Domain                 string
	Type                   string // "self_hosted", "saas", "ssh", etc.
	SessionDuration        string
	AllowedIdps            []string
	AutoRedirectToIdentity bool
	CorsHeaders            *CORSHeaders
}

// CORSHeaders represents CORS configuration.
type CORSHeaders struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
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
	Source core.Cloud `json:"source" yaml:"source"`
}

// Type implements core.MechanismSpec.
func (s *CloudflareAccessSpec) Type() core.MechanismType {
	return "cloudflare_access"
}

// Validate implements core.MechanismSpec.
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

// SourceProvider implements core.MechanismSpec.
func (s *CloudflareAccessSpec) SourceProvider() core.Cloud {
	return s.Source
}

// TargetProvider implements core.MechanismSpec.
func (s *CloudflareAccessSpec) TargetProvider() core.Cloud {
	return core.Cloudflare
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

// Name implements core.Provider.
func (p *Provider) Name() core.Cloud {
	return core.Cloudflare
}

// Capabilities implements core.Provider.
func (p *Provider) Capabilities() []core.Capability {
	return []core.Capability{
		core.CapabilitySetup,
		core.CapabilityValidate,
		core.CapabilityDelete,
		core.CapabilityDryRun,
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

// requireClient reports whether this provider can reach the Cloudflare API.
//
// The client is injected and init() registers a Provider without one, so every
// entry point used to dereference nil and panic — the same class of bug already
// fixed in the aws, gcp and azure providers, and still present here because
// nothing tested this package.
func (p *Provider) requireClient() error {
	if p.client == nil {
		return core.ErrValidation("Cloudflare API client not configured").
			WithProvider(core.Cloudflare).
			WithDetail("hint", "Pass cloudflare.WithAPIClient, or use --dry-run")
	}
	return nil
}

// Setup implements core.LifecycleProvider.
func (p *Provider) Setup(ctx context.Context, spec core.MechanismSpec, opts core.SetupOptions) (*core.Outputs, error) {
	if !opts.DryRun {
		if err := p.requireClient(); err != nil {
			return nil, err
		}
	}
	cfSpec, ok := spec.(*CloudflareAccessSpec)
	if !ok {
		return nil, core.ErrValidation(fmt.Sprintf("unsupported spec type: %T", spec)).
			WithProvider(core.Cloudflare)
	}

	var plan core.Plan
	resourceIDs := make(map[string]string)

	// Step 1: Create service token
	action := core.PlannedAction{
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
			return nil, core.ErrPermission("failed to create service token").
				WithCause(err).WithProvider(core.Cloudflare)
		}
		resourceIDs["token_id"] = token.ID
		resourceIDs["account_id"] = cfSpec.AccountID

		// Handle secret
		if opts.SecretSink != nil && token.ClientSecret != "" {
			secretRef, err := opts.SecretSink.StoreSecret(ctx, "cloudflare-token-"+token.ID, []byte(token.ClientSecret))
			if err != nil {
				// Delete the token on failure
				_ = p.client.DeleteAccessServiceToken(ctx, cfSpec.AccountID, token.ID)
				return nil, core.ErrInternal("failed to store token secret").WithCause(err)
			}
			resourceIDs["client_secret_ref"] = secretRef.ID
		}
	}

	// Step 2: Create application if specified
	var appID string
	if cfSpec.ApplicationName != "" && cfSpec.ApplicationDomain != "" {
		action := core.PlannedAction{
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
				return nil, core.ErrPermission("failed to create application").
					WithCause(err).WithProvider(core.Cloudflare)
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
				return nil, core.ErrPermission("failed to create policy").
					WithCause(err).WithProvider(core.Cloudflare)
			}
		}
	}

	ref := core.CreateMechanismRef("cloudflare_access", core.Cloudflare, resourceIDs)

	if opts.DryRun {
		plan.Summary = fmt.Sprintf("Would create %d Cloudflare Access resources", len(plan.Actions))
		return &core.Outputs{
			Ref: ref,
			Values: map[string]string{
				"plan": plan.Summary,
			},
		}, nil
	}

	outputs := &core.Outputs{
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

// Validate implements core.LifecycleProvider.
func (p *Provider) Validate(ctx context.Context, ref core.MechanismRef, opts core.ValidateOptions) (*core.ValidationReport, error) {
	if err := p.requireClient(); err != nil {
		return nil, err
	}
	var validators []core.Validator

	accountID := ref.ResourceIDs["account_id"]
	tokenID := ref.ResourceIDs["token_id"]
	if accountID != "" && tokenID != "" {
		validators = append(validators, &tokenExistsValidator{
			client:    p.client,
			accountID: accountID,
			tokenID:   tokenID,
		})
	}

	report := core.RunValidation(ctx, ref, validators)
	return report, nil
}

// Delete implements core.LifecycleProvider.
func (p *Provider) Delete(ctx context.Context, ref core.MechanismRef, opts core.DeleteOptions) error {
	if opts.DryRun {
		return nil
	}
	if err := p.requireClient(); err != nil {
		return err
	}

	accountID := ref.ResourceIDs["account_id"]

	// Delete application first
	if appID := ref.ResourceIDs["application_id"]; appID != "" {
		if err := p.client.DeleteAccessApplication(ctx, accountID, appID); err != nil {
			if !isNotFoundError(err) {
				return core.ErrPermission("failed to delete application").WithCause(err)
			}
		}
	}

	// Delete token
	if tokenID := ref.ResourceIDs["token_id"]; tokenID != "" {
		if err := p.client.DeleteAccessServiceToken(ctx, accountID, tokenID); err != nil {
			if !isNotFoundError(err) {
				return core.ErrPermission("failed to delete service token").WithCause(err)
			}
		}
	}

	return nil
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
		return nil, core.ErrValidation("Cloudflare API client not configured").
			WithProvider(core.Cloudflare).
			WithDetail("hint", "Configure Cloudflare API client using WithAPIClient option")
	}

	// Validate input
	if input.AccountID == "" {
		return nil, core.ErrValidation("AccountID is required").WithProvider(core.Cloudflare)
	}
	if input.TokenID == "" {
		return nil, core.ErrValidation("TokenID is required").WithProvider(core.Cloudflare)
	}

	token, err := p.client.GetAccessServiceToken(ctx, input.AccountID, input.TokenID)
	if err != nil {
		return nil, core.ErrAuth("failed to retrieve service token").
			WithCause(err).
			WithProvider(core.Cloudflare).
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

// isNotFoundError reports whether err means "already gone", which Delete relies
// on to be idempotent.
//
// It previously recognised only the typed category, and the APIClient interface
// has no typed errors — a real implementation's 404 arrives as a plain error. So
// deleting an already-absent token failed, and a re-run of `delete` could never
// succeed.
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

type tokenExistsValidator struct {
	client    APIClient
	accountID string
	tokenID   string
}

func (v *tokenExistsValidator) ID() string   { return "cf_token_exists" }
func (v *tokenExistsValidator) Name() string { return "Service Token Exists" }
func (v *tokenExistsValidator) Description() string {
	return "Checks if the Cloudflare Access service token exists"
}

func (v *tokenExistsValidator) Validate(ctx context.Context, ref core.MechanismRef) core.ValidationCheck {
	check := core.ValidationCheck{
		ID:          v.ID(),
		Name:        v.Name(),
		Description: v.Description(),
		Severity:    core.SeverityCritical,
		Evidence:    map[string]interface{}{"token_id": v.tokenID},
	}

	token, err := v.client.GetAccessServiceToken(ctx, v.accountID, v.tokenID)
	if err != nil {
		check.Status = core.CheckStatusFailed
		check.Evidence["error"] = err.Error()
		check.Remediation = "Create a new service token or run setup again"
		return check
	}

	check.Status = core.CheckStatusPassed
	check.Evidence["name"] = token.Name
	check.Evidence["expires_at"] = token.ExpiresAt
	return check
}

func init() {
	core.Register(New())
}
