// Package aws provides AWS lifecycle provider implementation.
package aws

import (
	"context"
	"crypto/sha1" // #nosec G505 -- AWS defines the OIDC provider thumbprint as SHA-1
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	neturl "net/url"
	"strings"
	"sync"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// Provider implements core.LifecycleProvider for AWS.
type Provider struct {
	mu        sync.Mutex
	client    IAMClient
	stsClient STSClient

	// resolveFailed caches a credential-resolution failure so the second call
	// reports the original cause rather than re-running a lookup that fails the
	// same way — and, on a host with no credentials at all, so the AWS SDK's
	// resolver chain is walked once per process instead of once per call.
	resolveFailed error

	// tlsConfig is used only when reading an OIDC issuer's certificate chain to
	// compute its thumbprint. nil means the platform defaults.
	tlsConfig *tls.Config
}

// iam returns the IAM client, building a real one from the ambient AWS
// configuration on first use.
//
// Construction is lazy because init() registers the provider at package load —
// long before anyone has asked to talk to AWS. Building eagerly there would make
// every import of this package depend on resolvable credentials, and would
// surface a credential problem as an import-time failure rather than at the
// operation that needed it. An injected client (tests, custom config) always wins.
func (p *Provider) iam(ctx context.Context) (IAMClient, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.client != nil {
		return p.client, nil
	}
	if p.resolveFailed != nil {
		return nil, p.resolveFailed
	}
	c, err := NewIAMClient(ctx)
	if err != nil {
		p.resolveFailed = err
		return nil, err
	}
	p.client = c
	return c, nil
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
	// ListRoles enumerates every role in the account, each carrying its
	// assume-role policy. `audit` needs roles this tool did NOT create — the
	// pre-existing backlog is the whole population it serves — so enumerating
	// from cloud-auth's own state would miss exactly the interesting ones.
	ListRoles(ctx context.Context) ([]*Role, error)
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
	ARN            string
	URL            string
	ClientIDList   []string
	ThumbprintList []string
	Tags           map[string]string
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

// WithThumbprintTLSConfig sets the TLS configuration used when reading an OIDC
// issuer's certificate chain.
//
// The chain is verified by default, because the thumbprint computed from it
// becomes a pin: an unverified handshake would let anyone in the path decide
// what gets pinned. An issuer fronted by a private CA is a legitimate case, so
// supply its roots here rather than disabling verification.
func WithThumbprintTLSConfig(cfg *tls.Config) ProviderOption {
	return func(p *Provider) {
		p.tlsConfig = cfg
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

// Name implements core.Provider.
func (p *Provider) Name() core.Cloud {
	return core.AWS
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

// Setup implements core.LifecycleProvider.
func (p *Provider) Setup(ctx context.Context, spec core.MechanismSpec, opts core.SetupOptions) (*core.Outputs, error) {
	switch s := spec.(type) {
	case *core.AWSRoleTrustOIDCSpec:
		return p.setupRoleTrustOIDC(ctx, s, opts)
	case *core.K8sServiceAccountFederationSpec:
		return p.setupK8sFederation(ctx, s, opts)
	default:
		return nil, core.ErrValidation(fmt.Sprintf("unsupported spec type: %T", spec)).
			WithProvider(core.AWS)
	}
}

// setupRoleTrustOIDC creates or updates an AWS IAM role with OIDC trust.
func (p *Provider) setupRoleTrustOIDC(ctx context.Context, spec *core.AWSRoleTrustOIDCSpec, opts core.SetupOptions) (*core.Outputs, error) {
	// Step 1 below can reach the OIDC-provider calls before the lazy resolve
	// further down, so resolve up front for anything that will touch AWS. A dry
	// run is exempt: describing a plan must not require credentials.
	if !opts.DryRun {
		if _, err := p.iam(ctx); err != nil {
			return nil, core.ErrValidation("AWS IAM client not configured").
				WithCause(err).
				WithProvider(core.AWS).
				WithDetail("hint", "Configure AWS credentials (env, shared config, or SSO), or use --dry-run")
		}
	}

	var plan core.Plan
	var createdResources []string
	var oidcProviderARN string

	// Determine role name
	roleName := spec.RoleName
	if spec.RoleARN != "" {
		parts := strings.Split(spec.RoleARN, "/")
		roleName = parts[len(parts)-1]
	}

	// Step 1: Handle OIDC provider
	//
	// Built-in IdPs (Google, Cognito, Login with Amazon, Facebook) are trusted by
	// AWS natively: creating an iam:OpenIDConnectProvider for them is unnecessary
	// and, for Google, actively wrong — the trust principal is the bare host, so
	// a provider ARN would never be referenced.
	switch {
	case spec.OIDCProviderARN != "":
		oidcProviderARN = spec.OIDCProviderARN
	case spec.OIDCProviderURL != "" && !needsOIDCProviderResource(spec.OIDCProviderURL):
		// Nothing to create; buildTrustPolicy uses the bare host as principal.
	case spec.OIDCProviderURL != "":
		// Check if provider already exists
		existingARN, err := p.findOIDCProviderByURL(ctx, spec.OIDCProviderURL)
		if err != nil {
			return nil, err
		}

		if existingARN != "" {
			oidcProviderARN = existingARN
		} else {
			// Need to create OIDC provider
			action := core.PlannedAction{
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
				thumbprint, err := p.oidcThumbprint(ctx, spec.OIDCProviderURL)
				if err != nil {
					return nil, core.ErrNetwork("failed to get OIDC thumbprint").WithCause(err)
				}

				arn, err := p.client.CreateOpenIDConnectProvider(ctx, &CreateOIDCProviderInput{
					URL:            spec.OIDCProviderURL,
					ClientIDList:   []string{spec.Audience},
					ThumbprintList: []string{thumbprint},
					Tags:           mergeTags(spec.Tags, opts.Tags),
				})
				if err != nil {
					return nil, core.ErrPermission("failed to create OIDC provider").
						WithCause(err).WithProvider(core.AWS)
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
		// A permission or network failure is not "the role is absent". Treating
		// it as absent sends the flow to CreateRole, which then fails on
		// EntityAlreadyExists — a confusing error for what is really "we could
		// not read the role".
		switch {
		case roleErr == nil:
			roleExists = existingRole != nil
		case isNotFoundError(roleErr):
			roleExists = false
		default:
			return nil, core.ErrPermission("could not determine whether role exists").
				WithCause(roleErr).
				WithResource("iam:role", roleName).
				WithProvider(core.AWS)
		}
	}

	if roleExists && existingRole != nil {
		// Update existing role
		action := core.PlannedAction{
			Operation:    "update",
			ResourceType: "iam:role",
			ResourceID:   existingRole.ARN,
			Details:      map[string]interface{}{"role_name": roleName},
			Reversible:   true,
		}
		plan.Actions = append(plan.Actions, action)
	} else {
		// Create new role
		action := core.PlannedAction{
			Operation:    "create",
			ResourceType: "iam:role",
			Details:      map[string]interface{}{"role_name": roleName},
			Reversible:   true,
		}
		plan.Actions = append(plan.Actions, action)
	}

	var roleARN string
	if !opts.DryRun {
		// Resolve the IAM client (building one from the ambient AWS config if
		// none was injected) before doing anything that touches AWS.
		if _, err := p.iam(ctx); err != nil {
			return nil, core.ErrValidation("AWS IAM client not configured").
				WithCause(err).
				WithProvider(core.AWS).
				WithDetail("hint", "Configure AWS credentials (env, shared config, or SSO) or use --dry-run")
		}

		// Build trust policy
		trustPolicy, err := buildTrustPolicy(oidcProviderARN, spec)
		if err != nil {
			return nil, err
		}
		trustPolicyJSON, err := json.Marshal(trustPolicy)
		if err != nil {
			return nil, core.ErrInternal("failed to marshal trust policy").WithCause(err)
		}

		if roleExists {
			// Update trust policy
			if err := p.client.UpdateAssumeRolePolicy(ctx, roleName, string(trustPolicyJSON)); err != nil {
				return nil, core.ErrPermission("failed to update role trust policy").
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
				return nil, core.ErrPermission("failed to create role").
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
				return nil, &core.RollbackError{
					OriginalError:     core.ErrPermission("failed to attach policy").WithCause(err),
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
				return nil, &core.RollbackError{
					OriginalError:  core.ErrPermission("failed to add inline policy").WithCause(err),
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
	// Persist what the trust was SUPPOSED to be, so a later Validate can compare
	// the live policy against the original intent. Without these, validation can
	// only confirm the role exists — it cannot detect that someone widened the
	// subject condition or repointed the issuer. None of these are secrets; they
	// are already public in the trust policy itself.
	if spec.OIDCProviderURL != "" {
		resourceIDs["expected_issuer"] = spec.OIDCProviderURL
	}
	if spec.Audience != "" {
		resourceIDs["expected_audience"] = spec.Audience
	}
	if spec.Subject != "" {
		resourceIDs["expected_subject"] = spec.Subject
	}
	if len(spec.PolicyARNs) > 0 {
		resourceIDs["expected_policy_arns"] = strings.Join(spec.PolicyARNs, ",")
	}

	ref := core.CreateMechanismRef(core.MechanismAWSRoleTrustOIDC, core.AWS, resourceIDs)

	if opts.DryRun {
		plan.Summary = fmt.Sprintf("Would create/update %d resources for AWS OIDC trust", len(plan.Actions))
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
			"role_arn":          roleARN,
			"oidc_provider_arn": oidcProviderARN,
		},
	}, nil
}

// Validate implements core.LifecycleProvider.
func (p *Provider) Validate(ctx context.Context, ref core.MechanismRef, opts core.ValidateOptions) (*core.ValidationReport, error) {
	// Resolve the IAM client BEFORE constructing validators: they capture it,
	// and a nil client would panic inside the check rather than reporting a
	// clean "could not reach AWS".
	if _, err := p.iam(ctx); err != nil {
		return nil, core.ErrValidation("AWS IAM client not configured").
			WithCause(err).
			WithProvider(core.AWS).
			WithDetail("hint", "Configure AWS credentials (env, shared config, or SSO)")
	}

	var validators []core.Validator

	// Add standard validators based on mechanism type
	switch ref.Type {
	case core.MechanismAWSRoleTrustOIDC:
		roleName := ref.ResourceIDs["role_name"]
		if roleName == "" {
			return nil, core.ErrValidation("role_name not found in mechanism ref")
		}

		// Role exists validator
		validators = append(validators, &roleExistsValidator{client: p.client, roleName: roleName})

		// OIDC provider object exists
		if oidcARN := ref.ResourceIDs["oidc_provider_arn"]; oidcARN != "" {
			validators = append(validators, &oidcProviderExistsValidator{client: p.client, arn: oidcARN})
		}

		// Compare the LIVE trust policy against the intent recorded at setup.
		// Mechanisms created before these keys were persisted simply won't have
		// them, and the check reports skipped rather than failing spuriously.
		expIssuer := ref.ResourceIDs["expected_issuer"]
		expAudience := ref.ResourceIDs["expected_audience"]
		expSubject := ref.ResourceIDs["expected_subject"]
		if expIssuer != "" || expAudience != "" || expSubject != "" {
			validators = append(validators, core.NewTrustPolicyMatchValidator(
				expIssuer, expAudience, expSubject,
				core.WithTrustPolicySource(p)))

			// Breadth is scored unconditionally, unlike the match check above:
			// it needs no recorded intent, only the live policy. A mechanism
			// created before cloud-auth persisted its intent still has subjects
			// worth grading, and that is exactly the pre-existing population
			// most likely to carry an over-broad one.
			validators = append(validators, core.NewSubjectBreadthValidator(p))
		}

		// Confirm the policies the spec asked for are still attached.
		if raw := ref.ResourceIDs["expected_policy_arns"]; raw != "" {
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
	// Resolve the client before dispatching. Delete used to dereference p.client
	// directly, and init() registers a Provider with no client at all — so
	// core.Delete on the global registry panicked instead of returning an error.
	if _, err := p.iam(ctx); err != nil {
		return core.ErrValidation("AWS IAM client not configured").
			WithCause(err).
			WithProvider(core.AWS).
			WithDetail("hint", "Configure AWS credentials (env, shared config, or SSO)")
	}
	switch ref.Type {
	case core.MechanismAWSRoleTrustOIDC:
		return p.deleteRoleTrustOIDC(ctx, ref, opts)
	default:
		return core.ErrValidation(fmt.Sprintf("unsupported mechanism type: %s", ref.Type))
	}
}

func (p *Provider) deleteRoleTrustOIDC(ctx context.Context, ref core.MechanismRef, opts core.DeleteOptions) error {
	roleName := ref.ResourceIDs["role_name"]
	if roleName == "" {
		return core.ErrValidation("role_name not found in mechanism ref")
	}

	if opts.DryRun {
		return nil // Would just return the plan
	}

	// Step 1: Detach all managed policies
	attachedPolicies, err := p.client.ListAttachedRolePolicies(ctx, roleName)
	if err == nil {
		for _, policyARN := range attachedPolicies {
			if err := p.client.DetachRolePolicy(ctx, roleName, policyARN); err != nil {
				return core.ErrPermission("failed to detach policy").
					WithCause(err).WithResource("iam:policy", policyARN)
			}
		}
	}

	// Step 2: Delete all inline policies
	inlinePolicies, err := p.client.ListRolePolicies(ctx, roleName)
	if err == nil {
		for _, policyName := range inlinePolicies {
			if err := p.client.DeleteRolePolicy(ctx, roleName, policyName); err != nil {
				return core.ErrPermission("failed to delete inline policy").
					WithCause(err).WithResource("iam:inline-policy", policyName)
			}
		}
	}

	// Step 3: Delete the role
	if err := p.client.DeleteRole(ctx, roleName); err != nil {
		// Check if already deleted (idempotent)
		if !isNotFoundError(err) {
			return core.ErrPermission("failed to delete role").
				WithCause(err).WithResource("iam:role", roleName)
		}
	}

	// Step 4: Optionally delete OIDC provider if owned
	if ref.Owned {
		if oidcARN := ref.ResourceIDs["oidc_provider_arn"]; oidcARN != "" {
			if err := p.client.DeleteOpenIDConnectProvider(ctx, oidcARN); err != nil {
				if !isNotFoundError(err) {
					return core.ErrPermission("failed to delete OIDC provider").
						WithCause(err).WithResource("iam:oidc-provider", oidcARN)
				}
			}
		}
	}

	return nil
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
		return nil, core.ErrValidation("AWS STS client not configured").
			WithProvider(core.AWS).
			WithDetail("hint", "Configure AWS STS client using WithSTSClient option")
	}

	// Validate input
	if input.ProjectNumber == "" {
		return nil, core.ErrValidation("ProjectNumber is required").WithProvider(core.AWS)
	}
	if input.PoolID == "" {
		return nil, core.ErrValidation("PoolID is required").WithProvider(core.AWS)
	}
	if input.ProviderID == "" {
		return nil, core.ErrValidation("ProviderID is required").WithProvider(core.AWS)
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
		return nil, core.ErrAuth("failed to sign request for GCP WIF").
			WithCause(err).WithProvider(core.AWS)
	}

	// Build the token in the format expected by GCP
	token := map[string]interface{}{
		"url":     signOutput.URL,
		"method":  signOutput.Method,
		"headers": signOutput.Headers,
	}

	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return nil, core.ErrInternal("failed to marshal GCP WIF token").WithCause(err)
	}

	return &CrossCloudTokenOutput{
		Token:     string(tokenJSON),
		TokenType: "urn:ietf:params:aws:token-type:aws4_request",
		Audience:  audience,
		// AWS signed requests are valid for a short time (typically 15 minutes)
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}, nil
}

// GenerateAzureFederatedToken is not implemented here, and deliberately so.
//
// It used to report that AWS → Azure federation was impossible because AWS
// exposed no OIDC token endpoint. That is no longer true: with outbound identity
// federation enabled, sts:GetWebIdentityToken vends an RS256 JWT that Entra
// accepts as a client assertion.
//
// Minting that JWT is a data-plane operation — it asserts the identity of the
// caller, so it belongs to the workload, not to a control-plane provider holding
// administrative IAM credentials. Use source.NewAWS().Mint, or broker.Exchange to
// mint and exchange in one step.
func (p *Provider) GenerateAzureFederatedToken(ctx context.Context, input *AzureFederatedTokenInput) (*CrossCloudTokenOutput, error) {
	return nil, core.ErrValidation("minting an AWS identity token is a data-plane operation, not a provider one").
		WithProvider(core.AWS).
		WithDetail("reason", "this provider holds administrative credentials; a proof of identity must be minted by the workload it identifies").
		WithDetail("use_instead", "source.NewAWS().Mint(ctx, \"api://AzureADTokenExchange\"), then target.NewAzureExchanger().Exchange — or broker.Exchange for both").
		WithDetail("prerequisite", "the account must have outbound identity federation enabled: aws iam enable-outbound-web-identity-federation")
}

// Helper functions

func (p *Provider) findOIDCProviderByURL(ctx context.Context, url string) (string, error) {
	// Without a usable client (e.g. a dry run with no credentials) we cannot
	// look, so report "not found" and let the caller plan a create.
	client, err := p.iam(ctx)
	if err != nil || client == nil {
		return "", nil
	}

	providers, err := client.ListOpenIDConnectProviders(ctx)
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

// oidcConditionPrefix returns the IAM condition-key prefix for an OIDC issuer:
// the provider NAME (host plus any path), with the scheme stripped.
//
// AWS: "Define condition keys using the name of the OIDC provider
// (token.actions.githubusercontent.com) followed by a claim (:aud)". Building
// the key from the provider ARN instead yields a key that IAM never populates,
// so StringEquals fails and the role can never be assumed.
func oidcConditionPrefix(issuerURL string) string {
	s := strings.TrimPrefix(issuerURL, "https://")
	s = strings.TrimPrefix(s, "http://")
	return strings.TrimSuffix(s, "/")
}

// builtInOIDCProviders are identity providers AWS trusts natively. They need no
// iam:OpenIDConnectProvider resource, and the trust principal is the bare host
// rather than a provider ARN.
var builtInOIDCProviders = map[string]bool{
	"accounts.google.com":            true,
	"cognito-identity.amazonaws.com": true,
	"www.amazon.com":                 true,
	"graph.facebook.com":             true,
}

// needsOIDCProviderResource reports whether an IAM OIDC provider must be created
// for this issuer.
func needsOIDCProviderResource(issuerURL string) bool {
	return !builtInOIDCProviders[oidcConditionPrefix(issuerURL)]
}

// audienceConditionClaim returns the claim to pin the audience with.
//
// Normally that is "aud". For accounts.google.com it must be "oaud": AWS maps
// the :aud key to the token's azp claim whenever azp is set, and Google service
// account tokens do set azp — so pinning :aud to the audience would never match.
// :oaud always carries the real aud.
func audienceConditionClaim(issuerURL string) string {
	if oidcConditionPrefix(issuerURL) == "accounts.google.com" {
		return "oaud"
	}
	return "aud"
}

// buildTrustPolicy renders the role's assume-role policy document.
//
// It refuses to emit a statement with no `:sub` condition unless the spec opted
// into that explicitly. The same rule lives in AWSRoleTrustOIDCSpec.Validate,
// but a caller can construct a spec directly and skip it, and the cost of
// getting this wrong is a role any workload the issuer serves can assume — so
// the document builder enforces it too rather than trusting its input.
func buildTrustPolicy(oidcProviderARN string, spec *core.AWSRoleTrustOIDCSpec) (map[string]interface{}, error) {
	prefix := oidcConditionPrefix(spec.OIDCProviderURL)

	// A built-in IdP has no provider resource; the principal is the bare host.
	principal := oidcProviderARN
	if !needsOIDCProviderResource(spec.OIDCProviderURL) || principal == "" {
		principal = prefix
	}

	condition := map[string]interface{}{
		"StringEquals": map[string]string{
			prefix + ":" + audienceConditionClaim(spec.OIDCProviderURL): spec.Audience,
		},
	}

	switch {
	case spec.Subject != "":
		conditionKey := "StringEquals"
		if spec.SubjectCondition != "" {
			conditionKey = spec.SubjectCondition
		}
		if _, ok := condition[conditionKey]; !ok {
			condition[conditionKey] = map[string]string{}
		}
		condition[conditionKey].(map[string]string)[prefix+":sub"] = spec.Subject
	case spec.AllowUnscopedSubject:
		// Deliberate and justified; Validate already required the justification.
	default:
		return nil, core.ErrValidation(fmt.Sprintf(
			"refusing to build a trust policy for role %q with no subject condition: it would be "+
				"assumable by every workload %s issues a token for. Set Subject, or set "+
				"AllowUnscopedSubject with UnscopedJustification",
			spec.RoleName, prefix)).WithProvider(core.AWS)
	}

	// sts:RoleAuthorizedByIdp, when asked for. STS evaluates this BEFORE the
	// trust policy, against the "https://aws.amazon.com/roles" claim the issuer
	// embedded — so the issuer gets a say in which roles its own tokens may
	// assume, and a stolen token is useless against roles it never named.
	//
	// A Bool condition, not a String one: the key answers "did the IdP
	// authorize this role", and the comparison against the claim is STS's.
	if spec.RequireIdPAuthorizedRole {
		condition["Bool"] = map[string]string{
			core.IdPAuthorizedRoleConditionKey: "true",
		}
	}

	return map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []map[string]interface{}{
			{
				"Effect": "Allow",
				"Principal": map[string]string{
					"Federated": principal,
				},
				"Action":    "sts:AssumeRoleWithWebIdentity",
				"Condition": condition,
			},
		},
	}, nil
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

// thumbprintDialTimeout bounds the TLS handshake used to read an issuer's chain.
const thumbprintDialTimeout = 10 * time.Second

// getOIDCThumbprint computes the SHA-1 thumbprint AWS stores for an OIDC
// provider: the fingerprint of the root-most certificate in the issuer's TLS
// chain.
//
// This used to return a hardcoded value for two issuers and forty zeroes, with a
// nil error, for everything else — which is every EKS cluster, every self-hosted
// IdP, every Okta or Auth0 tenant. The thumbprint is the pin on the issuer's
// certificate chain, so a constant silently disabled the control it exists to
// provide, and a hardcoded literal cannot follow a CA rotation. It is computed
// or it is an error; there is no useful third answer.
func (p *Provider) oidcThumbprint(ctx context.Context, issuer string) (string, error) {
	u, err := neturl.Parse(issuer)
	if err != nil {
		return "", fmt.Errorf("oidc thumbprint: issuer %q is not a URL: %w", issuer, err)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("oidc thumbprint: issuer %q must use https; an http issuer cannot be "+
			"pinned and its tokens cannot be trusted", issuer)
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}

	ctx, cancel := context.WithTimeout(ctx, thumbprintDialTimeout)
	defer cancel()

	cfg := p.tlsConfig.Clone()
	if cfg == nil {
		cfg = &tls.Config{}
	}
	if cfg.MinVersion == 0 {
		cfg.MinVersion = tls.VersionTLS12
	}
	if cfg.ServerName == "" {
		cfg.ServerName = u.Hostname()
	}
	d := &tls.Dialer{Config: cfg}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return "", fmt.Errorf("oidc thumbprint: connecting to %s: %w", host, err)
	}
	defer func() { _ = conn.Close() }()

	chain := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return "", fmt.Errorf("oidc thumbprint: %s presented no certificate", host)
	}
	// AWS pins the last certificate in the chain the server sends — the
	// root-most one it offers, not the leaf.
	sum := sha1.Sum(chain[len(chain)-1].Raw) // #nosec G401 -- AWS defines this thumbprint as SHA-1
	return hex.EncodeToString(sum[:]), nil
}

// isNotFoundError reports whether err means "the resource is absent", as opposed
// to "we could not tell".
//
// The typed check comes first and is the one that matters: IsNotFound unwraps to
// IAM's NoSuchEntityException. Substring matching on error text is how a
// create-or-update decision silently inverts after an SDK message change, so it
// remains only as a fallback for errors that reached here already stringified.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	if IsNotFound(err) || core.IsCategory(err, core.ErrCategoryNotFound) {
		return true
	}
	return strings.Contains(err.Error(), "NoSuchEntity")
}

// Validators

type roleExistsValidator struct {
	client   IAMClient
	roleName string
}

func (v *roleExistsValidator) ID() string          { return "aws_role_exists" }
func (v *roleExistsValidator) Name() string        { return "AWS Role Exists" }
func (v *roleExistsValidator) Description() string { return "Checks if the IAM role exists" }

func (v *roleExistsValidator) Validate(ctx context.Context, ref core.MechanismRef) core.ValidationCheck {
	check := core.NewCheck(v, core.SeverityCritical)
	check.Evidence["role_name"] = v.roleName

	role, err := v.client.GetRole(ctx, v.roleName)
	if err != nil {
		check.Status = core.CheckStatusFailed
		check.Evidence["error"] = err.Error()
		check.Remediation = "Create the IAM role or run setup again"
		return check
	}

	check.Status = core.CheckStatusPassed
	check.Evidence["role_arn"] = role.ARN
	return check
}

type oidcProviderExistsValidator struct {
	client IAMClient
	arn    string
}

func (v *oidcProviderExistsValidator) ID() string   { return "aws_oidc_provider_exists" }
func (v *oidcProviderExistsValidator) Name() string { return "OIDC Provider Exists" }
func (v *oidcProviderExistsValidator) Description() string {
	return "Checks if the OIDC provider exists"
}

func (v *oidcProviderExistsValidator) Validate(ctx context.Context, ref core.MechanismRef) core.ValidationCheck {
	check := core.NewCheck(v, core.SeverityCritical)
	check.Evidence["oidc_provider_arn"] = v.arn

	provider, err := v.client.GetOpenIDConnectProvider(ctx, v.arn)
	if err != nil {
		check.Status = core.CheckStatusFailed
		check.Evidence["error"] = err.Error()
		check.Remediation = "Create the OIDC provider or run setup again"
		return check
	}

	check.Status = core.CheckStatusPassed
	check.Evidence["url"] = provider.URL
	return check
}

func init() {
	// Register with default registry
	// Panic rather than discard: Register fails only on a duplicate name, which
	// is a programming error, and the alternative is a provider that silently
	// does not exist. Every command that reaches for it would then report
	// "provider not found" and send the reader looking in the wrong place.
	if err := core.Register(New()); err != nil {
		panic("cloud-auth/provider/aws: registering the AWS provider: " + err.Error())
	}
}
