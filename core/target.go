package core

import (
	"fmt"
	"strings"
)

// Target is the binding a caller wants credentials for.
type Target interface {
	// Cloud identifies which target STS to call.
	Cloud() Cloud

	// Audience is the value the source proof must be pinned to.
	Audience() string

	// Validate rejects an incomplete binding before any network call.
	Validate() error
}

// NoTarget is the absence of a target binding, expressed as a value.
type NoTarget struct{}

// Cloud reports the empty cloud: no target was named.
func (NoTarget) Cloud() Cloud { return "" }

// Audience is empty. A caller must not pin a proof to a target that is absent.
func (NoTarget) Audience() string { return "" }

// Validate always fails.
func (NoTarget) Validate() error {
	return fmt.Errorf("no target: pass --to, or --config with --target")
}

// Default audiences.
const (
	// DefaultAWSAudience is the audience AWS STS accepts for web identity.
	DefaultAWSAudience = "sts.amazonaws.com"

	// DefaultAzureAudience is Entra's federated-credential audience.
	DefaultAzureAudience = "api://AzureADTokenExchange"
)

// AWSTarget requests credentials for an IAM role via sts:AssumeRoleWithWebIdentity.
type AWSTarget struct {
	// RoleARN is the role to assume.
	RoleARN string

	// TokenAudience overrides the audience the proof is pinned to.
	TokenAudience string

	// SessionName sets sts:RoleSessionName.
	SessionName string

	// DurationSeconds requests a session lifetime. Zero uses the role's default.
	DurationSeconds int32
}

func (t AWSTarget) Cloud() Cloud { return AWS }

func (t AWSTarget) Audience() string {
	if t.TokenAudience != "" {
		return t.TokenAudience
	}
	return DefaultAWSAudience
}

func (t AWSTarget) Validate() error {
	if strings.TrimSpace(t.RoleARN) == "" {
		return fmt.Errorf("aws target: role ARN is required")
	}
	if err := ValidateAWSRoleARN(t.RoleARN); err != nil {
		return fmt.Errorf("aws target: %w", err)
	}
	if t.DurationSeconds != 0 && (t.DurationSeconds < 900 || t.DurationSeconds > 43200) {
		return fmt.Errorf("aws target: duration_seconds must be between 900 and 43200, got %d",
			t.DurationSeconds)
	}
	return nil
}

// GCPTarget requests credentials through Workload Identity Federation.
type GCPTarget struct {
	// WorkloadIdentityPool is the full provider resource name, //iam.googleapis.com/projects/N/locations/global/workloadIdentityPools/P/providers/X.
	WorkloadIdentityPool string

	// ImpersonateServiceAccount optionally exchanges the federated token for a service-account token.
	ImpersonateServiceAccount string

	// TokenAudience overrides the audience.
	TokenAudience string
}

func (t GCPTarget) Cloud() Cloud { return GCP }

func (t GCPTarget) Audience() string {
	if t.TokenAudience != "" {
		return t.TokenAudience
	}
	return normalizeWIFPool(t.WorkloadIdentityPool)
}

// normalizeWIFPool accepts either the full audience form or the bare resource name and returns the form GCP's STS expects.
func normalizeWIFPool(pool string) string {
	pool = strings.TrimSpace(pool)
	if pool == "" || strings.HasPrefix(pool, "//iam.googleapis.com/") {
		return pool
	}
	if strings.HasPrefix(pool, "projects/") {
		return "//iam.googleapis.com/" + pool
	}
	return pool
}

func (t GCPTarget) Validate() error {
	if strings.TrimSpace(t.WorkloadIdentityPool) == "" {
		return fmt.Errorf("gcp target: workload_identity_pool is required")
	}
	if !strings.HasPrefix(normalizeWIFPool(t.WorkloadIdentityPool), "//iam.googleapis.com/projects/") {
		return fmt.Errorf("gcp target: workload_identity_pool %q is not a provider resource name; "+
			"expected projects/N/locations/global/workloadIdentityPools/POOL/providers/PROVIDER, "+
			"optionally prefixed with //iam.googleapis.com/", t.WorkloadIdentityPool)
	}
	if t.ImpersonateServiceAccount != "" {
		if err := ValidateGCPServiceAccountEmail(t.ImpersonateServiceAccount); err != nil {
			return fmt.Errorf("gcp target: %w", err)
		}
	}
	return nil
}

// AzureTarget requests an Entra access token via the client-credentials grant with a federated client assertion.
type AzureTarget struct {
	// Tenant is the specific tenant to authenticate against: a GUID or a verified domain.
	Tenant string

	// ClientID is the app registration or user-assigned identity to authenticate as.
	ClientID string

	// TokenAudience overrides the assertion audience.
	TokenAudience string

	// Scope is the resource scope to request.
	Scope string
}

func (t AzureTarget) Cloud() Cloud { return Azure }

func (t AzureTarget) Audience() string {
	if t.TokenAudience != "" {
		return t.TokenAudience
	}
	return DefaultAzureAudience
}

func (t AzureTarget) Validate() error {
	if strings.TrimSpace(t.Tenant) == "" {
		return fmt.Errorf("azure target: tenant is required")
	}
	if err := ValidateAzureTenant(t.Tenant); err != nil {
		return fmt.Errorf("azure target: %w", err)
	}
	if strings.TrimSpace(t.ClientID) == "" {
		return fmt.Errorf("azure target: client_id is required")
	}
	if err := ValidateAzureUUID(t.ClientID); err != nil {
		return fmt.Errorf("azure target: client_id %w", err)
	}
	if strings.TrimSpace(t.Scope) == "" {
		return fmt.Errorf("azure target: scope is required; there is no safe default (the " +
			"previous one, https://management.azure.com/.default, granted the Azure control plane)")
	}
	return nil
}

// AnthropicTarget requests a short-lived Claude Platform access token.
type AnthropicTarget struct {
	// FederationRuleID is the rule to evaluate this proof against (fdrl_...).
	FederationRuleID string

	// OrganizationID is the Anthropic organization (a UUID).
	OrganizationID string

	// ServiceAccountID is the identity the minted token acts as (svac_...).
	ServiceAccountID string

	// WorkspaceID scopes the minted token (wrkspc_...).
	WorkspaceID string

	// TokenAudience is the audience the source proof must be minted for.
	TokenAudience string
}

func (t AnthropicTarget) Cloud() Cloud { return Anthropic }

func (t AnthropicTarget) Audience() string { return t.TokenAudience }

func (t AnthropicTarget) Validate() error {
	if strings.TrimSpace(t.FederationRuleID) == "" {
		return fmt.Errorf("anthropic target: federation_rule_id is required (fdrl_...); " +
			"rules are looked up by id and never searched")
	}
	if !strings.HasPrefix(t.FederationRuleID, "fdrl_") {
		return fmt.Errorf("anthropic target: federation_rule_id %q does not look like a rule id "+
			"(expected fdrl_...)", t.FederationRuleID)
	}
	if strings.TrimSpace(t.OrganizationID) == "" {
		return fmt.Errorf("anthropic target: organization_id is required")
	}
	if strings.TrimSpace(t.ServiceAccountID) == "" {
		return fmt.Errorf("anthropic target: service_account_id is required (svac_...)")
	}
	if !strings.HasPrefix(t.ServiceAccountID, "svac_") {
		return fmt.Errorf("anthropic target: service_account_id %q does not look like a service "+
			"account id (expected svac_...)", t.ServiceAccountID)
	}
	if t.WorkspaceID != "" && !strings.HasPrefix(t.WorkspaceID, "wrkspc_") {
		return fmt.Errorf("anthropic target: workspace_id %q does not look like a workspace id "+
			"(expected wrkspc_...)", t.WorkspaceID)
	}
	// Audience has no default and is checked here rather than left to the exchanger, so a missing one fails before a proof is minted at all.
	if strings.TrimSpace(t.TokenAudience) == "" {
		return fmt.Errorf("anthropic target: audience is required and has no default — " +
			"a federation rule may match on an exact audience, and guessing it would pin the " +
			"proof to the wrong party")
	}
	return nil
}
