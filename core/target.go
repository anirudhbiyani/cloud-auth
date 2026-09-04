package core

import (
	"fmt"
	"strings"
)

// Target is the binding a caller wants credentials for. The source identity is
// auto-detected; the target is always explicit.
//
// One type per cloud, rather than one struct with every cloud's fields side by
// side. The previous shape carried Role, WorkloadIdentityPool,
// ImpersonateServiceAccount, Tenant and ClientID together, of which only one
// cloud's worth was ever meaningful — so an AWS role ARN set on an Azure target
// was silently ignored, and adding a cloud meant widening a struct that every
// exchanger already had to read defensively. Here the cloud is implied by the
// type, an impossible combination cannot be written down, and a new cloud is a
// new type rather than an edit to a shared one.
type Target interface {
	// Cloud identifies which target STS to call.
	Cloud() Cloud

	// Audience is the value the source proof must be pinned to. Exchangers refuse
	// to transmit a proof minted for anything else.
	Audience() string

	// Validate rejects an incomplete binding before any network call.
	Validate() error
}

// NoTarget is the absence of a target binding, expressed as a value.
//
// Target is an interface, so an untyped nil has no method table and any method
// call on it panics. Returning nil for "the caller passed no --to" therefore put
// the burden on every consumer to nil-check before dispatch, in the right order,
// forever — and `cloud-auth doctor` with no arguments, the tool's most common
// invocation, shipped a segfault because one consumer checked after the call
// rather than before.
//
// A typed zero removes the class rather than patching the call sites. Cloud()
// returns the empty string, which is already the idiom the runtime commands use
// to mean "no target was named", and Validate() refuses rather than pretending
// an empty binding is usable.
type NoTarget struct{}

// Cloud reports the empty cloud: no target was named.
func (NoTarget) Cloud() Cloud { return "" }

// Audience is empty. A caller must not pin a proof to a target that is absent.
func (NoTarget) Audience() string { return "" }

// Validate always fails. Reaching it means a binding that was never named got
// as far as a network call.
func (NoTarget) Validate() error {
	return fmt.Errorf("no target: pass --to, or --config with --target")
}

// Default audiences. Each is the only value its cloud accepts, or the
// conventional one, so requiring the caller to restate it adds nothing.
const (
	// DefaultAWSAudience is the audience AWS STS accepts for web identity.
	DefaultAWSAudience = "sts.amazonaws.com"

	// DefaultAzureAudience is Entra's federated-credential audience.
	//
	// Note that it is not tenant-bound: any tenant holding a federated credential
	// for the same issuer and subject accepts the same assertion, which is why
	// AzureTarget.Tenant is validated rather than merely interpolated.
	DefaultAzureAudience = "api://AzureADTokenExchange"
)

// AWSTarget requests credentials for an IAM role via
// sts:AssumeRoleWithWebIdentity.
type AWSTarget struct {
	// RoleARN is the role to assume.
	RoleARN string

	// TokenAudience overrides the audience the proof is pinned to. Empty means
	// DefaultAWSAudience.
	TokenAudience string

	// SessionName sets sts:RoleSessionName. Empty derives it from the proof's
	// subject, which is what makes CloudTrail attributable — a constant here
	// makes every federated session in the fleet look like the same caller, and
	// defeats trust policies that constrain sts:RoleSessionName.
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
	// WorkloadIdentityPool is the full provider resource name,
	// //iam.googleapis.com/projects/N/locations/global/workloadIdentityPools/P/providers/X.
	WorkloadIdentityPool string

	// ImpersonateServiceAccount optionally exchanges the federated token for a
	// service-account token. Empty means direct resource access, which is the
	// narrower default.
	ImpersonateServiceAccount string

	// TokenAudience overrides the audience. Empty means the pool resource name,
	// which is what GCP expects.
	TokenAudience string
}

func (t GCPTarget) Cloud() Cloud { return GCP }

func (t GCPTarget) Audience() string {
	if t.TokenAudience != "" {
		return t.TokenAudience
	}
	return normalizeWIFPool(t.WorkloadIdentityPool)
}

// normalizeWIFPool accepts either the full audience form or the bare resource
// name and returns the form GCP's STS expects.
//
// Both are in circulation: gcloud prints the bare
// "projects/N/locations/global/workloadIdentityPools/P/providers/X", while the
// token exchange requires it prefixed with "//iam.googleapis.com/". Rejecting
// the bare form would be defensible but unkind — it is unambiguous, so accept it
// and prepend the prefix rather than making the operator learn the difference
// from a GCP STS rejection.
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

// AzureTarget requests an Entra access token via the client-credentials grant
// with a federated client assertion.
type AzureTarget struct {
	// Tenant is the specific tenant to authenticate against: a GUID or a verified
	// domain. Multi-tenant aliases are refused, because the default audience is
	// not tenant-bound and an alias would delegate the choice of who receives a
	// usable proof of this workload's identity.
	Tenant string

	// ClientID is the app registration or user-assigned identity to authenticate
	// as.
	ClientID string

	// TokenAudience overrides the assertion audience. Empty means
	// DefaultAzureAudience.
	TokenAudience string

	// Scope is the resource scope to request. Empty means the caller must set it:
	// there is no safe default, and the previous one
	// (https://management.azure.com/.default) was the broadest scope in Azure.
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
//
// The Claude Platform's Workload Identity Federation exchanges an OIDC proof
// for an `sk-ant-oat01-...` token bound to a service account, so it is a
// federation target in exactly the sense the other three are — an OIDC proof in,
// a short-lived native credential out.
//
// It differs from them in where the trust conditions live. AWS and Azure carry
// the issuer, subject and audience on the target-side resource, and the request
// names only what to assume. Anthropic evaluates a FEDERATION RULE identified by
// id, and the rule holds the match conditions — so the request names the rule
// and the identity to act as, and nothing about what the token must contain.
// Rules are looked up by id and never searched: a proof that satisfies a
// different rule is refused rather than quietly matched against it.
type AnthropicTarget struct {
	// FederationRuleID is the rule to evaluate this proof against (fdrl_...).
	FederationRuleID string

	// OrganizationID is the Anthropic organization (a UUID).
	OrganizationID string

	// ServiceAccountID is the identity the minted token acts as (svac_...).
	ServiceAccountID string

	// WorkspaceID scopes the minted token (wrkspc_...). Required when the rule
	// covers more than one workspace; the platform resolves it otherwise.
	WorkspaceID string

	// TokenAudience is the audience the source proof must be minted for.
	//
	// No default, deliberately. A federation rule MAY match on an exact
	// audience, and which value that is belongs to whoever wrote the rule —
	// guessing it would mint a proof pinned to the wrong party, which is a
	// disclosure whether or not the exchange then succeeds.
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
	// Audience has no default and is checked here rather than left to the
	// exchanger, so a missing one fails before a proof is minted at all.
	if strings.TrimSpace(t.TokenAudience) == "" {
		return fmt.Errorf("anthropic target: audience is required and has no default — " +
			"a federation rule may match on an exact audience, and guessing it would pin the " +
			"proof to the wrong party")
	}
	return nil
}
