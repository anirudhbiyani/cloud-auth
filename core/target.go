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
