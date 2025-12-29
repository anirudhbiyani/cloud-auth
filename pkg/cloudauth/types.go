// Package cloudauth provides core types and interfaces for cross-cloud
// authentication lifecycle management.
//
// This package defines the fundamental abstractions for managing cross-cloud
// authentication mechanisms including setup, validation, and deletion operations.
package cloudauth

import (
	"context"
	"encoding/json"
	"time"
)

// Capability represents a feature supported by a provider or mechanism.
type Capability string

const (
	// CapabilityToken indicates support for token acquisition.
	CapabilityToken Capability = "token"
	// CapabilitySetup indicates support for mechanism setup/creation.
	CapabilitySetup Capability = "setup"
	// CapabilityValidate indicates support for configuration validation.
	CapabilityValidate Capability = "validate"
	// CapabilityDelete indicates support for mechanism deletion.
	CapabilityDelete Capability = "delete"
	// CapabilityDryRun indicates support for dry-run mode.
	CapabilityDryRun Capability = "dry_run"
	// CapabilityFederationOIDC indicates support for OIDC federation.
	CapabilityFederationOIDC Capability = "federation_oidc"
	// CapabilityFederationSAML indicates support for SAML federation.
	CapabilityFederationSAML Capability = "federation_saml"
)

// CloudProvider identifies a cloud service provider.
type CloudProvider string

const (
	ProviderAWS        CloudProvider = "aws"
	ProviderGCP        CloudProvider = "gcp"
	ProviderAzure      CloudProvider = "azure"
	ProviderCloudflare CloudProvider = "cloudflare"
	ProviderVault      CloudProvider = "vault"
	ProviderOkta       CloudProvider = "okta"
	ProviderGitHubOIDC CloudProvider = "github_oidc"
	ProviderKubernetes CloudProvider = "kubernetes"
)

// MechanismType identifies the type of cross-cloud auth mechanism.
type MechanismType string

const (
	// MechanismAWSRoleTrustOIDC represents an AWS IAM Role trusting an OIDC IdP.
	MechanismAWSRoleTrustOIDC MechanismType = "aws_role_trust_oidc"
	// MechanismGCPWorkloadIdentityPool represents a GCP Workload Identity Pool.
	MechanismGCPWorkloadIdentityPool MechanismType = "gcp_workload_identity_pool"
	// MechanismAzureFederatedCredential represents an Azure Federated Credential.
	MechanismAzureFederatedCredential MechanismType = "azure_federated_credential"
	// MechanismK8sServiceAccountFederation represents K8s SA to cloud identity mapping.
	MechanismK8sServiceAccountFederation MechanismType = "k8s_service_account_federation"
)

// MechanismRef is a stable reference to a created mechanism instance.
// It contains identifiers needed to validate, update, or delete the mechanism.
type MechanismRef struct {
	// ID is a unique identifier for this mechanism instance.
	ID string `json:"id"`

	// Type identifies the mechanism type.
	Type MechanismType `json:"type"`

	// Provider is the cloud provider managing this mechanism.
	Provider CloudProvider `json:"provider"`

	// ResourceIDs contains cloud-specific resource identifiers.
	// Keys are resource types (e.g., "role_arn", "pool_id"), values are IDs.
	ResourceIDs map[string]string `json:"resource_ids"`

	// CreatedAt is when this mechanism was created.
	CreatedAt time.Time `json:"created_at"`

	// Owned indicates whether the mechanism was created by cloud-auth
	// and can be safely deleted.
	Owned bool `json:"owned"`

	// Version tracks schema version for migration purposes.
	Version int `json:"version"`
}

// Outputs contains non-secret outputs from a mechanism setup operation.
type Outputs struct {
	// MechanismRef is the reference to the created mechanism.
	Ref MechanismRef `json:"ref"`

	// Values contains non-secret output values.
	// Keys are output names (e.g., "audience", "issuer_url"), values are strings.
	Values map[string]string `json:"values,omitempty"`

	// SecretRefs contains references to secrets (not the secrets themselves).
	// The actual secrets should be handled via SecretSink.
	SecretRefs map[string]SecretRef `json:"secret_refs,omitempty"`

	// Instructions contains human-readable setup instructions if manual steps needed.
	Instructions []string `json:"instructions,omitempty"`
}

// SecretRef is a reference to a secret stored in an external secret manager.
// cloud-auth never returns secret values directly; it returns references.
type SecretRef struct {
	// Provider is the secret store provider (e.g., "aws_secrets_manager", "vault").
	Provider string `json:"provider"`

	// ID is the secret identifier in the provider.
	ID string `json:"id"`

	// Version is the secret version if applicable.
	Version string `json:"version,omitempty"`
}

// Severity indicates the severity level of a validation check.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityError    Severity = "error"
	SeverityCritical Severity = "critical"
)

// CheckStatus indicates the result of a validation check.
type CheckStatus string

const (
	CheckStatusPassed  CheckStatus = "passed"
	CheckStatusFailed  CheckStatus = "failed"
	CheckStatusSkipped CheckStatus = "skipped"
	CheckStatusUnknown CheckStatus = "unknown"
)

// ValidationCheck represents a single validation check result.
type ValidationCheck struct {
	// ID is a unique identifier for this check type.
	ID string `json:"id"`

	// Name is a human-readable name for the check.
	Name string `json:"name"`

	// Description explains what this check validates.
	Description string `json:"description"`

	// Status is the check result.
	Status CheckStatus `json:"status"`

	// Severity indicates how serious a failure would be.
	Severity Severity `json:"severity"`

	// Evidence contains data supporting the check result.
	Evidence map[string]interface{} `json:"evidence,omitempty"`

	// Remediation contains steps to fix a failed check.
	Remediation string `json:"remediation,omitempty"`

	// Duration is how long the check took to run.
	Duration time.Duration `json:"duration"`
}

// ValidationReport contains the results of validating a mechanism.
type ValidationReport struct {
	// MechanismRef identifies the validated mechanism.
	Ref MechanismRef `json:"ref"`

	// Checks contains all validation check results.
	Checks []ValidationCheck `json:"checks"`

	// Summary provides aggregate status.
	Summary ValidationSummary `json:"summary"`

	// ValidatedAt is when validation was performed.
	ValidatedAt time.Time `json:"validated_at"`
}

// ValidationSummary provides aggregate validation statistics.
type ValidationSummary struct {
	TotalChecks   int  `json:"total_checks"`
	PassedChecks  int  `json:"passed_checks"`
	FailedChecks  int  `json:"failed_checks"`
	SkippedChecks int  `json:"skipped_checks"`
	IsValid       bool `json:"is_valid"`
}

// IsValid returns true if all checks passed or were skipped.
func (r *ValidationReport) IsValid() bool {
	for _, check := range r.Checks {
		if check.Status == CheckStatusFailed && check.Severity >= SeverityError {
			return false
		}
	}
	return true
}

// FailedChecks returns only the checks that failed.
func (r *ValidationReport) FailedChecks() []ValidationCheck {
	var failed []ValidationCheck
	for _, check := range r.Checks {
		if check.Status == CheckStatusFailed {
			failed = append(failed, check)
		}
	}
	return failed
}

// Plan represents a set of planned actions for dry-run mode.
type Plan struct {
	// Actions lists the planned operations.
	Actions []PlannedAction `json:"actions"`

	// Summary provides a human-readable summary.
	Summary string `json:"summary"`
}

// PlannedAction represents a single action that would be taken.
type PlannedAction struct {
	// Operation is the type of operation (create, update, delete).
	Operation string `json:"operation"`

	// ResourceType is the type of resource affected.
	ResourceType string `json:"resource_type"`

	// ResourceID is the ID of the resource (if known).
	ResourceID string `json:"resource_id,omitempty"`

	// Details contains operation-specific details.
	Details map[string]interface{} `json:"details,omitempty"`

	// Reversible indicates whether this action can be rolled back.
	Reversible bool `json:"reversible"`
}

// String implements fmt.Stringer for MechanismRef.
func (r MechanismRef) String() string {
	data, _ := json.Marshal(r)
	return string(data)
}

// SetupOptions configures a Setup operation.
type SetupOptions struct {
	// DryRun if true, returns a Plan instead of making changes.
	DryRun bool

	// Force if true, overwrite existing resources.
	Force bool

	// Tags to apply to created resources.
	Tags map[string]string

	// SecretSink receives any generated secrets.
	SecretSink SecretSink
}

// ValidateOptions configures a Validate operation.
type ValidateOptions struct {
	// CheckIDs limits validation to specific checks.
	CheckIDs []string

	// IncludeTokenTest if true, attempts actual token acquisition.
	IncludeTokenTest bool

	// Timeout for the validation operation.
	Timeout time.Duration
}

// DeleteOptions configures a Delete operation.
type DeleteOptions struct {
	// DryRun if true, returns a Plan instead of making changes.
	DryRun bool

	// Force if true, delete even non-owned resources.
	Force bool

	// OwnedOnly if true (default), only delete resources created by cloud-auth.
	OwnedOnly bool

	// Confirm is a callback that must return true to proceed.
	// Used for interactive confirmation.
	Confirm func(Plan) bool
}

// SecretSink is an interface for securely handling generated secrets.
// Implementations can write secrets to secure storage like Vault or cloud secret managers.
type SecretSink interface {
	// StoreSecret stores a secret and returns a reference to it.
	StoreSecret(ctx context.Context, name string, value []byte) (SecretRef, error)
}

// NullSecretSink is a SecretSink that discards secrets (for testing or when not needed).
type NullSecretSink struct{}

// StoreSecret implements SecretSink by discarding the secret.
func (NullSecretSink) StoreSecret(ctx context.Context, name string, value []byte) (SecretRef, error) {
	return SecretRef{Provider: "null", ID: name}, nil
}

