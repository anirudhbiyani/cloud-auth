package core

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// AWSRoleTrustOIDCSpec specifies an AWS IAM Role trusting an OIDC identity provider.
// This is used for scenarios like GitHub Actions, Kubernetes, or external OIDC providers
// accessing AWS resources.
type AWSRoleTrustOIDCSpec struct {
	// RoleName is the name of the IAM role to create or update.
	RoleName string `json:"role_name" yaml:"role_name"`

	// RoleARN is the ARN of an existing role to update (mutually exclusive with RoleName).
	RoleARN string `json:"role_arn,omitempty" yaml:"role_arn,omitempty"`

	// AccountID is the AWS account ID where the role should be created.
	AccountID string `json:"account_id" yaml:"account_id"`

	// OIDCProviderARN is the ARN of an existing OIDC provider.
	// If empty and OIDCProviderURL is set, a new provider will be created.
	OIDCProviderARN string `json:"oidc_provider_arn,omitempty" yaml:"oidc_provider_arn,omitempty"`

	// OIDCProviderURL is the URL of the OIDC identity provider.
	// Used to create a new OIDC provider if OIDCProviderARN is not set.
	OIDCProviderURL string `json:"oidc_provider_url,omitempty" yaml:"oidc_provider_url,omitempty"`

	// Audience is the expected audience claim in the OIDC token.
	Audience string `json:"audience" yaml:"audience"`

	// Subject is the expected subject claim pattern (can use wildcards).
	Subject string `json:"subject,omitempty" yaml:"subject,omitempty"`

	// SubjectCondition specifies the condition operator for subject matching.
	// Valid values: "StringEquals", "StringLike" (for wildcards).
	SubjectCondition string `json:"subject_condition,omitempty" yaml:"subject_condition,omitempty"`

	// AllowUnscopedSubject permits a trust policy with no sub condition at all.
	//
	// A policy that pins only `aud` is assumable by every workload the issuer
	// serves — for GitHub Actions, whose audience is the freely-requestable
	// sts.amazonaws.com, that is every repository on GitHub. It is occasionally
	// what you want (an issuer you operate, whose every token is equally
	// trusted), so it stays expressible — but only deliberately, and only with a
	// reason recorded next to it.
	AllowUnscopedSubject bool `json:"allow_unscoped_subject,omitempty" yaml:"allow_unscoped_subject,omitempty"`

	// UnscopedJustification records why an unscoped trust is acceptable here.
	// Required whenever AllowUnscopedSubject is set, so the decision survives in
	// the spec for the next reader and for review.
	UnscopedJustification string `json:"unscoped_justification,omitempty" yaml:"unscoped_justification,omitempty"`

	// PolicyARNs are managed policy ARNs to attach to the role.
	PolicyARNs []string `json:"policy_arns,omitempty" yaml:"policy_arns,omitempty"`

	// InlinePolicy is an inline policy document to attach to the role.
	InlinePolicy string `json:"inline_policy,omitempty" yaml:"inline_policy,omitempty"`

	// MaxSessionDuration is the maximum session duration in seconds (3600-43200).
	MaxSessionDuration int `json:"max_session_duration,omitempty" yaml:"max_session_duration,omitempty"`

	// Tags are resource tags to apply.
	Tags map[string]string `json:"tags,omitempty" yaml:"tags,omitempty"`

	// Description is a description for the IAM role.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// PermissionsBoundary is the ARN of a permissions boundary policy.
	PermissionsBoundary string `json:"permissions_boundary,omitempty" yaml:"permissions_boundary,omitempty"`

	// RequireIdPAuthorizedRole adds the sts:RoleAuthorizedByIdp condition.
	//
	// AWS shipped this in July 2026. An identity provider may embed
	// "https://aws.amazon.com/roles" in the OIDC token naming which roles that
	// token may assume, and STS enforces it as an ALLOW-LIST *before* the role
	// trust policy is evaluated. That inverts the usual direction: normally
	// only the account decides who may assume a role, and this lets the issuer
	// constrain it too, so a stolen token is useless against roles its issuer
	// never authorized.
	//
	// Off by default, and it must stay that way: turning it on for an issuer
	// that does not emit the claim locks every workload out of the role. There
	// is no partial credit — the condition either matches or the exchange is
	// refused before the trust policy is read.
	RequireIdPAuthorizedRole bool `json:"require_idp_authorized_role,omitempty" yaml:"require_idp_authorized_role,omitempty"`

	// SourceProvider identifies the OIDC provider type.
	Source Cloud `json:"source" yaml:"source"`
}

// IdPAuthorizedRoleClaim is the claim STS reads for sts:RoleAuthorizedByIdp.
//
// A string or an array of role ARNs, embedded by the identity provider.
const IdPAuthorizedRoleClaim = "https://aws.amazon.com/roles"

// IdPAuthorizedRoleConditionKey is the IAM condition key STS evaluates.
const IdPAuthorizedRoleConditionKey = "sts:RoleAuthorizedByIdp"

// Type implements MechanismSpec.
func (s *AWSRoleTrustOIDCSpec) Type() MechanismType {
	return MechanismAWSRoleTrustOIDC
}

// Validate implements MechanismSpec.
func (s *AWSRoleTrustOIDCSpec) Validate() error {
	if s.RoleName == "" && s.RoleARN == "" {
		return fmt.Errorf("either role_name or role_arn must be specified")
	}
	if s.RoleName != "" && s.RoleARN != "" {
		return fmt.Errorf("role_name and role_arn are mutually exclusive")
	}
	if s.AccountID == "" && s.RoleARN == "" {
		return fmt.Errorf("account_id is required when role_name is specified")
	}
	if s.AccountID != "" {
		if err := ValidateAWSAccountID(s.AccountID); err != nil {
			return err
		}
	}
	if s.RoleARN != "" {
		if err := ValidateAWSRoleARN(s.RoleARN); err != nil {
			return err
		}
	}
	if s.OIDCProviderARN == "" && s.OIDCProviderURL == "" {
		return fmt.Errorf("either oidc_provider_arn or oidc_provider_url must be specified")
	}
	if s.OIDCProviderURL != "" {
		// An http issuer cannot be pinned to a certificate chain, so AWS cannot
		// bind the provider to a known CA and its tokens cannot be trusted.
		if err := ValidateURL(s.OIDCProviderURL); err != nil {
			return fmt.Errorf("oidc_provider_url: %w", err)
		}
	}
	if s.Audience == "" {
		return fmt.Errorf("audience is required")
	}
	if s.MaxSessionDuration != 0 && (s.MaxSessionDuration < 3600 || s.MaxSessionDuration > 43200) {
		return fmt.Errorf("max_session_duration must be between 3600 and 43200 seconds")
	}
	if s.SubjectCondition != "" && s.SubjectCondition != "StringEquals" && s.SubjectCondition != "StringLike" {
		return fmt.Errorf("subject_condition must be 'StringEquals' or 'StringLike'")
	}
	if err := validateSubjectScope(s.Subject, s.AllowUnscopedSubject, s.UnscopedJustification); err != nil {
		return err
	}
	return nil
}

// unscopedSubjectPatterns are subject values that admit every workload the
// issuer serves. They match nothing more narrowly than "*" does, so accepting
// one silently is the same hole as omitting the condition entirely.
var unscopedSubjectPatterns = map[string]bool{
	"*": true, "?*": true, "*:*": true, "**": true,
}

// validateSubjectScope enforces that a mechanism pins the subject claim, or says
// out loud that it is choosing not to.
//
// The subject is the only part of an OIDC trust that identifies *which* workload
// may assume the identity. The audience does not: it is chosen by the token
// requester, and for the common issuers it is a well-known constant. So a
// mechanism with no subject condition is world-assumable within its issuer, and
// that has to be a deliberate, recorded decision rather than a default.
func validateSubjectScope(subject string, allowUnscoped bool, justification string) error {
	trimmed := strings.TrimSpace(subject)

	if trimmed == "" {
		if !allowUnscoped {
			return fmt.Errorf("subject is required: a trust policy that pins only the audience is " +
				"assumable by every workload the issuer serves (for GitHub Actions, every repository " +
				"on GitHub). Set subject, or set allow_unscoped_subject with unscoped_justification " +
				"to accept that deliberately")
		}
		if strings.TrimSpace(justification) == "" {
			return fmt.Errorf("allow_unscoped_subject requires unscoped_justification: record why " +
				"every workload from this issuer may assume this identity")
		}
		return nil
	}

	if unscopedSubjectPatterns[trimmed] && !allowUnscoped {
		return fmt.Errorf("subject %q admits any workload from this issuer, which is the same as "+
			"pinning no subject at all; narrow it, or set allow_unscoped_subject with "+
			"unscoped_justification", subject)
	}
	return nil
}

// SourceProvider implements MechanismSpec.
func (s *AWSRoleTrustOIDCSpec) SourceProvider() Cloud {
	return s.Source
}

// TargetProvider implements MechanismSpec.
func (s *AWSRoleTrustOIDCSpec) TargetProvider() Cloud {
	return AWS
}

// GCPWorkloadIdentityPoolSpec specifies a GCP Workload Identity Pool configuration.
// This enables external identities (AWS, Azure, OIDC) to access GCP resources.
type GCPWorkloadIdentityPoolSpec struct {
	// ProjectID is the GCP project ID.
	ProjectID string `json:"project_id" yaml:"project_id"`

	// ProjectNumber is the GCP project number.
	ProjectNumber string `json:"project_number" yaml:"project_number"`

	// PoolID is the workload identity pool ID (will be created if not exists).
	PoolID string `json:"pool_id" yaml:"pool_id"`

	// PoolDisplayName is a human-readable name for the pool.
	PoolDisplayName string `json:"pool_display_name,omitempty" yaml:"pool_display_name,omitempty"`

	// ProviderID is the identity provider ID within the pool.
	ProviderID string `json:"provider_id" yaml:"provider_id"`

	// ProviderDisplayName is a human-readable name for the provider.
	ProviderDisplayName string `json:"provider_display_name,omitempty" yaml:"provider_display_name,omitempty"`

	// ProviderType specifies the external identity provider type.
	// Valid values: "aws", "oidc", "saml".
	ProviderType string `json:"provider_type" yaml:"provider_type"`

	// AWSAccountID is required when ProviderType is "aws".
	AWSAccountID string `json:"aws_account_id,omitempty" yaml:"aws_account_id,omitempty"`

	// OIDCIssuerURL is required when ProviderType is "oidc".
	OIDCIssuerURL string `json:"oidc_issuer_url,omitempty" yaml:"oidc_issuer_url,omitempty"`

	// AllowedAudiences for OIDC tokens.
	AllowedAudiences []string `json:"allowed_audiences,omitempty" yaml:"allowed_audiences,omitempty"`

	// AttributeMapping maps external attributes to Google attributes.
	AttributeMapping map[string]string `json:"attribute_mapping,omitempty" yaml:"attribute_mapping,omitempty"`

	// AttributeCondition is a CEL expression for attribute conditions.
	//
	// This is the pool provider's admission control: with no condition, the
	// provider accepts every identity the issuer will mint a token for.
	AttributeCondition string `json:"attribute_condition,omitempty" yaml:"attribute_condition,omitempty"`

	// SubjectScope narrows which pool identities may impersonate the service
	// account. It is the value after the principal type in the IAM member
	// string, so a Subject scope of "repo:org/repo:ref:refs/heads/main" becomes
	//
	//	principalSet://iam.googleapis.com/<pool>/subject/repo:org/repo:ref:…
	//
	// Empty means the whole pool, which is what Google's documentation warns
	// against: every identity that can federate through ANY provider in the pool
	// would be able to impersonate the target service account.
	SubjectScope string `json:"subject_scope,omitempty" yaml:"subject_scope,omitempty"`

	// AttributeScope is the alternative to SubjectScope for providers that map
	// attributes: an attribute name and value, joined as "attribute.<name>/<value>".
	// Mutually exclusive with SubjectScope.
	AttributeScope string `json:"attribute_scope,omitempty" yaml:"attribute_scope,omitempty"`

	// AllowWholePoolImpersonation permits the unscoped principalSet://…/* form.
	AllowWholePoolImpersonation bool `json:"allow_whole_pool_impersonation,omitempty" yaml:"allow_whole_pool_impersonation,omitempty"`

	// UnscopedJustification records why whole-pool impersonation is acceptable.
	// Required with AllowWholePoolImpersonation.
	UnscopedJustification string `json:"unscoped_justification,omitempty" yaml:"unscoped_justification,omitempty"`

	// ServiceAccountEmail is the service account to impersonate.
	ServiceAccountEmail string `json:"service_account_email" yaml:"service_account_email"`

	// CreateServiceAccount if true, creates the service account if it doesn't exist.
	CreateServiceAccount bool `json:"create_service_account,omitempty" yaml:"create_service_account,omitempty"`

	// ServiceAccountRoles are IAM roles to grant to the service account.
	ServiceAccountRoles []string `json:"service_account_roles,omitempty" yaml:"service_account_roles,omitempty"`

	// Source identifies the external identity provider.
	Source Cloud `json:"source" yaml:"source"`
}

// Type implements MechanismSpec.
func (s *GCPWorkloadIdentityPoolSpec) Type() MechanismType {
	return MechanismGCPWorkloadIdentityPool
}

// Validate implements MechanismSpec.
func (s *GCPWorkloadIdentityPoolSpec) Validate() error {
	if s.ProjectID == "" {
		return fmt.Errorf("project_id is required")
	}
	if s.ProjectNumber == "" {
		return fmt.Errorf("project_number is required")
	}
	if s.PoolID == "" {
		return fmt.Errorf("pool_id is required")
	}
	if s.ProviderID == "" {
		return fmt.Errorf("provider_id is required")
	}
	if s.ServiceAccountEmail == "" {
		return fmt.Errorf("service_account_email is required")
	}
	if err := ValidateGCPProjectID(s.ProjectID); err != nil {
		return err
	}
	if err := ValidateGCPServiceAccountEmail(s.ServiceAccountEmail); err != nil {
		return err
	}

	switch s.ProviderType {
	case "aws":
		if s.AWSAccountID == "" {
			return fmt.Errorf("aws_account_id is required for AWS provider type")
		}
		if err := ValidateAWSAccountID(s.AWSAccountID); err != nil {
			return err
		}
	case "oidc":
		if s.OIDCIssuerURL == "" {
			return fmt.Errorf("oidc_issuer_url is required for OIDC provider type")
		}
		if err := ValidateURL(s.OIDCIssuerURL); err != nil {
			return fmt.Errorf("oidc_issuer_url: %w", err)
		}
	case "saml":
		// SAML-specific validation
	default:
		return fmt.Errorf("provider_type must be 'aws', 'oidc', or 'saml'")
	}

	if s.SubjectScope != "" && s.AttributeScope != "" {
		return fmt.Errorf("subject_scope and attribute_scope are mutually exclusive")
	}

	// The pool provider decides who may federate; the IAM binding decides who
	// may then impersonate. Both have to be narrowed, and neither has a safe
	// default, so both are required.
	if s.AttributeCondition == "" && !s.AllowWholePoolImpersonation {
		return fmt.Errorf("attribute_condition is required: a workload identity pool provider with " +
			"no attribute condition accepts every identity its issuer will mint a token for. " +
			"Set attribute_condition, or set allow_whole_pool_impersonation with " +
			"unscoped_justification to accept that deliberately")
	}
	if s.SubjectScope == "" && s.AttributeScope == "" && !s.AllowWholePoolImpersonation {
		return fmt.Errorf("subject_scope or attribute_scope is required: binding "+
			"roles/iam.workloadIdentityUser to the whole pool lets every identity that can "+
			"federate through any provider in it impersonate %s. Set a scope, or set "+
			"allow_whole_pool_impersonation with unscoped_justification", s.ServiceAccountEmail)
	}
	if s.AllowWholePoolImpersonation && strings.TrimSpace(s.UnscopedJustification) == "" {
		return fmt.Errorf("allow_whole_pool_impersonation requires unscoped_justification: record " +
			"why every identity in this pool may impersonate the service account")
	}

	return nil
}

// ImpersonationPrincipal returns the IAM member string that may impersonate the
// service account, scoped as narrowly as the spec allows.
//
// Google's guidance is explicit that the whole-pool form should be avoided; this
// returns it only when the spec opted in, and Validate has by then required a
// justification.
func (s *GCPWorkloadIdentityPoolSpec) ImpersonationPrincipal(poolName string) string {
	const base = "principalSet://iam.googleapis.com/"
	switch {
	case s.SubjectScope != "":
		return base + poolName + "/subject/" + s.SubjectScope
	case s.AttributeScope != "":
		return base + poolName + "/attribute." + s.AttributeScope
	default:
		return base + poolName + "/*"
	}
}

// SourceProvider implements MechanismSpec.
func (s *GCPWorkloadIdentityPoolSpec) SourceProvider() Cloud {
	return s.Source
}

// TargetProvider implements MechanismSpec.
func (s *GCPWorkloadIdentityPoolSpec) TargetProvider() Cloud {
	return GCP
}

// AzureFederatedCredentialSpec specifies an Azure federated identity credential.
// This enables external identities to access Azure resources without secrets.
type AzureFederatedCredentialSpec struct {
	// TenantID is the Azure AD tenant ID.
	TenantID string `json:"tenant_id" yaml:"tenant_id"`

	// SubscriptionID is the Azure subscription ID.
	SubscriptionID string `json:"subscription_id,omitempty" yaml:"subscription_id,omitempty"`

	// ResourceGroup is the resource group for managed identity (if applicable).
	ResourceGroup string `json:"resource_group,omitempty" yaml:"resource_group,omitempty"`

	// IdentityType specifies whether to use app registration or managed identity.
	// Valid values: "app_registration", "managed_identity".
	IdentityType string `json:"identity_type" yaml:"identity_type"`

	// ApplicationID is the app registration client ID (for app_registration type).
	ApplicationID string `json:"application_id,omitempty" yaml:"application_id,omitempty"`

	// ApplicationDisplayName is for creating new app registrations.
	ApplicationDisplayName string `json:"application_display_name,omitempty" yaml:"application_display_name,omitempty"`

	// ManagedIdentityName is the name of the managed identity (for managed_identity type).
	ManagedIdentityName string `json:"managed_identity_name,omitempty" yaml:"managed_identity_name,omitempty"`

	// CreateManagedIdentity if true, creates the managed identity if it doesn't exist.
	CreateManagedIdentity bool `json:"create_managed_identity,omitempty" yaml:"create_managed_identity,omitempty"`

	// FederatedCredentialName is the name of the federated credential.
	FederatedCredentialName string `json:"federated_credential_name" yaml:"federated_credential_name"`

	// Issuer is the OIDC issuer URL of the external identity provider.
	Issuer string `json:"issuer" yaml:"issuer"`

	// Subject is the external identity subject claim.
	Subject string `json:"subject" yaml:"subject"`

	// Audiences are the accepted audience values.
	Audiences []string `json:"audiences,omitempty" yaml:"audiences,omitempty"`

	// RoleAssignments specifies Azure RBAC roles to assign.
	RoleAssignments []AzureRoleAssignment `json:"role_assignments,omitempty" yaml:"role_assignments,omitempty"`

	// Source identifies the external identity provider.
	Source Cloud `json:"source" yaml:"source"`
}

// AzureRoleAssignment specifies an Azure RBAC role assignment.
type AzureRoleAssignment struct {
	// RoleDefinitionID is the role definition ID or built-in role name.
	RoleDefinitionID string `json:"role_definition_id" yaml:"role_definition_id"`

	// Scope is the scope of the role assignment.
	Scope string `json:"scope" yaml:"scope"`
}

// Type implements MechanismSpec.
func (s *AzureFederatedCredentialSpec) Type() MechanismType {
	return MechanismAzureFederatedCredential
}

// Validate implements MechanismSpec.
func (s *AzureFederatedCredentialSpec) Validate() error {
	if s.TenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}
	if err := ValidateAzureTenant(s.TenantID); err != nil {
		return err
	}
	if s.Issuer == "" {
		return fmt.Errorf("issuer is required")
	}
	if err := ValidateURL(s.Issuer); err != nil {
		return fmt.Errorf("issuer: %w", err)
	}
	if s.Subject == "" {
		return fmt.Errorf("subject is required")
	}
	if s.FederatedCredentialName == "" {
		return fmt.Errorf("federated_credential_name is required")
	}

	switch s.IdentityType {
	case "app_registration":
		if s.ApplicationID == "" && s.ApplicationDisplayName == "" {
			return fmt.Errorf("application_id or application_display_name is required for app_registration")
		}
		if s.ApplicationID != "" {
			if err := ValidateAzureUUID(s.ApplicationID); err != nil {
				return fmt.Errorf("application_id %w", err)
			}
		}
	case "managed_identity":
		if s.ManagedIdentityName == "" {
			return fmt.Errorf("managed_identity_name is required for managed_identity type")
		}
		if s.ResourceGroup == "" {
			return fmt.Errorf("resource_group is required for managed_identity type")
		}
		if s.SubscriptionID == "" {
			return fmt.Errorf("subscription_id is required for managed_identity type")
		}
		if err := ValidateAzureUUID(s.SubscriptionID); err != nil {
			return fmt.Errorf("subscription_id %w", err)
		}
	default:
		return fmt.Errorf("identity_type must be 'app_registration' or 'managed_identity'")
	}

	return nil
}

// SourceProvider implements MechanismSpec.
func (s *AzureFederatedCredentialSpec) SourceProvider() Cloud {
	return s.Source
}

// TargetProvider implements MechanismSpec.
func (s *AzureFederatedCredentialSpec) TargetProvider() Cloud {
	return Azure
}

// K8sServiceAccountFederationSpec specifies a Kubernetes ServiceAccount federation.
// This maps a K8s ServiceAccount to a cloud identity for workload identity.
type K8sServiceAccountFederationSpec struct {
	// ClusterName is a friendly name for the Kubernetes cluster.
	ClusterName string `json:"cluster_name" yaml:"cluster_name"`

	// Namespace is the Kubernetes namespace for the ServiceAccount.
	Namespace string `json:"namespace" yaml:"namespace"`

	// ServiceAccountName is the Kubernetes ServiceAccount name.
	ServiceAccountName string `json:"service_account_name" yaml:"service_account_name"`

	// CreateServiceAccount if true, creates the K8s ServiceAccount.
	CreateServiceAccount bool `json:"create_service_account,omitempty" yaml:"create_service_account,omitempty"`

	// OIDCIssuerURL is the cluster's OIDC issuer URL.
	OIDCIssuerURL string `json:"oidc_issuer_url" yaml:"oidc_issuer_url"`

	// TargetCloud specifies which cloud provider to federate with.
	TargetCloud Cloud `json:"target_cloud" yaml:"target_cloud"`

	// AWSConfig is required when TargetCloud is "aws".
	AWSConfig *K8sToAWSConfig `json:"aws_config,omitempty" yaml:"aws_config,omitempty"`

	// GCPConfig is required when TargetCloud is "gcp".
	GCPConfig *K8sToGCPConfig `json:"gcp_config,omitempty" yaml:"gcp_config,omitempty"`

	// AzureConfig is required when TargetCloud is "azure".
	AzureConfig *K8sToAzureConfig `json:"azure_config,omitempty" yaml:"azure_config,omitempty"`
}

// K8sToAWSConfig contains AWS-specific configuration for K8s federation.
type K8sToAWSConfig struct {
	RoleName   string            `json:"role_name" yaml:"role_name"`
	AccountID  string            `json:"account_id" yaml:"account_id"`
	PolicyARNs []string          `json:"policy_arns,omitempty" yaml:"policy_arns,omitempty"`
	Tags       map[string]string `json:"tags,omitempty" yaml:"tags,omitempty"`
}

// K8sToGCPConfig contains GCP-specific configuration for K8s federation.
type K8sToGCPConfig struct {
	ProjectID           string   `json:"project_id" yaml:"project_id"`
	ProjectNumber       string   `json:"project_number" yaml:"project_number"`
	ServiceAccountEmail string   `json:"service_account_email" yaml:"service_account_email"`
	Roles               []string `json:"roles,omitempty" yaml:"roles,omitempty"`
}

// K8sToAzureConfig contains Azure-specific configuration for K8s federation.
type K8sToAzureConfig struct {
	TenantID        string                `json:"tenant_id" yaml:"tenant_id"`
	SubscriptionID  string                `json:"subscription_id" yaml:"subscription_id"`
	IdentityType    string                `json:"identity_type" yaml:"identity_type"`
	ApplicationID   string                `json:"application_id,omitempty" yaml:"application_id,omitempty"`
	RoleAssignments []AzureRoleAssignment `json:"role_assignments,omitempty" yaml:"role_assignments,omitempty"`
}

// Type implements MechanismSpec.
func (s *K8sServiceAccountFederationSpec) Type() MechanismType {
	return MechanismK8sServiceAccountFederation
}

// Validate implements MechanismSpec.
func (s *K8sServiceAccountFederationSpec) Validate() error {
	if s.Namespace == "" {
		return fmt.Errorf("namespace is required")
	}
	if s.ServiceAccountName == "" {
		return fmt.Errorf("service_account_name is required")
	}
	if s.OIDCIssuerURL == "" {
		return fmt.Errorf("oidc_issuer_url is required")
	}
	if err := ValidateURL(s.OIDCIssuerURL); err != nil {
		return fmt.Errorf("oidc_issuer_url: %w", err)
	}

	switch s.TargetCloud {
	case AWS:
		if s.AWSConfig == nil {
			return fmt.Errorf("aws_config is required when target_cloud is 'aws'")
		}
		if s.AWSConfig.RoleName == "" || s.AWSConfig.AccountID == "" {
			return fmt.Errorf("aws_config.role_name and account_id are required")
		}
		if err := ValidateAWSAccountID(s.AWSConfig.AccountID); err != nil {
			return fmt.Errorf("aws_config.account_id: %w", err)
		}
	case GCP:
		if s.GCPConfig == nil {
			return fmt.Errorf("gcp_config is required when target_cloud is 'gcp'")
		}
		if s.GCPConfig.ProjectID == "" || s.GCPConfig.ServiceAccountEmail == "" {
			return fmt.Errorf("gcp_config.project_id and service_account_email are required")
		}
		if err := ValidateGCPProjectID(s.GCPConfig.ProjectID); err != nil {
			return fmt.Errorf("gcp_config.project_id: %w", err)
		}
		if err := ValidateGCPServiceAccountEmail(s.GCPConfig.ServiceAccountEmail); err != nil {
			return fmt.Errorf("gcp_config.service_account_email: %w", err)
		}
	case Azure:
		if s.AzureConfig == nil {
			return fmt.Errorf("azure_config is required when target_cloud is 'azure'")
		}
		if s.AzureConfig.TenantID == "" {
			return fmt.Errorf("azure_config.tenant_id is required")
		}
		if err := ValidateAzureTenant(s.AzureConfig.TenantID); err != nil {
			return fmt.Errorf("azure_config.tenant_id: %w", err)
		}
	default:
		return fmt.Errorf("target_cloud must be 'aws', 'gcp', or 'azure'")
	}

	return nil
}

// SourceProvider implements MechanismSpec.
func (s *K8sServiceAccountFederationSpec) SourceProvider() Cloud {
	return Kubernetes
}

// TargetProvider implements MechanismSpec.
func (s *K8sServiceAccountFederationSpec) TargetProvider() Cloud {
	return s.TargetCloud
}

// Helper functions for identity validation

var (
	awsAccountIDRegex = regexp.MustCompile(`^\d{12}$`)
	// Every AWS partition, not just the commercial one: aws-us-gov and aws-cn
	// role ARNs were rejected outright.
	awsARNRegex       = regexp.MustCompile(`^arn:aws[a-z0-9-]*:iam::\d{12}:role\/[a-zA-Z_0-9+=,.@\-_/]+$`)
	gcpProjectIDRegex = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	gcpSAEmailRegex   = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.iam\.gserviceaccount\.com$`)
	azureUUIDRegex    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

	// azureTenantRegex accepts the two forms Entra uses for a specific tenant: a
	// GUID, or a verified domain.
	azureTenantRegex = regexp.MustCompile(
		`^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}` +
			`|[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+)$`)
)

// ValidateAWSAccountID validates an AWS account ID format.
func ValidateAWSAccountID(id string) error {
	if !awsAccountIDRegex.MatchString(id) {
		return fmt.Errorf("invalid AWS account ID format: %s", id)
	}
	return nil
}

// ValidateAWSRoleARN validates an AWS IAM role ARN format.
func ValidateAWSRoleARN(arn string) error {
	if !awsARNRegex.MatchString(arn) {
		return fmt.Errorf("invalid AWS role ARN format: %s", arn)
	}
	return nil
}

// ValidateGCPProjectID validates a GCP project ID format.
func ValidateGCPProjectID(id string) error {
	if !gcpProjectIDRegex.MatchString(id) {
		return fmt.Errorf("invalid GCP project ID format: %s", id)
	}
	return nil
}

// ValidateGCPServiceAccountEmail validates a GCP service account email format.
func ValidateGCPServiceAccountEmail(email string) error {
	if !gcpSAEmailRegex.MatchString(email) {
		return fmt.Errorf("invalid GCP service account email format: %s", email)
	}
	return nil
}

// ValidateAzureUUID validates an Azure UUID format.
func ValidateAzureUUID(id string) error {
	if !azureUUIDRegex.MatchString(id) {
		return fmt.Errorf("invalid Azure UUID format: %s", id)
	}
	return nil
}

// ValidateURL validates that a string is a valid HTTPS URL.
//
// HTTPS is not stylistic here: an http:// OIDC issuer cannot have its
// certificate chain pinned, so AWS cannot bind the provider to a known CA and
// the tokens it mints cannot be trusted to come from it.
func ValidateURL(urlStr string) error {
	u, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("not a URL: %s", urlStr)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("URL must use HTTPS (an http issuer cannot be pinned to a "+
			"certificate chain, so its tokens cannot be trusted): %s", urlStr)
	}
	if u.Host == "" {
		return fmt.Errorf("URL has no host: %s", urlStr)
	}
	return nil
}

// ValidateAzureTenant rejects anything that is not one concrete Entra tenant.
//
// The multi-tenant aliases are refused explicitly: for a federated
// client-credentials grant an alias means "whichever tenant the assertion
// resolves to", and since the default assertion audience is not tenant-bound,
// that delegates the choice of who receives a usable proof of this workload's
// identity.
func ValidateAzureTenant(tenant string) error {
	switch strings.ToLower(strings.TrimSpace(tenant)) {
	case "common", "organizations", "consumers":
		return fmt.Errorf("tenant %q is a multi-tenant alias; name one specific tenant "+
			"(a GUID or a verified domain)", tenant)
	}
	if !azureTenantRegex.MatchString(tenant) {
		return fmt.Errorf("tenant %q is not a GUID or a verified domain name", tenant)
	}
	return nil
}
