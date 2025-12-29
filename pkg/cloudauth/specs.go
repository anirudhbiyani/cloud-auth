package cloudauth

import (
	"fmt"
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

	// SourceProvider identifies the OIDC provider type.
	Source CloudProvider `json:"source" yaml:"source"`
}

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
	if s.OIDCProviderARN == "" && s.OIDCProviderURL == "" {
		return fmt.Errorf("either oidc_provider_arn or oidc_provider_url must be specified")
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
	return nil
}

// SourceProvider implements MechanismSpec.
func (s *AWSRoleTrustOIDCSpec) SourceProvider() CloudProvider {
	return s.Source
}

// TargetProvider implements MechanismSpec.
func (s *AWSRoleTrustOIDCSpec) TargetProvider() CloudProvider {
	return ProviderAWS
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
	AttributeCondition string `json:"attribute_condition,omitempty" yaml:"attribute_condition,omitempty"`

	// ServiceAccountEmail is the service account to impersonate.
	ServiceAccountEmail string `json:"service_account_email" yaml:"service_account_email"`

	// CreateServiceAccount if true, creates the service account if it doesn't exist.
	CreateServiceAccount bool `json:"create_service_account,omitempty" yaml:"create_service_account,omitempty"`

	// ServiceAccountRoles are IAM roles to grant to the service account.
	ServiceAccountRoles []string `json:"service_account_roles,omitempty" yaml:"service_account_roles,omitempty"`

	// Source identifies the external identity provider.
	Source CloudProvider `json:"source" yaml:"source"`
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

	switch s.ProviderType {
	case "aws":
		if s.AWSAccountID == "" {
			return fmt.Errorf("aws_account_id is required for AWS provider type")
		}
	case "oidc":
		if s.OIDCIssuerURL == "" {
			return fmt.Errorf("oidc_issuer_url is required for OIDC provider type")
		}
	case "saml":
		// SAML-specific validation
	default:
		return fmt.Errorf("provider_type must be 'aws', 'oidc', or 'saml'")
	}

	return nil
}

// SourceProvider implements MechanismSpec.
func (s *GCPWorkloadIdentityPoolSpec) SourceProvider() CloudProvider {
	return s.Source
}

// TargetProvider implements MechanismSpec.
func (s *GCPWorkloadIdentityPoolSpec) TargetProvider() CloudProvider {
	return ProviderGCP
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
	Source CloudProvider `json:"source" yaml:"source"`
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
	if s.Issuer == "" {
		return fmt.Errorf("issuer is required")
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
	default:
		return fmt.Errorf("identity_type must be 'app_registration' or 'managed_identity'")
	}

	return nil
}

// SourceProvider implements MechanismSpec.
func (s *AzureFederatedCredentialSpec) SourceProvider() CloudProvider {
	return s.Source
}

// TargetProvider implements MechanismSpec.
func (s *AzureFederatedCredentialSpec) TargetProvider() CloudProvider {
	return ProviderAzure
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
	TargetCloud CloudProvider `json:"target_cloud" yaml:"target_cloud"`

	// AWSConfig is required when TargetCloud is "aws".
	AWSConfig *K8sToAWSConfig `json:"aws_config,omitempty" yaml:"aws_config,omitempty"`

	// GCPConfig is required when TargetCloud is "gcp".
	GCPConfig *K8sToGCPConfig `json:"gcp_config,omitempty" yaml:"gcp_config,omitempty"`

	// AzureConfig is required when TargetCloud is "azure".
	AzureConfig *K8sToAzureConfig `json:"azure_config,omitempty" yaml:"azure_config,omitempty"`
}

// K8sToAWSConfig contains AWS-specific configuration for K8s federation.
type K8sToAWSConfig struct {
	RoleName    string            `json:"role_name" yaml:"role_name"`
	AccountID   string            `json:"account_id" yaml:"account_id"`
	PolicyARNs  []string          `json:"policy_arns,omitempty" yaml:"policy_arns,omitempty"`
	Tags        map[string]string `json:"tags,omitempty" yaml:"tags,omitempty"`
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

	switch s.TargetCloud {
	case ProviderAWS:
		if s.AWSConfig == nil {
			return fmt.Errorf("aws_config is required when target_cloud is 'aws'")
		}
		if s.AWSConfig.RoleName == "" || s.AWSConfig.AccountID == "" {
			return fmt.Errorf("aws_config.role_name and account_id are required")
		}
	case ProviderGCP:
		if s.GCPConfig == nil {
			return fmt.Errorf("gcp_config is required when target_cloud is 'gcp'")
		}
		if s.GCPConfig.ProjectID == "" || s.GCPConfig.ServiceAccountEmail == "" {
			return fmt.Errorf("gcp_config.project_id and service_account_email are required")
		}
	case ProviderAzure:
		if s.AzureConfig == nil {
			return fmt.Errorf("azure_config is required when target_cloud is 'azure'")
		}
		if s.AzureConfig.TenantID == "" {
			return fmt.Errorf("azure_config.tenant_id is required")
		}
	default:
		return fmt.Errorf("target_cloud must be 'aws', 'gcp', or 'azure'")
	}

	return nil
}

// SourceProvider implements MechanismSpec.
func (s *K8sServiceAccountFederationSpec) SourceProvider() CloudProvider {
	return ProviderKubernetes
}

// TargetProvider implements MechanismSpec.
func (s *K8sServiceAccountFederationSpec) TargetProvider() CloudProvider {
	return s.TargetCloud
}

// Helper functions for identity validation

var (
	awsAccountIDRegex = regexp.MustCompile(`^\d{12}$`)
	awsARNRegex       = regexp.MustCompile(`^arn:aws:iam::\d{12}:role\/[a-zA-Z_0-9+=,.@\-_/]+$`)
	gcpProjectIDRegex = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	gcpSAEmailRegex   = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.iam\.gserviceaccount\.com$`)
	azureUUIDRegex    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
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
func ValidateURL(urlStr string) error {
	if !strings.HasPrefix(urlStr, "https://") {
		return fmt.Errorf("URL must use HTTPS: %s", urlStr)
	}
	return nil
}

