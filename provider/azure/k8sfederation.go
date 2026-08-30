package azure

import (
	"context"
	"fmt"
	"strings"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// A Kubernetes ServiceAccount federated to Azure is a federated identity
// credential: the cluster's projected SA token is an OIDC token, its issuer is
// the cluster's OIDC issuer, and its sub claim is the fixed string
// system:serviceaccount:<namespace>:<name>.
//
// So this translates and delegates to the federated-credential path rather than
// reimplementing it, exactly as provider/aws does. The Outputs and MechanismRef
// are an AzureFederatedCredential, deliberately: that is what exists in the
// tenant afterwards, and it means validate and delete — which branch on
// ref.Type — work on the result without learning a second spec type.

// k8sSubjectFormat is the sub claim a projected ServiceAccount token carries.
// Exact, never a pattern: Azure matches subjects literally.
const k8sSubjectFormat = "system:serviceaccount:%s:%s"

// setupK8sFederation maps a Kubernetes ServiceAccount to an Azure identity.
func (p *Provider) setupK8sFederation(ctx context.Context, spec *core.K8sServiceAccountFederationSpec, opts core.SetupOptions) (*core.Outputs, error) {
	translated, err := k8sToFederatedCredentialSpec(spec)
	if err != nil {
		return nil, err
	}
	return p.setupFederatedCredential(ctx, translated, opts)
}

// k8sToFederatedCredentialSpec rewrites a K8s federation spec as the Azure
// federated identity credential it is.
//
// Separate from the setup call so the mapping — and especially the subject — is
// testable without a Graph client.
func k8sToFederatedCredentialSpec(spec *core.K8sServiceAccountFederationSpec) (*core.AzureFederatedCredentialSpec, error) {
	if spec.TargetCloud != core.Azure {
		return nil, core.ErrValidation(fmt.Sprintf(
			"target_cloud is %q, not azure", spec.TargetCloud)).WithProvider(core.Azure)
	}
	if spec.AzureConfig == nil {
		return nil, core.ErrValidation("azure_config is required when target_cloud is 'azure'").
			WithProvider(core.Azure)
	}
	if spec.CreateServiceAccount {
		return nil, core.ErrValidation(
			"create_service_account is not supported: cloud-auth configures the Azure side of the "+
				"trust and never talks to your cluster; create the ServiceAccount with kubectl or "+
				"your manifests, then re-run without it").
			WithProvider(core.Azure).
			WithDetail("service_account", fmt.Sprintf("%s/%s", spec.Namespace, spec.ServiceAccountName))
	}
	if strings.ContainsAny(spec.Namespace+spec.ServiceAccountName, "*?") {
		// Azure matches subjects literally, so a wildcard here would not widen
		// the trust — it would produce a credential that matches nothing and
		// fails without error. Refusing is the kinder answer either way.
		return nil, core.ErrValidation(
			"namespace and service_account_name must be exact: Azure matches the subject " +
				"literally, so a wildcard would create a credential that never matches a token").
			WithProvider(core.Azure)
	}

	cfg := spec.AzureConfig

	// K8sToAzureConfig carries TenantID, SubscriptionID, IdentityType,
	// ApplicationID and RoleAssignments — and no ResourceGroup or
	// ManagedIdentityName. It is shaped for an app registration, and a managed
	// identity cannot be expressed through it at all: core's own validation
	// requires both of those fields for managed_identity, so translating to one
	// would fail one layer down with a message about a field this spec type has
	// no way to set.
	//
	// So app registration is the default, and asking for a managed identity is
	// refused here with somewhere to go, rather than passed through to become a
	// confusing validation error.
	identityType := normalizeIdentityType(cfg.IdentityType)
	switch identityType {
	case "", "app_registration":
		identityType = "app_registration"
	case "managed_identity":
		return nil, core.ErrValidation(
			"identity_type managed_identity cannot be expressed by a k8s-federation spec: it needs a " +
				"resource group and an identity name, which azure_config has no fields for; use " +
				"`setup --type azure-federated --identity-type managed-identity` instead").
			WithProvider(core.Azure)
	default:
		return nil, core.ErrValidation(fmt.Sprintf(
			"identity_type %q is not recognised; want app_registration", cfg.IdentityType)).
			WithProvider(core.Azure)
	}

	out := &core.AzureFederatedCredentialSpec{
		TenantID:                cfg.TenantID,
		SubscriptionID:          cfg.SubscriptionID,
		IdentityType:            identityType,
		ApplicationID:           cfg.ApplicationID,
		FederatedCredentialName: k8sCredentialName(spec),
		Issuer:                  spec.OIDCIssuerURL,
		Subject:                 fmt.Sprintf(k8sSubjectFormat, spec.Namespace, spec.ServiceAccountName),
		Audiences:               []string{core.DefaultAzureAudience},
		RoleAssignments:         cfg.RoleAssignments,
		Source:                  core.Kubernetes,
	}
	// core requires an id or a display name; with neither, name the app after
	// the workload rather than failing an operator who gave a namespace and a
	// ServiceAccount and reasonably expected that to be enough.
	if out.ApplicationID == "" {
		out.ApplicationDisplayName = fmt.Sprintf("cloud-auth %s %s/%s",
			k8sClusterName(spec), spec.Namespace, spec.ServiceAccountName)
	}
	return out, nil
}

// normalizeIdentityType accepts the CLI's hyphenated spelling and the spec's
// underscored one.
//
// buildAzureSpec normalizes --identity-type for the azure-federated path, but
// buildK8sSpec passes the raw flag value straight into azure_config — so
// "managed-identity" arrived here unrecognised while the same word worked on the
// other command. A spec file can legitimately use either spelling too.
func normalizeIdentityType(in string) string {
	switch strings.ToLower(strings.TrimSpace(in)) {
	case "":
		return ""
	case "app", "app_registration", "app-registration":
		return "app_registration"
	case "mi", "managed_identity", "managed-identity":
		return "managed_identity"
	default:
		return in
	}
}

// k8sClusterName returns the cluster name, or a placeholder.
func k8sClusterName(spec *core.K8sServiceAccountFederationSpec) string {
	if spec.ClusterName != "" {
		return spec.ClusterName
	}
	return "cluster"
}

// k8sCredentialName derives a stable, Azure-legal credential name.
//
// Stable because re-running setup for the same ServiceAccount must target the
// same credential rather than consuming another of the twenty slots.
func k8sCredentialName(spec *core.K8sServiceAccountFederationSpec) string {
	return azureSafeName(fmt.Sprintf("k8s-%s-%s", spec.Namespace, spec.ServiceAccountName))
}

// azureSafeName reduces a name to the characters Azure resource names accept.
func azureSafeName(in string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(in) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	// Azure caps most of these names at 128; well under it in practice, but a
	// namespace and account name are operator-supplied and unbounded.
	name := strings.Trim(b.String(), "-")
	if len(name) > 120 {
		name = strings.Trim(name[:120], "-")
	}
	return name
}
