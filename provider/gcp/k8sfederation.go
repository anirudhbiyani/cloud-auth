package gcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// A Kubernetes ServiceAccount federated to GCP is a workload identity pool with an OIDC provider: the cluster's projected SA token is an OIDC token, its issuer is the cluster's OIDC issuer, and its sub claim is the fixed string system:serviceaccount:<namespace>:<name>.

// k8sSubjectFormat is the sub claim a projected ServiceAccount token carries.
const k8sSubjectFormat = "system:serviceaccount:%s:%s"

// setupK8sFederation maps a Kubernetes ServiceAccount to a GCP service account.
func (p *Provider) setupK8sFederation(ctx context.Context, spec *core.K8sServiceAccountFederationSpec, opts core.SetupOptions) (*core.Outputs, error) {
	translated, err := k8sToWorkloadIdentitySpec(spec)
	if err != nil {
		return nil, err
	}
	return p.setupWorkloadIdentityPool(ctx, translated, opts)
}

// k8sToWorkloadIdentitySpec rewrites a K8s federation spec as the workload identity pool it is.
func k8sToWorkloadIdentitySpec(spec *core.K8sServiceAccountFederationSpec) (*core.GCPWorkloadIdentityPoolSpec, error) {
	if spec.TargetCloud != core.GCP {
		return nil, core.ErrValidation(fmt.Sprintf(
			"target_cloud is %q, not gcp", spec.TargetCloud)).WithProvider(core.GCP)
	}
	if spec.GCPConfig == nil {
		return nil, core.ErrValidation("gcp_config is required when target_cloud is 'gcp'").
			WithProvider(core.GCP)
	}
	if spec.CreateServiceAccount {
		return nil, core.ErrValidation(
			"create_service_account is not supported: cloud-auth configures the GCP side of the "+
				"trust and never talks to your cluster; create the ServiceAccount with kubectl or "+
				"your manifests, then re-run without it").
			WithProvider(core.GCP).
			WithDetail("service_account", fmt.Sprintf("%s/%s", spec.Namespace, spec.ServiceAccountName))
	}
	if strings.ContainsAny(spec.Namespace+spec.ServiceAccountName, "*?") {
		return nil, core.ErrValidation(
			"namespace and service_account_name must be exact: a wildcard would admit every " +
				"ServiceAccount that matches it").WithProvider(core.GCP)
	}

	cfg := spec.GCPConfig
	subject := fmt.Sprintf(k8sSubjectFormat, spec.Namespace, spec.ServiceAccountName)

	// The attribute condition is what stops the provider accepting every identity its issuer will mint a token for.
	condition := fmt.Sprintf("assertion.sub == %q", subject)

	return &core.GCPWorkloadIdentityPoolSpec{
		ProjectID:           cfg.ProjectID,
		ProjectNumber:       cfg.ProjectNumber,
		PoolID:              k8sPoolID(spec),
		PoolDisplayName:     fmt.Sprintf("cloud-auth %s", k8sClusterName(spec)),
		ProviderID:          k8sProviderID(spec),
		ProviderDisplayName: fmt.Sprintf("%s/%s", spec.Namespace, spec.ServiceAccountName),
		ProviderType:        "oidc",
		OIDCIssuerURL:       spec.OIDCIssuerURL,
		// The projected token's aud, which the AKS/EKS/GKE webhooks default to the cluster's API server unless asked otherwise.
		AttributeMapping: map[string]string{
			"google.subject": "assertion.sub",
		},
		AttributeCondition:  condition,
		SubjectScope:        subject,
		ServiceAccountEmail: cfg.ServiceAccountEmail,
		ServiceAccountRoles: cfg.Roles,
		Source:              core.Kubernetes,
	}, nil
}

// k8sPoolID derives a stable pool id, so re-running setup for the same cluster reuses the pool instead of creating another.
func k8sPoolID(spec *core.K8sServiceAccountFederationSpec) string {
	return gcpSafeID("k8s-" + k8sClusterName(spec))
}

// k8sProviderID derives the provider id within the pool.
func k8sProviderID(spec *core.K8sServiceAccountFederationSpec) string {
	return gcpSafeID(fmt.Sprintf("%s-%s", spec.Namespace, spec.ServiceAccountName))
}

func k8sClusterName(spec *core.K8sServiceAccountFederationSpec) string {
	if spec.ClusterName != "" {
		return spec.ClusterName
	}
	return "cluster"
}

// gcpSafeID reduces a name to the 4-32 character lowercase form GCP requires for pool and provider ids.
func gcpSafeID(in string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(in) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	id := strings.Trim(b.String(), "-")
	if len(id) > 32 {
		id = strings.Trim(id[:32], "-")
	}
	// The floor is real: GCP rejects an id under 4 characters, and a namespace like "ci" would otherwise produce one.
	for len(id) < 4 {
		id += "-x"
	}
	return id
}
