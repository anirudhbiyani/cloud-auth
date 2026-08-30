package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// A Kubernetes ServiceAccount federated to AWS *is* an OIDC role trust. The
// cluster's projected SA token is an OIDC token, its issuer is the cluster's
// OIDC issuer, and its sub claim is the fixed string
// system:serviceaccount:<namespace>:<name>. There is no second mechanism here —
// only a friendlier way to describe the same IAM role.
//
// So this file translates and delegates rather than reimplementing. The Outputs
// and the MechanismRef it produces are an AWSRoleTrustOIDC, deliberately: that
// is what was created in the account, and it means `validate` and `delete`
// work on the result without either of them learning a second spec type.

// k8sSubjectFormat is the sub claim a Kubernetes projected ServiceAccount token
// carries. It is exact, never a pattern — one ServiceAccount, one subject.
const k8sSubjectFormat = "system:serviceaccount:%s:%s"

// setupK8sFederation maps a Kubernetes ServiceAccount to an IAM role.
func (p *Provider) setupK8sFederation(ctx context.Context, spec *core.K8sServiceAccountFederationSpec, opts core.SetupOptions) (*core.Outputs, error) {
	translated, err := k8sToRoleTrustSpec(spec)
	if err != nil {
		return nil, err
	}
	return p.setupRoleTrustOIDC(ctx, translated, opts)
}

// k8sToRoleTrustSpec rewrites a K8s federation spec as the AWS role trust it is.
//
// Kept separate from setupK8sFederation so the translation is testable without
// an IAM client: the mapping — and especially the subject — is the part worth
// pinning down.
func k8sToRoleTrustSpec(spec *core.K8sServiceAccountFederationSpec) (*core.AWSRoleTrustOIDCSpec, error) {
	if spec.TargetCloud != core.AWS {
		// Unreachable through the manager, which routes on TargetProvider(), but
		// this function is exported to the package and should not silently build
		// an AWS role for a spec that asked for another cloud.
		return nil, core.ErrValidation(fmt.Sprintf(
			"target_cloud is %q, not aws", spec.TargetCloud)).WithProvider(core.AWS)
	}
	if spec.AWSConfig == nil {
		return nil, core.ErrValidation("aws_config is required when target_cloud is 'aws'").
			WithProvider(core.AWS)
	}
	if spec.CreateServiceAccount {
		// Refuse rather than ignore. Creating the ServiceAccount needs a
		// Kubernetes API client and cluster credentials, which cloud-auth does
		// not have and does not ask for — and a spec that says "create it" while
		// nothing creates it is the same class of lie this whole pass is fixing.
		return nil, core.ErrValidation(
			"create_service_account is not supported: cloud-auth configures the AWS side of the "+
				"trust and never talks to your cluster; create the ServiceAccount with kubectl or "+
				"your manifests, then re-run without it").
			WithProvider(core.AWS).
			WithDetail("service_account", fmt.Sprintf("%s/%s", spec.Namespace, spec.ServiceAccountName))
	}
	if strings.ContainsAny(spec.Namespace+spec.ServiceAccountName, "*?") {
		// A wildcard here would widen the trust to every ServiceAccount matching
		// it. If that is ever wanted it should be asked for on the role trust
		// spec, where the unscoped-subject justification machinery lives.
		return nil, core.ErrValidation(
			"namespace and service_account_name must be exact: a wildcard would admit every " +
				"ServiceAccount that matches it").WithProvider(core.AWS)
	}

	cfg := spec.AWSConfig
	return &core.AWSRoleTrustOIDCSpec{
		RoleName:        cfg.RoleName,
		AccountID:       cfg.AccountID,
		OIDCProviderURL: spec.OIDCIssuerURL,
		Audience:        core.DefaultAWSAudience,
		Subject:         fmt.Sprintf(k8sSubjectFormat, spec.Namespace, spec.ServiceAccountName),
		// Exact, not StringLike: the subject is fully known, so there is nothing
		// for a pattern operator to do except accept more than was asked for.
		SubjectCondition: "StringEquals",
		PolicyARNs:       cfg.PolicyARNs,
		Tags:             cfg.Tags,
		Description:      k8sRoleDescription(spec),
		Source:           core.Kubernetes,
	}, nil
}

// k8sRoleDescription records where the trust came from, so the role is
// attributable in the console without consulting cloud-auth's state file.
func k8sRoleDescription(spec *core.K8sServiceAccountFederationSpec) string {
	cluster := spec.ClusterName
	if cluster == "" {
		cluster = "kubernetes"
	}
	return fmt.Sprintf("cloud-auth: %s/%s on %s", spec.Namespace, spec.ServiceAccountName, cluster)
}
