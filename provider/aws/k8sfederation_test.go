package aws

import (
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// k8s-federation shipped a complete CLI surface, spec type, help text, YAML
// loader and two example files, and no provider handled the spec — every
// invocation died on "unsupported spec type", --dry-run included. The subject is
// the part worth pinning: it is what decides which workload can assume the role.

func k8sSpec(mutate func(*core.K8sServiceAccountFederationSpec)) *core.K8sServiceAccountFederationSpec {
	s := &core.K8sServiceAccountFederationSpec{
		ClusterName:        "prod-eks",
		Namespace:          "payments",
		ServiceAccountName: "ledger",
		OIDCIssuerURL:      "https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E",
		TargetCloud:        core.AWS,
		AWSConfig: &core.K8sToAWSConfig{
			RoleName:   "ledger-role",
			AccountID:  "123456789012",
			PolicyARNs: []string{"arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"},
			Tags:       map[string]string{"team": "payments"},
		},
	}
	if mutate != nil {
		mutate(s)
	}
	return s
}

func TestK8sToRoleTrustSpecMapsTheSubject(t *testing.T) {
	got, err := k8sToRoleTrustSpec(k8sSpec(nil))
	if err != nil {
		t.Fatalf("translate: %v", err)
	}

	// The projected ServiceAccount token's sub claim, exactly.
	if want := "system:serviceaccount:payments:ledger"; got.Subject != want {
		t.Errorf("Subject = %q, want %q", got.Subject, want)
	}
	// Exact match, not StringLike: the subject is fully known, so a pattern
	// operator could only accept more than was asked for.
	if got.SubjectCondition != "StringEquals" {
		t.Errorf("SubjectCondition = %q, want StringEquals", got.SubjectCondition)
	}
	if got.OIDCProviderURL != "https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E" {
		t.Errorf("OIDCProviderURL = %q", got.OIDCProviderURL)
	}
	if got.Audience != core.DefaultAWSAudience {
		t.Errorf("Audience = %q, want %q", got.Audience, core.DefaultAWSAudience)
	}
	if got.RoleName != "ledger-role" || got.AccountID != "123456789012" {
		t.Errorf("role = %q account = %q", got.RoleName, got.AccountID)
	}
	if len(got.PolicyARNs) != 1 || got.Tags["team"] != "payments" {
		t.Errorf("policies/tags not carried through: %+v / %+v", got.PolicyARNs, got.Tags)
	}
	if got.Source != core.Kubernetes {
		t.Errorf("Source = %q, want kubernetes", got.Source)
	}
	if !strings.Contains(got.Description, "prod-eks") {
		t.Errorf("Description = %q, want the cluster named", got.Description)
	}

	// The translated spec must satisfy the same validation a hand-written role
	// trust spec does, or setup would refuse it one layer down.
	if err := got.Validate(); err != nil {
		t.Errorf("translated spec fails AWSRoleTrustOIDCSpec.Validate: %v", err)
	}
}

func TestK8sToRoleTrustSpecRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		spec   *core.K8sServiceAccountFederationSpec
		errHas string
	}{
		{
			name:   "create_service_account has nothing behind it",
			spec:   k8sSpec(func(s *core.K8sServiceAccountFederationSpec) { s.CreateServiceAccount = true }),
			errHas: "never talks to your cluster",
		},
		{
			name:   "wildcard namespace would widen the trust",
			spec:   k8sSpec(func(s *core.K8sServiceAccountFederationSpec) { s.Namespace = "*" }),
			errHas: "must be exact",
		},
		{
			name:   "wildcard service account would widen the trust",
			spec:   k8sSpec(func(s *core.K8sServiceAccountFederationSpec) { s.ServiceAccountName = "app-?" }),
			errHas: "must be exact",
		},
		{
			name:   "another cloud's target must not build an AWS role",
			spec:   k8sSpec(func(s *core.K8sServiceAccountFederationSpec) { s.TargetCloud = core.GCP }),
			errHas: "not aws",
		},
		{
			name:   "missing aws_config",
			spec:   k8sSpec(func(s *core.K8sServiceAccountFederationSpec) { s.AWSConfig = nil }),
			errHas: "aws_config is required",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := k8sToRoleTrustSpec(tc.spec)
			if err == nil {
				t.Fatalf("want an error, got spec %+v", got)
			}
			if !strings.Contains(err.Error(), tc.errHas) {
				t.Errorf("error = %q, want it to contain %q", err, tc.errHas)
			}
		})
	}
}

// The provider must accept the spec type at all — this is the exact failure that
// made every `setup --type k8s-federation` unusable.
func TestProviderAcceptsK8sFederationSpec(t *testing.T) {
	p := New()
	_, err := p.Setup(t.Context(), k8sSpec(nil), core.SetupOptions{DryRun: true})
	if err != nil && strings.Contains(err.Error(), "unsupported spec type") {
		t.Fatalf("provider still rejects the spec type: %v", err)
	}
}
