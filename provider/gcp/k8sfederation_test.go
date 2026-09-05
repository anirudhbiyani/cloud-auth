package gcp

import (
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// k8s-federation reached "unsupported spec type" on GCP until this landed: only provider/aws handled the spec.

func k8sSpec(mutate func(*core.K8sServiceAccountFederationSpec)) *core.K8sServiceAccountFederationSpec {
	s := &core.K8sServiceAccountFederationSpec{
		ClusterName:        "prod-gke",
		Namespace:          "payments",
		ServiceAccountName: "ledger",
		OIDCIssuerURL:      "https://container.googleapis.com/v1/projects/p/locations/us/clusters/c",
		TargetCloud:        core.GCP,
		GCPConfig: &core.K8sToGCPConfig{
			ProjectID:           "my-project",
			ProjectNumber:       "123456789012",
			ServiceAccountEmail: "ledger@my-project.iam.gserviceaccount.com",
			Roles:               []string{"roles/storage.objectViewer"},
		},
	}
	if mutate != nil {
		mutate(s)
	}
	return s
}

func TestK8sToWorkloadIdentitySpec(t *testing.T) {
	got, err := k8sToWorkloadIdentitySpec(k8sSpec(nil))
	if err != nil {
		t.Fatalf("translate: %v", err)
	}

	const wantSubject = "system:serviceaccount:payments:ledger"
	if got.SubjectScope != wantSubject {
		t.Errorf("SubjectScope = %q, want %q", got.SubjectScope, wantSubject)
	}
	// Without an attribute condition the provider accepts every identity the cluster's issuer will mint a token for — a confused-deputy hole, and the exact thing core refuses to create.
	if !strings.Contains(got.AttributeCondition, wantSubject) {
		t.Errorf("AttributeCondition = %q, want it to pin %q", got.AttributeCondition, wantSubject)
	}
	if got.ProviderType != "oidc" {
		t.Errorf("ProviderType = %q, want oidc", got.ProviderType)
	}
	if got.AttributeMapping["google.subject"] != "assertion.sub" {
		t.Errorf("google.subject mapping = %q", got.AttributeMapping["google.subject"])
	}
	if got.ServiceAccountEmail != "ledger@my-project.iam.gserviceaccount.com" {
		t.Errorf("ServiceAccountEmail = %q", got.ServiceAccountEmail)
	}
	if len(got.ServiceAccountRoles) != 1 {
		t.Errorf("roles not carried through: %v", got.ServiceAccountRoles)
	}
	if got.Source != core.Kubernetes {
		t.Errorf("Source = %q", got.Source)
	}

	// The translated spec must satisfy the same validation a hand-written one does, or setup refuses it one layer down.
	if err := got.Validate(); err != nil {
		t.Errorf("translated spec fails GCPWorkloadIdentityPoolSpec.Validate: %v", err)
	}
}

// Re-running setup must reuse the pool, not create another — and GCP soft-deletes pools, reserving the id for 30 days, so an unstable id is a name nobody can reuse for a month.
func TestK8sPoolIDIsStableAndLegal(t *testing.T) {
	a, _ := k8sToWorkloadIdentitySpec(k8sSpec(nil))
	b, _ := k8sToWorkloadIdentitySpec(k8sSpec(nil))
	if a.PoolID != b.PoolID {
		t.Errorf("pool id is not stable: %q vs %q", a.PoolID, b.PoolID)
	}

	for _, tc := range []struct {
		name string
		spec *core.K8sServiceAccountFederationSpec
	}{
		{"short names hit the 4-character floor", k8sSpec(func(s *core.K8sServiceAccountFederationSpec) {
			s.ClusterName, s.Namespace, s.ServiceAccountName = "c", "ci", "a"
		})},
		{"long names hit the 32-character ceiling", k8sSpec(func(s *core.K8sServiceAccountFederationSpec) {
			s.ClusterName = strings.Repeat("very-long-cluster-name", 4)
			s.Namespace = strings.Repeat("namespace", 5)
		})},
		{"illegal characters are replaced", k8sSpec(func(s *core.K8sServiceAccountFederationSpec) {
			s.ClusterName, s.Namespace = "Prod_Cluster.01", "Team/Payments"
		})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := k8sToWorkloadIdentitySpec(tc.spec)
			if err != nil {
				t.Fatalf("translate: %v", err)
			}
			for _, id := range []string{got.PoolID, got.ProviderID} {
				if len(id) < 4 || len(id) > 32 {
					t.Errorf("id %q is %d characters; GCP requires 4-32", id, len(id))
				}
				for _, r := range id {
					legal := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-'
					if !legal {
						t.Errorf("id %q contains an illegal character %q", id, r)
						break
					}
				}
				if strings.HasPrefix(id, "-") || strings.HasSuffix(id, "-") {
					t.Errorf("id %q starts or ends with a hyphen", id)
				}
			}
		})
	}
}

func TestK8sToWorkloadIdentitySpecRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		spec   *core.K8sServiceAccountFederationSpec
		errHas string
	}{
		{"create_service_account has nothing behind it",
			k8sSpec(func(s *core.K8sServiceAccountFederationSpec) { s.CreateServiceAccount = true }),
			"never talks to your cluster"},
		{"wildcard namespace",
			k8sSpec(func(s *core.K8sServiceAccountFederationSpec) { s.Namespace = "*" }), "must be exact"},
		{"another cloud's target",
			k8sSpec(func(s *core.K8sServiceAccountFederationSpec) { s.TargetCloud = core.AWS }), "not gcp"},
		{"missing gcp_config",
			k8sSpec(func(s *core.K8sServiceAccountFederationSpec) { s.GCPConfig = nil }), "gcp_config is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := k8sToWorkloadIdentitySpec(tc.spec); err == nil {
				t.Fatalf("want an error, got spec %+v", got)
			} else if !strings.Contains(err.Error(), tc.errHas) {
				t.Errorf("error = %q, want it to contain %q", err, tc.errHas)
			}
		})
	}
}

func TestProviderAcceptsK8sFederationSpec(t *testing.T) {
	_, err := New().Setup(t.Context(), k8sSpec(nil), core.SetupOptions{DryRun: true})
	if err != nil && strings.Contains(err.Error(), "unsupported spec type") {
		t.Fatalf("provider still rejects the spec type: %v", err)
	}
}
