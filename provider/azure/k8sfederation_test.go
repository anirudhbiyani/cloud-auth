package azure

import (
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// k8s-federation reached "unsupported spec type" on Azure until this landed.
// Azure matches the subject literally, so the subject is the whole game: get it
// wrong and the credential is created successfully and never matches a token.

func k8sSpec(mutate func(*core.K8sServiceAccountFederationSpec)) *core.K8sServiceAccountFederationSpec {
	s := &core.K8sServiceAccountFederationSpec{
		ClusterName:        "prod-aks",
		Namespace:          "payments",
		ServiceAccountName: "ledger",
		OIDCIssuerURL:      "https://oidc.prod-aks.azure.com/00000000-0000-0000-0000-000000000000/",
		TargetCloud:        core.Azure,
		AzureConfig: &core.K8sToAzureConfig{
			TenantID:       "11111111-1111-1111-1111-111111111111",
			SubscriptionID: "22222222-2222-2222-2222-222222222222",
			ApplicationID:  "33333333-3333-3333-3333-333333333333",
		},
	}
	if mutate != nil {
		mutate(s)
	}
	return s
}

func TestK8sToFederatedCredentialSpec(t *testing.T) {
	got, err := k8sToFederatedCredentialSpec(k8sSpec(nil))
	if err != nil {
		t.Fatalf("translate: %v", err)
	}

	if want := "system:serviceaccount:payments:ledger"; got.Subject != want {
		t.Errorf("Subject = %q, want %q", got.Subject, want)
	}
	if got.Issuer != "https://oidc.prod-aks.azure.com/00000000-0000-0000-0000-000000000000/" {
		t.Errorf("Issuer = %q", got.Issuer)
	}
	if len(got.Audiences) != 1 || got.Audiences[0] != core.DefaultAzureAudience {
		t.Errorf("Audiences = %v, want exactly [%s]", got.Audiences, core.DefaultAzureAudience)
	}
	if got.IdentityType != "app_registration" {
		t.Errorf("IdentityType = %q, want app_registration", got.IdentityType)
	}
	if got.FederatedCredentialName == "" {
		t.Error("no credential name was derived")
	}
	if err := got.Validate(); err != nil {
		t.Errorf("translated spec fails AzureFederatedCredentialSpec.Validate: %v", err)
	}
}

// The credential name must be stable and Azure-legal: re-running setup for one
// ServiceAccount has to target the same credential rather than consuming
// another of the twenty slots.
func TestK8sCredentialNameIsStableAndLegal(t *testing.T) {
	a, _ := k8sToFederatedCredentialSpec(k8sSpec(nil))
	b, _ := k8sToFederatedCredentialSpec(k8sSpec(nil))
	if a.FederatedCredentialName != b.FederatedCredentialName {
		t.Errorf("credential name is not stable: %q vs %q",
			a.FederatedCredentialName, b.FederatedCredentialName)
	}

	got, err := k8sToFederatedCredentialSpec(k8sSpec(func(s *core.K8sServiceAccountFederationSpec) {
		s.Namespace, s.ServiceAccountName = "Team/Payments", "Ledger_Service.01"
	}))
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	name := got.FederatedCredentialName
	for _, r := range name {
		legal := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-'
		if !legal {
			t.Errorf("credential name %q contains an illegal character %q", name, r)
			break
		}
	}
	if strings.HasPrefix(name, "-") || strings.HasSuffix(name, "-") {
		t.Errorf("credential name %q starts or ends with a hyphen", name)
	}
	// The subject keeps the ORIGINAL casing and characters: it is a Kubernetes
	// claim, not an Azure resource name, and Azure compares it literally.
	if got.Subject != "system:serviceaccount:Team/Payments:Ledger_Service.01" {
		t.Errorf("Subject was sanitized: %q — it must match the token's sub claim exactly", got.Subject)
	}
}

// buildAzureSpec normalizes --identity-type for the azure-federated path, but
// buildK8sSpec passes the raw flag through, so "managed-identity" arrived here
// unrecognised while the same word worked on the other command.
func TestIdentityTypeSpellings(t *testing.T) {
	for _, in := range []string{"app", "app_registration", "app-registration", "APP", ""} {
		t.Run("accepted: "+in, func(t *testing.T) {
			got, err := k8sToFederatedCredentialSpec(k8sSpec(func(s *core.K8sServiceAccountFederationSpec) {
				s.AzureConfig.IdentityType = in
			}))
			if err != nil {
				t.Fatalf("translate: %v", err)
			}
			if got.IdentityType != "app_registration" {
				t.Errorf("IdentityType = %q, want app_registration", got.IdentityType)
			}
		})
	}

	// Managed identity needs a resource group and an identity name, and
	// K8sToAzureConfig has fields for neither — so it is refused here with
	// somewhere to go, rather than failing one layer down on a field this spec
	// type cannot set.
	for _, in := range []string{"managed-identity", "managed_identity", "mi"} {
		t.Run("refused: "+in, func(t *testing.T) {
			_, err := k8sToFederatedCredentialSpec(k8sSpec(func(s *core.K8sServiceAccountFederationSpec) {
				s.AzureConfig.IdentityType = in
			}))
			if err == nil {
				t.Fatal("want a refusal")
			}
			if !strings.Contains(err.Error(), "azure-federated") {
				t.Errorf("the refusal should point somewhere: %v", err)
			}
		})
	}
}

// With no application id, core requires a display name; failing an operator who
// gave a namespace and a ServiceAccount would not be useful.
func TestNoApplicationIDGetsADisplayName(t *testing.T) {
	got, err := k8sToFederatedCredentialSpec(k8sSpec(func(s *core.K8sServiceAccountFederationSpec) {
		s.AzureConfig.ApplicationID = ""
	}))
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if got.ApplicationDisplayName == "" {
		t.Error("neither an application id nor a display name was set")
	}
	if err := got.Validate(); err != nil {
		t.Errorf("spec without an application id fails validation: %v", err)
	}
}

func TestK8sToFederatedCredentialSpecRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		spec   *core.K8sServiceAccountFederationSpec
		errHas string
	}{
		{"create_service_account has nothing behind it",
			k8sSpec(func(s *core.K8sServiceAccountFederationSpec) { s.CreateServiceAccount = true }),
			"never talks to your cluster"},
		{"wildcard service account",
			k8sSpec(func(s *core.K8sServiceAccountFederationSpec) { s.ServiceAccountName = "app-*" }),
			"matches the subject"},
		{"another cloud's target",
			k8sSpec(func(s *core.K8sServiceAccountFederationSpec) { s.TargetCloud = core.GCP }), "not azure"},
		{"missing azure_config",
			k8sSpec(func(s *core.K8sServiceAccountFederationSpec) { s.AzureConfig = nil }), "azure_config is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := k8sToFederatedCredentialSpec(tc.spec); err == nil {
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
