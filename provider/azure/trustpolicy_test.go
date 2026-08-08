package azure

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
)

type stubGraph struct {
	GraphClient
	cred *FederatedIdentityCredential
	err  error
}

func (s *stubGraph) GetFederatedIdentityCredential(context.Context, string, string) (*FederatedIdentityCredential, error) {
	return s.cred, s.err
}

type stubARM struct {
	ARMClient
	cred        *FederatedIdentityCredential
	credErr     error
	assignments []*RoleAssignment
	assignErr   error
}

func (s *stubARM) GetManagedIdentityFederatedCredential(context.Context, string, string, string, string) (*FederatedIdentityCredential, error) {
	return s.cred, s.credErr
}
func (s *stubARM) ListRoleAssignments(context.Context, string, string) ([]*RoleAssignment, error) {
	return s.assignments, s.assignErr
}

const (
	issuer  = "https://oidc.eks.us-east-1.amazonaws.com/id/ABC"
	subject = "system:serviceaccount:cloud-auth-test:verifier"
	aud     = "api://AzureADTokenExchange"
)

func appRef() cloudauth.MechanismRef {
	return cloudauth.MechanismRef{
		ID: "m", Type: cloudauth.MechanismAzureFederatedCredential,
		ResourceIDs: map[string]string{
			"app_object_id":           "app-1",
			"federated_credential_id": "fic-1",
			"service_principal_id":    "sp-1",
			"subscription_id":         "sub-1",
		},
	}
}

func uamiRef() cloudauth.MechanismRef {
	return cloudauth.MechanismRef{
		ID: "m", Type: cloudauth.MechanismAzureFederatedCredential,
		ResourceIDs: map[string]string{
			"identity_name":             "uami-1",
			"resource_group":            "rg-1",
			"subscription_id":           "sub-1",
			"federated_credential_name": "fic-1",
		},
	}
}

func TestAzureTrustPolicyFromAppFIC(t *testing.T) {
	p := &Provider{graphClient: &stubGraph{cred: &FederatedIdentityCredential{
		Name: "fic-1", Issuer: issuer, Subject: subject, Audiences: []string{aud},
	}}}
	tp, err := p.TrustPolicy(context.Background(), appRef())
	if err != nil {
		t.Fatalf("TrustPolicy: %v", err)
	}
	if tp.Issuer != issuer || len(tp.Subjects) != 1 || tp.Subjects[0] != subject {
		t.Errorf("got issuer=%q subjects=%v", tp.Issuer, tp.Subjects)
	}
	if len(tp.Audiences) != 1 || tp.Audiences[0] != aud {
		t.Errorf("audiences = %v", tp.Audiences)
	}
}

func TestAzureTrustPolicyFromManagedIdentityFIC(t *testing.T) {
	p := &Provider{armClient: &stubARM{cred: &FederatedIdentityCredential{
		Name: "fic-1", Issuer: issuer, Subject: subject, Audiences: []string{aud},
	}}}
	tp, err := p.TrustPolicy(context.Background(), uamiRef())
	if err != nil {
		t.Fatalf("TrustPolicy: %v", err)
	}
	if tp.Issuer != issuer {
		t.Errorf("issuer = %q", tp.Issuer)
	}
}

// Entra matches issuer/subject/audience case-sensitively and exactly. This is
// the most common Azure federation failure and it must be named, not buried in
// a generic mismatch message.
func TestAzureCaseOnlyMismatchIsDiagnosed(t *testing.T) {
	p := &Provider{graphClient: &stubGraph{cred: &FederatedIdentityCredential{
		Issuer:    strings.ToLower(issuer), // ...id/abc instead of ...id/ABC
		Subject:   subject,
		Audiences: []string{aud},
	}}}
	v := cloudauth.NewTrustPolicyMatchValidator(issuer, aud, subject,
		cloudauth.WithTrustPolicySource(p))
	got := v.Validate(context.Background(), appRef())
	if got.Status != cloudauth.CheckStatusFailed {
		t.Fatalf("status = %s, want failed", got.Status)
	}
	if !strings.Contains(strings.ToLower(got.Message), "case") {
		t.Errorf("message %q must call out the case-only difference", got.Message)
	}
}

func TestAzureTrustPolicyErrors(t *testing.T) {
	t.Run("propagates fetch error", func(t *testing.T) {
		p := &Provider{graphClient: &stubGraph{err: errors.New("Forbidden")}}
		if _, err := p.TrustPolicy(context.Background(), appRef()); err == nil {
			t.Error("expected an error")
		}
	})
	t.Run("ref identifying neither an app nor a managed identity", func(t *testing.T) {
		p := &Provider{}
		if _, err := p.TrustPolicy(context.Background(), cloudauth.MechanismRef{ID: "x"}); err == nil {
			t.Error("expected an error when the ref names no federated credential")
		}
	})
}

func TestAzureGrantedPoliciesReturnsRoleDefinitions(t *testing.T) {
	p := &Provider{armClient: &stubARM{assignments: []*RoleAssignment{
		{RoleDefinitionID: "/subscriptions/s/providers/Microsoft.Authorization/roleDefinitions/reader", PrincipalID: "sp-1"},
		{RoleDefinitionID: "/subscriptions/s/providers/Microsoft.Authorization/roleDefinitions/contrib", PrincipalID: "sp-1"},
	}}}
	got, err := p.GrantedPolicies(context.Background(), appRef())
	if err != nil {
		t.Fatalf("GrantedPolicies: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %v, want both role definitions", got)
	}
}

func TestAzureProviderSatisfiesInterfaces(t *testing.T) {
	var _ cloudauth.TrustPolicySource = (*Provider)(nil)
	var _ cloudauth.GrantedPolicySource = (*Provider)(nil)
}
