package gcp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

type stubWIF struct {
	WorkloadIdentityClient
	provider *WorkloadIdentityPoolProvider
	err      error
}

func (s *stubWIF) GetWorkloadIdentityPoolProvider(context.Context, string) (*WorkloadIdentityPoolProvider, error) {
	return s.provider, s.err
}

type stubIAM struct {
	IAMClient
	policy *IAMPolicy
	err    error
}

func (s *stubIAM) GetIAMPolicy(context.Context, string) (*IAMPolicy, error) {
	return s.policy, s.err
}

const (
	providerName = "projects/1/locations/global/workloadIdentityPools/p/providers/eks"
	saEmail      = "sa@proj.iam.gserviceaccount.com"
)

func gcpRef() core.MechanismRef {
	return core.MechanismRef{
		ID:   "m",
		Type: core.MechanismGCPWorkloadIdentityPool,
		ResourceIDs: map[string]string{
			"provider_name":         providerName,
			"service_account_email": saEmail,
		},
	}
}

func TestGCPTrustPolicyFromOIDCProvider(t *testing.T) {
	p := &Provider{wifClient: &stubWIF{provider: &WorkloadIdentityPoolProvider{
		Name:               providerName,
		AttributeCondition: `assertion.sub == "system:serviceaccount:ns:verifier"`,
		OIDC: &OIDCProviderConfig{
			IssuerURI:        "https://oidc.eks.us-east-1.amazonaws.com/id/ABC",
			AllowedAudiences: []string{"//iam.googleapis.com/" + providerName},
		},
	}}}

	tp, err := p.TrustPolicy(context.Background(), gcpRef())
	if err != nil {
		t.Fatalf("TrustPolicy: %v", err)
	}
	if tp.Issuer != "https://oidc.eks.us-east-1.amazonaws.com/id/ABC" {
		t.Errorf("issuer = %q", tp.Issuer)
	}
	if len(tp.Audiences) != 1 {
		t.Errorf("audiences = %v", tp.Audiences)
	}
	// The subject scoping lives in a CEL attribute condition; the literal must be surfaced so the core validator can compare against it.
	if len(tp.Subjects) != 1 || tp.Subjects[0] != "system:serviceaccount:ns:verifier" {
		t.Errorf("subjects = %v, want the literal from the attribute condition", tp.Subjects)
	}
}

// The single most dangerous GCP WIF misconfiguration: a provider with no attribute condition admits EVERY identity from that issuer.
func TestGCPMissingAttributeConditionIsUnscoped(t *testing.T) {
	p := &Provider{wifClient: &stubWIF{provider: &WorkloadIdentityPoolProvider{
		Name: providerName,
		OIDC: &OIDCProviderConfig{IssuerURI: "https://issuer.example"},
	}}}

	tp, err := p.TrustPolicy(context.Background(), gcpRef())
	if err != nil {
		t.Fatalf("TrustPolicy: %v", err)
	}
	if len(tp.Subjects) != 1 || tp.Subjects[0] != "*" {
		t.Fatalf("subjects = %v; an absent attribute condition must surface as the wildcard \"*\"", tp.Subjects)
	}
	// ...and the core validator must therefore fail it outright.
	v := core.NewTrustPolicyMatchValidator("https://issuer.example", "", "anything",
		core.WithTrustPolicySource(p))
	got := v.Validate(context.Background(), gcpRef())
	if got.Status != core.CheckStatusFailed {
		t.Errorf("status = %s, want failed for an unscoped pool provider", got.Status)
	}
	if !strings.Contains(strings.ToLower(got.Message), "unscoped") {
		t.Errorf("message %q should say the trust is unscoped", got.Message)
	}
}

// An empty AllowedAudiences does NOT mean "no audience accepted" — GCP falls back to the provider's own resource name.
func TestGCPDefaultAudienceWhenUnset(t *testing.T) {
	p := &Provider{wifClient: &stubWIF{provider: &WorkloadIdentityPoolProvider{
		Name:               providerName,
		AttributeCondition: `assertion.sub == "x"`,
		OIDC:               &OIDCProviderConfig{IssuerURI: "https://issuer.example"},
	}}}
	tp, err := p.TrustPolicy(context.Background(), gcpRef())
	if err != nil {
		t.Fatalf("TrustPolicy: %v", err)
	}
	want := "//iam.googleapis.com/" + providerName
	found := false
	for _, a := range tp.Audiences {
		if a == want {
			found = true
		}
	}
	if !found {
		t.Errorf("audiences = %v, want the implicit default %q", tp.Audiences, want)
	}
}

func TestGCPAWSTypeProvider(t *testing.T) {
	p := &Provider{wifClient: &stubWIF{provider: &WorkloadIdentityPoolProvider{
		Name:               providerName,
		AttributeCondition: `attribute.aws_role == "arn:aws:sts::123:assumed-role/r"`,
		AWS:                &AWSProviderConfig{AccountID: "123456789012"},
	}}}
	tp, err := p.TrustPolicy(context.Background(), gcpRef())
	if err != nil {
		t.Fatalf("TrustPolicy: %v", err)
	}
	// For an aws-type provider the trusted party is an AWS account, not an OIDC issuer; surface it in a form an operator recognizes.
	if !strings.Contains(tp.Issuer, "123456789012") {
		t.Errorf("issuer = %q, want it to name the trusted AWS account", tp.Issuer)
	}
}

func TestGCPTrustPolicyErrors(t *testing.T) {
	t.Run("propagates fetch error", func(t *testing.T) {
		p := &Provider{wifClient: &stubWIF{err: errors.New("permission denied")}}
		if _, err := p.TrustPolicy(context.Background(), gcpRef()); err == nil {
			t.Error("expected an error")
		}
	})
	t.Run("requires provider_name", func(t *testing.T) {
		p := &Provider{wifClient: &stubWIF{}}
		if _, err := p.TrustPolicy(context.Background(), core.MechanismRef{ID: "x"}); err == nil {
			t.Error("expected an error without provider_name")
		}
	})
}

func TestGCPGrantedPoliciesReturnsBoundRoles(t *testing.T) {
	p := &Provider{iamClient: &stubIAM{policy: &IAMPolicy{Bindings: []*IAMBinding{
		{Role: "roles/storage.objectViewer", Members: []string{"serviceAccount:" + saEmail}},
		{Role: "roles/iam.workloadIdentityUser", Members: []string{"principalSet://x"}},
	}}}}
	got, err := p.GrantedPolicies(context.Background(), gcpRef())
	if err != nil {
		t.Fatalf("GrantedPolicies: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %v, want both bound roles", got)
	}
}

func TestGCPProviderSatisfiesInterfaces(t *testing.T) {
	var _ core.TrustPolicySource = (*Provider)(nil)
	var _ core.GrantedPolicySource = (*Provider)(nil)
}
