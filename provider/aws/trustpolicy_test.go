package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// stubIAM implements just enough of IAMClient for the trust-policy and
// granted-policy lookups; every other method fails loudly if called.
type stubIAM struct {
	IAMClient
	role         *Role
	roleErr      error
	attached     []string
	attachedErr  error
	inline       []string
	inlineErr    error
	gotRoleNames []string
}

func (s *stubIAM) GetRole(_ context.Context, name string) (*Role, error) {
	s.gotRoleNames = append(s.gotRoleNames, name)
	return s.role, s.roleErr
}
func (s *stubIAM) ListAttachedRolePolicies(context.Context, string) ([]string, error) {
	return s.attached, s.attachedErr
}
func (s *stubIAM) ListRolePolicies(context.Context, string) ([]string, error) {
	return s.inline, s.inlineErr
}

func ref(role string) core.MechanismRef {
	return core.MechanismRef{
		ID:          "test",
		Type:        core.MechanismAWSRoleTrustOIDC,
		ResourceIDs: map[string]string{"role_name": role},
	}
}

const ghPolicy = `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
      "StringLike":   {"token.actions.githubusercontent.com:sub": "repo:myorg/myrepo:*"}
    }
  }]
}`

func TestTrustPolicyParsesLiveRolePolicy(t *testing.T) {
	p := &Provider{client: &stubIAM{role: &Role{RoleName: "r", AssumeRolePolicyDocument: ghPolicy}}}

	tp, err := p.TrustPolicy(context.Background(), ref("r"))
	if err != nil {
		t.Fatalf("TrustPolicy: %v", err)
	}
	// The ARN names the provider; the ISSUER is the https URL a token carries.
	if tp.Issuer != "https://token.actions.githubusercontent.com" {
		t.Errorf("issuer = %q, want the https issuer URL derived from the ARN", tp.Issuer)
	}
	if len(tp.Audiences) != 1 || tp.Audiences[0] != "sts.amazonaws.com" {
		t.Errorf("audiences = %v", tp.Audiences)
	}
	if len(tp.Subjects) != 1 || tp.Subjects[0] != "repo:myorg/myrepo:*" {
		t.Errorf("subjects = %v", tp.Subjects)
	}
	if tp.Raw == "" {
		t.Error("Raw should carry the original document as evidence")
	}
}

func TestTrustPolicyHandlesScalarAndArrayForms(t *testing.T) {
	// IAM accepts a bare string or an array in Principal.Federated and in
	// condition values. Both shapes appear in real policies.
	const arrayForm = `{
      "Statement": [{
        "Effect": "Allow",
        "Principal": {"Federated": ["accounts.google.com"]},
        "Condition": {"StringEquals": {
           "accounts.google.com:oaud": ["sts.amazonaws.com", "other"],
           "accounts.google.com:sub":  "109876543210"
        }}
      }]
    }`
	p := &Provider{client: &stubIAM{role: &Role{AssumeRolePolicyDocument: arrayForm}}}
	tp, err := p.TrustPolicy(context.Background(), ref("r"))
	if err != nil {
		t.Fatalf("TrustPolicy: %v", err)
	}
	if tp.Issuer != "https://accounts.google.com" {
		t.Errorf("issuer = %q", tp.Issuer)
	}
	// :oaud is the audience key for Google (":aud" maps to azp there), so it
	// must be collected too or the audience check would find nothing.
	if len(tp.Audiences) != 2 {
		t.Errorf("audiences = %v, want both entries from the array", tp.Audiences)
	}
	if len(tp.Subjects) != 1 || tp.Subjects[0] != "109876543210" {
		t.Errorf("subjects = %v", tp.Subjects)
	}
}

func TestTrustPolicyErrors(t *testing.T) {
	t.Run("propagates GetRole failure", func(t *testing.T) {
		p := &Provider{client: &stubIAM{roleErr: errors.New("AccessDenied")}}
		if _, err := p.TrustPolicy(context.Background(), ref("r")); err == nil {
			t.Error("expected an error when the role cannot be read")
		}
	})
	t.Run("rejects malformed policy json", func(t *testing.T) {
		p := &Provider{client: &stubIAM{role: &Role{AssumeRolePolicyDocument: "{not json"}}}
		if _, err := p.TrustPolicy(context.Background(), ref("r")); err == nil {
			t.Error("expected an error on unparseable policy")
		}
	})
	t.Run("requires a role name in the ref", func(t *testing.T) {
		p := &Provider{client: &stubIAM{}}
		if _, err := p.TrustPolicy(context.Background(), core.MechanismRef{ID: "x"}); err == nil {
			t.Error("expected an error when the ref carries no role_name")
		}
	})
}

func TestGrantedPoliciesCombinesAttachedAndInline(t *testing.T) {
	p := &Provider{client: &stubIAM{
		attached: []string{"arn:aws:iam::aws:policy/ReadOnlyAccess"},
		inline:   []string{"inline-extra"},
	}}
	got, err := p.GrantedPolicies(context.Background(), ref("r"))
	if err != nil {
		t.Fatalf("GrantedPolicies: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %v, want both the attached ARN and the inline policy", got)
	}
}

// The whole point of the wiring: the core validators must actually run against
// the provider rather than reporting "skipped".
func TestProviderSatisfiesValidationSources(t *testing.T) {
	var _ core.TrustPolicySource = (*Provider)(nil)
	var _ core.GrantedPolicySource = (*Provider)(nil)

	p := &Provider{client: &stubIAM{
		role:     &Role{AssumeRolePolicyDocument: ghPolicy},
		attached: []string{"arn:aws:iam::aws:policy/ReadOnlyAccess"},
	}}
	v := core.NewTrustPolicyMatchValidator(
		"https://token.actions.githubusercontent.com", "sts.amazonaws.com",
		"repo:myorg/myrepo:ref:refs/heads/main",
		core.WithTrustPolicySource(p))
	check := v.Validate(context.Background(), ref("r"))
	if check.Status != core.CheckStatusPassed {
		t.Errorf("trust check = %s, want passed (message=%q)", check.Status, check.Message)
	}

	pv := core.NewPermissionsValidator(
		[]string{"arn:aws:iam::aws:policy/ReadOnlyAccess"},
		core.WithGrantedPolicySource(p))
	if got := pv.Validate(context.Background(), ref("r")); got.Status != core.CheckStatusPassed {
		t.Errorf("permissions check = %s, want passed (message=%q)", got.Status, got.Message)
	}
}

// End-to-end: Provider.Validate must now actually run the trust-policy and
// permission checks, not just "role exists".
func TestValidateRunsTrustAndPermissionChecks(t *testing.T) {
	fullRef := core.MechanismRef{
		ID:   "m1",
		Type: core.MechanismAWSRoleTrustOIDC,
		ResourceIDs: map[string]string{
			"role_name":            "r",
			"expected_issuer":      "https://token.actions.githubusercontent.com",
			"expected_audience":    "sts.amazonaws.com",
			"expected_subject":     "repo:myorg/myrepo:ref:refs/heads/main",
			"expected_policy_arns": "arn:aws:iam::aws:policy/ReadOnlyAccess",
		},
	}

	t.Run("healthy mechanism validates and is complete", func(t *testing.T) {
		p := &Provider{client: &stubIAM{
			role:     &Role{RoleName: "r", AssumeRolePolicyDocument: ghPolicy},
			attached: []string{"arn:aws:iam::aws:policy/ReadOnlyAccess"},
		}}
		rep, err := p.Validate(context.Background(), fullRef, core.ValidateOptions{})
		if err != nil {
			t.Fatalf("Validate: %v", err)
		}
		if !rep.IsValid() {
			t.Errorf("IsValid()=false; failed=%+v", rep.FailedChecks())
		}
		if !rep.IsComplete() {
			t.Errorf("IsComplete()=false; skipped=%+v", rep.SkippedChecks())
		}
	})

	t.Run("widened trust policy is detected", func(t *testing.T) {
		// Someone replaced the scoped subject with a wildcard — the confused
		// deputy hole. Previously this validated clean.
		const widened = `{"Statement":[{"Effect":"Allow",
			"Principal":{"Federated":"arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"},
			"Condition":{"StringEquals":{"x:aud":"sts.amazonaws.com"},"StringLike":{"x:sub":"*"}}}]}`
		p := &Provider{client: &stubIAM{
			role:     &Role{RoleName: "r", AssumeRolePolicyDocument: widened},
			attached: []string{"arn:aws:iam::aws:policy/ReadOnlyAccess"},
		}}
		rep, _ := p.Validate(context.Background(), fullRef, core.ValidateOptions{})
		if rep.IsValid() {
			t.Error("a wide-open subject condition must fail validation")
		}
	})

	t.Run("detached policy is detected", func(t *testing.T) {
		p := &Provider{client: &stubIAM{
			role:     &Role{RoleName: "r", AssumeRolePolicyDocument: ghPolicy},
			attached: nil, // policy was detached out-of-band
		}}
		rep, _ := p.Validate(context.Background(), fullRef, core.ValidateOptions{})
		if rep.IsValid() {
			t.Error("a missing expected policy must fail validation")
		}
	})

	t.Run("legacy ref without expectations degrades to skipped, not failed", func(t *testing.T) {
		legacy := core.MechanismRef{
			ID: "old", Type: core.MechanismAWSRoleTrustOIDC,
			ResourceIDs: map[string]string{"role_name": "r"},
		}
		p := &Provider{client: &stubIAM{role: &Role{RoleName: "r", AssumeRolePolicyDocument: ghPolicy}}}
		rep, err := p.Validate(context.Background(), legacy, core.ValidateOptions{})
		if err != nil {
			t.Fatalf("Validate: %v", err)
		}
		if !rep.IsValid() {
			t.Errorf("a pre-existing mechanism must not fail merely for lacking recorded intent: %+v", rep.FailedChecks())
		}
	})
}
