package aws

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// decode the generated policy into something assertable.
type builtPolicy struct {
	Statement []struct {
		Principal map[string]string            `json:"Principal"`
		Condition map[string]map[string]string `json:"Condition"`
	} `json:"Statement"`
}

func build(t *testing.T, spec *core.AWSRoleTrustOIDCSpec, arn string) builtPolicy {
	t.Helper()
	doc, err := buildTrustPolicy(arn, spec)
	if err != nil {
		t.Fatalf("buildTrustPolicy: %v", err)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var bp builtPolicy
	if err := json.Unmarshal(raw, &bp); err != nil {
		t.Fatalf("unmarshal: %v (%s)", err, raw)
	}
	if len(bp.Statement) != 1 {
		t.Fatalf("want 1 statement, got %d", len(bp.Statement))
	}
	return bp
}

// The condition key prefix is the OIDC PROVIDER NAME (host+path), never the provider ARN.
func TestTrustPolicyConditionKeysUseProviderNameNotARN(t *testing.T) {
	spec := &core.AWSRoleTrustOIDCSpec{
		OIDCProviderURL:  "https://token.actions.githubusercontent.com",
		Audience:         "sts.amazonaws.com",
		Subject:          "repo:myorg/myrepo:ref:refs/heads/main",
		SubjectCondition: "StringEquals",
		Source:           core.GitHubOIDC,
	}
	bp := build(t, spec, "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com")

	keys := map[string]string{}
	for _, byKey := range bp.Statement[0].Condition {
		for k, v := range byKey {
			keys[k] = v
		}
	}
	if got, ok := keys["token.actions.githubusercontent.com:aud"]; !ok || got != "sts.amazonaws.com" {
		t.Errorf("missing/incorrect aud condition key; got keys %v", keys)
	}
	if got, ok := keys["token.actions.githubusercontent.com:sub"]; !ok || got != spec.Subject {
		t.Errorf("missing/incorrect sub condition key; got keys %v", keys)
	}
	for k := range keys {
		if strings.HasPrefix(k, "arn:") {
			t.Errorf("condition key %q is built from the ARN; IAM would never populate it", k)
		}
	}
}

func TestTrustPolicyEKSIssuerWithPath(t *testing.T) {
	// An EKS issuer has a path component; the whole host+path is the prefix.
	spec := &core.AWSRoleTrustOIDCSpec{
		OIDCProviderURL: "https://oidc.eks.us-east-1.amazonaws.com/id/ABC123",
		Audience:        "sts.amazonaws.com",
		Subject:         "system:serviceaccount:ns:sa",
	}
	bp := build(t, spec, "arn:aws:iam::1:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/ABC123")
	found := false
	for _, byKey := range bp.Statement[0].Condition {
		if _, ok := byKey["oidc.eks.us-east-1.amazonaws.com/id/ABC123:sub"]; ok {
			found = true
		}
	}
	if !found {
		t.Errorf("EKS sub condition key not built from host+path: %+v", bp.Statement[0].Condition)
	}
}

// Google is a BUILT-IN AWS identity provider: the principal is the bare issuer host, not a provider ARN.
func TestTrustPolicyGooglePrincipalIsBareHost(t *testing.T) {
	spec := &core.AWSRoleTrustOIDCSpec{
		OIDCProviderURL: "https://accounts.google.com",
		Audience:        "sts.amazonaws.com",
		Subject:         "109876543210987654321",
	}
	bp := build(t, spec, "") // no provider ARN exists for a built-in IdP
	if got := bp.Statement[0].Principal["Federated"]; got != "accounts.google.com" {
		t.Errorf("Federated principal = %q, want the bare host accounts.google.com", got)
	}
}

// For accounts.google.com the :aud key maps to the token's azp claim whenever azp is set — and GCE service-account tokens set it.
func TestTrustPolicyGooglePinsAudienceWithOaud(t *testing.T) {
	spec := &core.AWSRoleTrustOIDCSpec{
		OIDCProviderURL: "https://accounts.google.com",
		Audience:        "sts.amazonaws.com",
		Subject:         "109876543210987654321",
	}
	bp := build(t, spec, "")

	keys := map[string]string{}
	for _, byKey := range bp.Statement[0].Condition {
		for k, v := range byKey {
			keys[k] = v
		}
	}
	if got, ok := keys["accounts.google.com:oaud"]; !ok || got != "sts.amazonaws.com" {
		t.Errorf("audience must be pinned with :oaud for Google; got %v", keys)
	}
	if got, ok := keys["accounts.google.com:aud"]; ok && got == "sts.amazonaws.com" {
		t.Errorf(":aud must NOT be pinned to the audience for Google (it maps to azp); got %v", keys)
	}
	if got, ok := keys["accounts.google.com:sub"]; !ok || got != spec.Subject {
		t.Errorf("sub must be pinned; got %v", keys)
	}
}

func TestNeedsOIDCProviderResource(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://accounts.google.com", false}, // built-in
		{"https://cognito-identity.amazonaws.com", false},
		{"https://token.actions.githubusercontent.com", true},
		{"https://oidc.eks.us-east-1.amazonaws.com/id/A", true},
	}
	for _, tc := range tests {
		if got := needsOIDCProviderResource(tc.url); got != tc.want {
			t.Errorf("needsOIDCProviderResource(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

// A spec with no subject must not produce a policy at all.
func TestTrustPolicyRefusesUnscopedSubject(t *testing.T) {
	spec := &core.AWSRoleTrustOIDCSpec{
		RoleName:        "deploy",
		AccountID:       "123456789012",
		OIDCProviderURL: "https://token.actions.githubusercontent.com",
		Audience:        "sts.amazonaws.com",
		Source:          core.GitHubOIDC,
		// Subject deliberately omitted.
	}
	doc, err := buildTrustPolicy("arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com", spec)
	if err == nil {
		raw, _ := json.Marshal(doc)
		t.Fatalf("built a world-assumable trust policy instead of refusing: %s", raw)
	}
	if !strings.Contains(err.Error(), "no subject condition") {
		t.Errorf("error should name the problem, got: %v", err)
	}
}

// The escape hatch still works, and still emits no sub condition — the point is that reaching it takes a deliberate flag, not an omission.
func TestTrustPolicyAllowsUnscopedWhenExplicit(t *testing.T) {
	spec := &core.AWSRoleTrustOIDCSpec{
		RoleName:              "internal-idp-role",
		AccountID:             "123456789012",
		OIDCProviderURL:       "https://idp.internal.example.com",
		Audience:              "sts.amazonaws.com",
		AllowUnscopedSubject:  true,
		UnscopedJustification: "issuer is operated by us and mints tokens for one workload only",
	}
	bp := build(t, spec, "arn:aws:iam::123456789012:oidc-provider/idp.internal.example.com")
	for op, kv := range bp.Statement[0].Condition {
		for key := range kv {
			if strings.HasSuffix(key, ":sub") {
				t.Errorf("%s pinned %s but the spec opted out of subject scoping", op, key)
			}
		}
	}
}
