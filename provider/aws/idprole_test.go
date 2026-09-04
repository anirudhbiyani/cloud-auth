package aws

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/internal/jwt"
)

// Round-trip: the policy this package GENERATES, read back through the parser
// it also owns, into the detector that judges it. Testing the generator alone
// would prove the JSON is shaped right and nothing about whether the shape is
// the one STS reads.

func idpRoleSpec(require bool) *core.AWSRoleTrustOIDCSpec {
	return &core.AWSRoleTrustOIDCSpec{
		RoleName: "deploy", AccountID: "123456789012",
		OIDCProviderURL:          "https://token.actions.githubusercontent.com",
		Audience:                 "sts.amazonaws.com",
		Subject:                  "repo:myorg/myrepo:ref:refs/heads/main",
		SubjectCondition:         "StringEquals",
		RequireIdPAuthorizedRole: require,
		Source:                   core.GitHubOIDC,
	}
}

func TestBuildTrustPolicyEmitsTheCondition(t *testing.T) {
	doc, err := buildTrustPolicy(
		"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
		idpRoleSpec(true))
	if err != nil {
		t.Fatalf("buildTrustPolicy: %v", err)
	}

	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(encoded), core.IdPAuthorizedRoleConditionKey) {
		t.Fatalf("the condition is absent:\n%s", encoded)
	}
	// A Bool condition, not a String one: the key answers "did the IdP
	// authorize this role", and the comparison against the claim is STS's.
	if !strings.Contains(string(encoded), `"Bool":{"`+core.IdPAuthorizedRoleConditionKey+`":"true"}`) {
		t.Errorf("the condition is not a Bool:\n%s", encoded)
	}
}

// Off by default. Turning it on for an issuer that does not emit the claim locks
// every workload out of the role, so nobody should get it by omission.
func TestBuildTrustPolicyOmitsTheConditionByDefault(t *testing.T) {
	doc, err := buildTrustPolicy(
		"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
		idpRoleSpec(false))
	if err != nil {
		t.Fatalf("buildTrustPolicy: %v", err)
	}
	encoded, _ := json.Marshal(doc)
	if strings.Contains(string(encoded), core.IdPAuthorizedRoleConditionKey) {
		t.Errorf("the condition appeared without being asked for:\n%s", encoded)
	}
}

// The generated policy, read back, must reach the detector — a generator and a
// parser that disagree produce a policy nothing can explain.
func TestIdPAuthorizedRoleRoundTrip(t *testing.T) {
	doc, err := buildTrustPolicy(
		"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
		idpRoleSpec(true))
	if err != nil {
		t.Fatalf("buildTrustPolicy: %v", err)
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	tp := readPolicy(t, string(encoded))

	var found bool
	for _, c := range tp.Conditions {
		if c.Claim == core.IdPAuthorizedRoleConditionKey {
			found = true
			if c.Operator != "Bool" || c.Value != "true" {
				t.Errorf("condition = %+v, want Bool/true", c)
			}
		}
	}
	if !found {
		t.Fatalf("the parser dropped the condition it just generated: %+v", tp.Conditions)
	}

	const role = "arn:aws:iam::123456789012:role/deploy"
	const subject = "repo:myorg/myrepo:ref:refs/heads/main"
	tok := &core.SourceToken{
		Kind: core.OIDC, Issuer: "https://token.actions.githubusercontent.com",
		Subject: subject, Audience: "sts.amazonaws.com",
	}

	t.Run("a token carrying the role validates", func(t *testing.T) {
		for _, f := range core.Explain(core.ExplainInput{
			Trust: tp, Token: tok, TargetRole: role,
			IdPAuthorizedRoles: []string{role},
		}) {
			if strings.HasPrefix(f.Detector, "idp-authorized-role") {
				t.Errorf("unexpected finding: %s — %s", f.Detector, f.Summary)
			}
		}
	})

	t.Run("a token missing the claim is diagnosed", func(t *testing.T) {
		var found bool
		for _, f := range core.Explain(core.ExplainInput{
			Trust: tp, Token: tok, TargetRole: role,
		}) {
			if f.Detector == "idp-authorized-role-missing" {
				found = true
			}
		}
		if !found {
			t.Error("a policy requiring the condition and a token without the claim produced " +
				"no named diagnosis")
		}
	})
}

// The claim is a string OR an array of role ARNs, and both shapes must read.
func TestIdPRoleClaimShapes(t *testing.T) {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	mk := func(claim any) string {
		return enc(map[string]any{"alg": "RS256"}) + "." +
			enc(map[string]any{
				"iss": "https://token.actions.githubusercontent.com",
				"sub": "repo:o/r:ref:refs/heads/main", "aud": "sts.amazonaws.com",
				core.IdPAuthorizedRoleClaim: claim,
			}) + ".sig"
	}

	for _, tc := range []struct {
		name  string
		claim any
		want  int
	}{
		{"single string", "arn:aws:iam::1:role/a", 1},
		{"array", []string{"arn:aws:iam::1:role/a", "arn:aws:iam::1:role/b"}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := jwt.StringOrSliceClaim(mk(tc.claim), core.IdPAuthorizedRoleClaim)
			if err != nil {
				t.Fatalf("reading the claim: %v", err)
			}
			if len(got) != tc.want {
				t.Errorf("got %d roles, want %d: %v", len(got), tc.want, got)
			}
		})
	}

	t.Run("absent is not an error", func(t *testing.T) {
		token := enc(map[string]any{"alg": "RS256"}) + "." +
			enc(map[string]any{"iss": "https://x", "sub": "s", "aud": "a"}) + ".sig"
		got, err := jwt.StringOrSliceClaim(token, core.IdPAuthorizedRoleClaim)
		if err != nil {
			t.Fatalf("an absent claim should not be an error: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("got %v, want nothing", got)
		}
	})
}
