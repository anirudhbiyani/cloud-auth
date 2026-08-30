package aws

import (
	"context"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// The parser matched on the claim suffix "across any operator" and threw the
// operator away. That collapses two OPPOSITE policies into one representation:
// "*" under StringLike admits every token the issuer will ever mint, and the
// same "*" under StringEquals is compared literally, so it admits nothing and
// the trust is silently dead.

type policyIAM struct {
	IAMClient
	doc string
}

func (f *policyIAM) GetRole(_ context.Context, name string) (*Role, error) {
	return &Role{RoleName: name, ARN: "arn:aws:iam::123456789012:role/" + name,
		AssumeRolePolicyDocument: f.doc}, nil
}

func readPolicy(t *testing.T, doc string) *core.TrustPolicy {
	t.Helper()
	p := New(WithIAMClient(&policyIAM{doc: doc}))
	tp, err := p.TrustPolicy(context.Background(), core.MechanismRef{
		ID: "r", ResourceIDs: map[string]string{"role_name": "r"},
	})
	if err != nil {
		t.Fatalf("TrustPolicy: %v", err)
	}
	return tp
}

func TestTrustPolicyRetainsTheConditionOperator(t *testing.T) {
	const doc = `{
	  "Version": "2012-10-17",
	  "Statement": [{
	    "Effect": "Allow",
	    "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
	    "Action": "sts:AssumeRoleWithWebIdentity",
	    "Condition": {
	      "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
	      "StringLike": {"token.actions.githubusercontent.com:sub": "repo:myorg/myrepo:*"}
	    }
	  }]
	}`

	tp := readPolicy(t, doc)

	subs := tp.SubjectConditions()
	if len(subs) != 1 {
		t.Fatalf("got %d subject conditions, want 1", len(subs))
	}
	if subs[0].Operator != "StringLike" {
		t.Errorf("subject operator = %q, want StringLike", subs[0].Operator)
	}
	if !subs[0].HonoursWildcards() {
		t.Error("StringLike should honour wildcards")
	}

	auds := tp.AudienceConditions()
	if len(auds) != 1 || auds[0].Operator != "StringEquals" {
		t.Errorf("audience conditions = %+v, want one StringEquals", auds)
	}

	// The flattened views stay populated: the existing validators compare
	// membership and do not care how a value is matched.
	if len(tp.Subjects) != 1 || tp.Subjects[0] != "repo:myorg/myrepo:*" {
		t.Errorf("Subjects = %v", tp.Subjects)
	}
	if len(tp.Audiences) != 1 {
		t.Errorf("Audiences = %v", tp.Audiences)
	}
}

// The two policies this test compares differ ONLY in the operator, and mean
// opposite things. Before the parser retained it they were indistinguishable.
func TestOppositePoliciesAreDistinguishable(t *testing.T) {
	policy := func(operator string) string {
		return `{"Version":"2012-10-17","Statement":[{
		  "Effect":"Allow",
		  "Principal":{"Federated":"arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"},
		  "Action":"sts:AssumeRoleWithWebIdentity",
		  "Condition":{"` + operator + `":{"token.actions.githubusercontent.com:sub":"repo:myorg/myrepo:*"}}
		}]}`
	}

	wideOpen := readPolicy(t, policy("StringLike"))
	silentlyDead := readPolicy(t, policy("StringEquals"))

	token := &core.SourceToken{
		Kind: core.OIDC, Issuer: "https://token.actions.githubusercontent.com",
		Subject: "repo:myorg/myrepo:ref:refs/heads/main", Audience: "sts.amazonaws.com",
	}

	openFindings := core.Explain(core.ExplainInput{Trust: wideOpen, Token: token})
	deadFindings := core.Explain(core.ExplainInput{Trust: silentlyDead, Token: token})

	has := func(findings []core.Finding, detector string) bool {
		for _, f := range findings {
			if f.Detector == detector {
				return true
			}
		}
		return false
	}

	// StringLike + trailing wildcard: too wide, and reachable by a fork's PR.
	if !has(openFindings, "github-fork-pull-request") {
		t.Error("StringLike with a trailing wildcard should be flagged as fork-reachable")
	}
	if has(openFindings, "wildcard-under-exact-operator") {
		t.Error("StringLike honours wildcards; it must not be flagged as matching nothing")
	}

	// StringEquals + the same value: matches nothing at all.
	if !has(deadFindings, "wildcard-under-exact-operator") {
		t.Error("StringEquals with a wildcard should be flagged as matching nothing")
	}
	if has(deadFindings, "github-fork-pull-request") {
		t.Error("a policy that matches nothing cannot be fork-reachable; " +
			"one policy must not produce two contradictory findings")
	}
}

// Iteration over the operator map is random, so a diff that reorders itself
// between runs would be unreadable.
func TestConditionOrderIsStable(t *testing.T) {
	const doc = `{"Version":"2012-10-17","Statement":[{
	  "Effect":"Allow",
	  "Principal":{"Federated":"arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"},
	  "Action":"sts:AssumeRoleWithWebIdentity",
	  "Condition":{
	    "StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},
	    "StringLike":{"token.actions.githubusercontent.com:sub":["repo:a/b:*","repo:c/d:*"]},
	    "ForAllValues:StringEquals":{"token.actions.githubusercontent.com:sub":"repo:e/f:main"}
	  }
	}]}`

	first := readPolicy(t, doc).Conditions
	for range 20 {
		got := readPolicy(t, doc).Conditions
		if len(got) != len(first) {
			t.Fatalf("condition count changed: %d then %d", len(first), len(got))
		}
		for i := range got {
			if got[i] != first[i] {
				t.Fatalf("condition order changed at %d:\n first: %+v\n then:  %+v",
					i, first[i], got[i])
			}
		}
	}
}

// A Deny does not grant trust, and folding one into the allowed set would
// report a restriction as a permission.
func TestDenyStatementsAreIgnored(t *testing.T) {
	const doc = `{"Version":"2012-10-17","Statement":[
	  {"Effect":"Allow",
	   "Principal":{"Federated":"arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"},
	   "Action":"sts:AssumeRoleWithWebIdentity",
	   "Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:a/b:ref:refs/heads/main"}}},
	  {"Effect":"Deny",
	   "Principal":{"Federated":"arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"},
	   "Action":"sts:AssumeRoleWithWebIdentity",
	   "Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:evil/*"}}}
	]}`

	tp := readPolicy(t, doc)
	for _, c := range tp.Conditions {
		if c.Value == "repo:evil/*" {
			t.Error("a Deny condition was collected as though it granted trust")
		}
	}
	if len(tp.SubjectConditions()) != 1 {
		t.Errorf("got %d subject conditions, want 1", len(tp.SubjectConditions()))
	}
}
