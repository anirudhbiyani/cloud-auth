package aws

import (
	"context"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// The population `audit` serves is roles that predate this tool: AWS's shared-IdP guardrail explicitly does not apply to roles created before June 2025. Enumerating from cloud-auth's state file would list what cloud-auth created, which is the one set already known to be fine.

type listIAM struct {
	IAMClient
	roles []*Role
	err   error
}

func (f *listIAM) ListRoles(context.Context) ([]*Role, error) { return f.roles, f.err }

const ghProviderARN = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"

// federatedPolicy builds a realistic assume-role policy.
func federatedPolicy(operator, subject string) string {
	conditions := `"` + operator + `":{` +
		`"token.actions.githubusercontent.com:aud":"sts.amazonaws.com",` +
		`"token.actions.githubusercontent.com:sub":"` + subject + `"}`
	if operator != "StringEquals" {
		conditions = `"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},` +
			`"` + operator + `":{"token.actions.githubusercontent.com:sub":"` + subject + `"}`
	}
	return `{"Version":"2012-10-17","Statement":[{
	  "Effect":"Allow",
	  "Principal":{"Federated":"` + ghProviderARN + `"},
	  "Action":"sts:AssumeRoleWithWebIdentity",
	  "Condition":{` + conditions + `}
	}]}`
}

func TestListTrustRecords(t *testing.T) {
	p := New(WithIAMClient(&listIAM{roles: []*Role{
		{ARN: "arn:aws:iam::123456789012:role/deploy", RoleName: "deploy",
			AssumeRolePolicyDocument: federatedPolicy("StringEquals", "repo:myorg/myrepo:ref:refs/heads/main")},
		// Assumable only by an IAM principal in the same account: not a cross-cloud trust, and listing it would bury the ones that are.
		{ARN: "arn:aws:iam::123456789012:role/internal", RoleName: "internal",
			AssumeRolePolicyDocument: `{"Version":"2012-10-17","Statement":[{
			  "Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},
			  "Action":"sts:AssumeRole"}]}`},
	}}))

	records, err := p.ListTrustRecords(context.Background())
	if err != nil {
		t.Fatalf("ListTrustRecords: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1 (only the federated role):\n%+v", len(records), records)
	}

	r := records[0]
	if r.Cloud != core.AWS || r.Name != "deploy" {
		t.Errorf("record = %+v", r)
	}
	if r.SubjectCondition != "repo:myorg/myrepo:ref:refs/heads/main" {
		t.Errorf("SubjectCondition = %q", r.SubjectCondition)
	}
	if r.Operator != "StringEquals" {
		t.Errorf("Operator = %q — the operator decides whether the pattern means anything", r.Operator)
	}
	if r.Issuer != "https://token.actions.githubusercontent.com" {
		t.Errorf("Issuer = %q", r.Issuer)
	}
	if len(r.Audiences) != 1 || r.Audiences[0] != "sts.amazonaws.com" {
		t.Errorf("Audiences = %v", r.Audiences)
	}
}

// One row per (role, subject): each is separately scoreable and separately claimable, and collapsing them hides the worst behind the best.
func TestOneRecordPerSubjectCondition(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[{
	  "Effect":"Allow","Principal":{"Federated":"` + ghProviderARN + `"},
	  "Action":"sts:AssumeRoleWithWebIdentity",
	  "Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":[
	    "repo:myorg/myrepo:ref:refs/heads/main","repo:deletedorg/*"]}}
	}]}`

	p := New(WithIAMClient(&listIAM{roles: []*Role{
		{ARN: "arn:aws:iam::1:role/multi", RoleName: "multi", AssumeRolePolicyDocument: doc},
	}}))
	records, err := p.ListTrustRecords(context.Background())
	if err != nil {
		t.Fatalf("ListTrustRecords: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want one per subject", len(records))
	}
}

// A federated trust with no subject condition is the widest possible one.
func TestNoSubjectConditionIsARecord(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[{
	  "Effect":"Allow","Principal":{"Federated":"` + ghProviderARN + `"},
	  "Action":"sts:AssumeRoleWithWebIdentity",
	  "Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"}}
	}]}`

	p := New(WithIAMClient(&listIAM{roles: []*Role{
		{ARN: "arn:aws:iam::1:role/wide", RoleName: "wide", AssumeRolePolicyDocument: doc},
	}}))
	records, err := p.ListTrustRecords(context.Background())
	if err != nil {
		t.Fatalf("ListTrustRecords: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if records[0].SubjectCondition != "" {
		t.Errorf("SubjectCondition = %q, want empty", records[0].SubjectCondition)
	}
	// And the scorer must call that what it is.
	if got := core.ScoreSubject(records[0].SubjectCondition).Breadth; got != core.BreadthCritical {
		t.Errorf("breadth = %s, want critical", got)
	}
}

// A Deny does not grant trust.
func TestDenyStatementsAreNotInventoried(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[{
	  "Effect":"Deny","Principal":{"Federated":"` + ghProviderARN + `"},
	  "Action":"sts:AssumeRoleWithWebIdentity",
	  "Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:evil/*"}}
	}]}`

	p := New(WithIAMClient(&listIAM{roles: []*Role{
		{ARN: "arn:aws:iam::1:role/denied", RoleName: "denied", AssumeRolePolicyDocument: doc},
	}}))
	records, err := p.ListTrustRecords(context.Background())
	if err != nil {
		t.Fatalf("ListTrustRecords: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("a Deny was inventoried as a grant: %+v", records)
	}
}

// A policy that cannot be parsed is surfaced, not dropped: "we could not tell" is not "nothing here".
func TestUnparseablePolicyIsStillARecord(t *testing.T) {
	p := New(WithIAMClient(&listIAM{roles: []*Role{
		{ARN: "arn:aws:iam::1:role/weird", RoleName: "weird", AssumeRolePolicyDocument: "not json"},
	}}))
	records, err := p.ListTrustRecords(context.Background())
	if err != nil {
		t.Fatalf("ListTrustRecords: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("an unreadable policy was silently dropped")
	}
}

func TestInventoryCloud(t *testing.T) {
	if got := New().InventoryCloud(); got != core.AWS {
		t.Errorf("InventoryCloud() = %q", got)
	}
}
