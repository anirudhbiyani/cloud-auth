package aws

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// TrustPolicy parses a document IAM returns, which may be percent-encoded and whose Principal, Action and condition values are each string-or-array.
func FuzzTrustPolicyDoc(f *testing.F) {
	f.Add(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::1:oidc-provider/x"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"x:aud":"a","x:sub":"s"}}}]}`)
	f.Add(`{"Statement":[{"Principal":{"Federated":["a","b"]},"Condition":{"StringLike":{"x:sub":["p","q"]}}}]}`)
	f.Add(`%7B%22Statement%22%3A%5B%5D%7D`)
	f.Add(`{"Statement":[]}`)
	f.Add(``)
	f.Add(`{"Statement":[{"Effect":"Deny","Condition":{"StringEquals":{"x:aud":"nope"}}}]}`)

	f.Fuzz(func(t *testing.T, doc string) {
		p := New(WithIAMClient(&fuzzRole{doc: doc}))
		tp, err := p.TrustPolicy(context.Background(), fuzzRef())
		if err != nil {
			return
		}
		if tp == nil {
			t.Fatal("nil trust policy with nil error")
		}
		// Anything reported must actually appear in the document, or the drift check compares against values nobody wrote.
		if utf8.ValidString(doc) {
			decoded, derr := urlDecodeIfNeeded(doc)
			if derr != nil {
				decoded = doc
			}
			for _, a := range tp.Audiences {
				if a != "" && !strings.Contains(decoded, a) {
					t.Fatalf("reported audience %q is absent from the document", a)
				}
			}
			for _, s := range tp.Subjects {
				if s != "" && !strings.Contains(decoded, s) {
					t.Fatalf("reported subject %q is absent from the document", s)
				}
			}
		}
		// Duplicates would inflate the "policy admits" list in error messages.
		if dup(tp.Audiences) {
			t.Fatalf("duplicate audiences: %v", tp.Audiences)
		}
		if dup(tp.Subjects) {
			t.Fatalf("duplicate subjects: %v", tp.Subjects)
		}
	})
}

func dup(xs []string) bool {
	seen := map[string]bool{}
	for _, x := range xs {
		if seen[x] {
			return true
		}
		seen[x] = true
	}
	return false
}

// FuzzIssuerFromFederatedPrincipal covers the ARN and bare-host parsing that decides which issuer a trust policy is compared against.
func FuzzIssuerFromFederatedPrincipal(f *testing.F) {
	f.Add("arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com")
	f.Add("accounts.google.com")
	f.Add("https://issuer.example.com")
	f.Add("arn:aws:iam::1:saml-provider/x")
	f.Add("")
	f.Add(":oidc-provider/")

	f.Fuzz(func(t *testing.T, principal string) {
		got := issuerFromFederatedPrincipal(principal)
		if principal == "" && got != "" {
			t.Fatalf("empty principal produced %q", got)
		}
		if got == "" {
			return
		}
		// A non-empty result is either a URL or the untouched non-OIDC principal.
		if !strings.HasPrefix(got, "https://") && !strings.HasPrefix(got, "http://") && got != principal {
			t.Fatalf("issuerFromFederatedPrincipal(%q) = %q: neither a URL nor the input",
				principal, got)
		}
	})
}

// helpers ---------------------------------------------------------------------

// fuzzRole returns a role whose assume-role policy is whatever the fuzzer produced.
type fuzzRole struct {
	IAMClient
	doc string
}

func (f *fuzzRole) GetRole(context.Context, string) (*Role, error) {
	return &Role{RoleName: "r", ARN: "arn:aws:iam::123456789012:role/r", AssumeRolePolicyDocument: f.doc}, nil
}

func fuzzRef() core.MechanismRef {
	return core.MechanismRef{
		ID:          "m",
		Type:        core.MechanismAWSRoleTrustOIDC,
		ResourceIDs: map[string]string{"role_name": "r"},
	}
}
