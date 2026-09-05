package main

import (
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

func TestScaffoldAWS(t *testing.T) {
	out, err := scaffoldTrust(scaffoldInput{
		target:  core.AWSTarget{RoleARN: "arn:aws:iam::123456789012:role/x"},
		issuer:  "https://oidc.example.com",
		subject: "repo:org/repo:ref:main",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"aws_iam_openid_connect_provider",
		"sts:AssumeRoleWithWebIdentity",
		"oidc.example.com:aud", // scheme stripped for condition key
		"repo:org/repo:ref:main",
		"aws iam create-open-id-connect-provider",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("AWS scaffold missing %q\n%s", want, out)
		}
	}
}

func TestScaffoldGCP(t *testing.T) {
	out, err := scaffoldTrust(scaffoldInput{
		target: core.GCPTarget{
			WorkloadIdentityPool:      "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/providers/pr",
			ImpersonateServiceAccount: "sa@proj.iam.gserviceaccount.com",
			TokenAudience:             "//iam.googleapis.com/aud",
		},
		issuer:  "https://oidc.example.com",
		subject: "sub-123",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"google_iam_workload_identity_pool_provider",
		"roles/iam.workloadIdentityUser",
		"sa@proj.iam.gserviceaccount.com",
		"gcloud iam workload-identity-pools providers create-oidc",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("GCP scaffold missing %q\n%s", want, out)
		}
	}
}

func TestScaffoldAzure(t *testing.T) {
	out, err := scaffoldTrust(scaffoldInput{
		target:  core.AzureTarget{Tenant: "11111111-1111-1111-1111-111111111111", ClientID: "22222222-2222-2222-2222-222222222222", Scope: "https://storage.azure.com/.default"},
		issuer:  "https://oidc.example.com",
		subject: "sub-abc",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"azuread_application_federated_identity_credential",
		"az ad app federated-credential create",
		"case-sensitive",
		"api://AzureADTokenExchange",
		"22222222-2222-2222-2222-222222222222", // the client id
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Azure scaffold missing %q\n%s", want, out)
		}
	}
}

func TestScaffoldUnsupported(t *testing.T) {
	if _, err := scaffoldTrust(scaffoldInput{target: unsupportedTarget{}}); err == nil {
		t.Error("want error for unsupported target cloud")
	}
}

func TestScaffoldPlaceholdersWhenNoRuntime(t *testing.T) {
	out, err := scaffoldTrust(scaffoldInput{target: core.AWSTarget{RoleARN: "arn:aws:iam::123456789012:role/r"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "<SOURCE_OIDC_ISSUER_URL>") || !strings.Contains(out, "<SOURCE_SUBJECT>") {
		t.Errorf("want placeholders when issuer/subject unknown\n%s", out)
	}
}

// unsupportedTarget stands in for a cloud the scaffolder does not handle.
type unsupportedTarget struct{}

func (unsupportedTarget) Cloud() core.Cloud { return core.Okta }
func (unsupportedTarget) Audience() string  { return "aud" }
func (unsupportedTarget) Validate() error   { return nil }
