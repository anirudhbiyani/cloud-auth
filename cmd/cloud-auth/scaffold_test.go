package main

import (
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
)

func TestScaffoldAWS(t *testing.T) {
	out, err := scaffoldTrust(scaffoldInput{
		target:  cloudauth.Target{Cloud: cloudauth.AWS, Role: "arn:aws:iam::1:role/x", Audience: "sts.amazonaws.com"},
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
		target: cloudauth.Target{
			Cloud:                     cloudauth.GCP,
			WorkloadIdentityPool:      "projects/123/locations/global/workloadIdentityPools/p/providers/pr",
			ImpersonateServiceAccount: "sa@proj.iam.gserviceaccount.com",
			Audience:                  "//iam.googleapis.com/aud",
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
		target:  cloudauth.Target{Cloud: cloudauth.Azure, Tenant: "tid", ClientID: "cid", Audience: "api://AzureADTokenExchange"},
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
		"tid",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Azure scaffold missing %q\n%s", want, out)
		}
	}
}

func TestScaffoldUnsupported(t *testing.T) {
	if _, err := scaffoldTrust(scaffoldInput{target: cloudauth.Target{Cloud: cloudauth.Cloudflare}}); err == nil {
		t.Error("want error for unsupported target cloud")
	}
}

func TestScaffoldPlaceholdersWhenNoRuntime(t *testing.T) {
	out, err := scaffoldTrust(scaffoldInput{target: cloudauth.Target{Cloud: cloudauth.AWS, Role: "r"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "<SOURCE_OIDC_ISSUER_URL>") || !strings.Contains(out, "<SOURCE_SUBJECT>") {
		t.Errorf("want placeholders when issuer/subject unknown\n%s", out)
	}
}
