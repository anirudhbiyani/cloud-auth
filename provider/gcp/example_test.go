package gcp_test

import (
	"context"
	"log"

	"github.com/anirudhbiyani/cloud-auth/provider/gcp"
)

// The examples that used to live in these methods' doc comments, as real
// Example functions so the compiler checks them.
//
// Example functions with no "Output:" comment are compiled but not run, which
// is what we want here: every one of these would talk to Google. Compiling them
// is the point — a documented example that does not build is worse than no
// example, because it is the first thing a new user copies.

// GCP workloads can authenticate to AWS with no long-lived credentials. The
// token is a JWT signed by Google that AWS validates.
//
// The AWS IAM role must trust the Google OIDC issuer
// (https://accounts.google.com), and the service account needs
// iam.serviceAccounts.signJwt.
func ExampleProvider_GenerateAWSRoleAssumptionToken() {
	p := gcp.New()

	token, err := p.GenerateAWSRoleAssumptionToken(context.Background(), &gcp.AWSRoleAssumptionInput{
		ServiceAccountEmail: "my-sa@project.iam.gserviceaccount.com",
		RoleARN:             "arn:aws:iam::123456789012:role/MyRole",
	})
	if err != nil {
		log.Fatal(err)
	}

	// token.Token goes to the AWS provider's Token() method.
	_ = token.Token
}

// The Azure direction, via an Entra federated credential trusting the Google
// issuer.
func ExampleProvider_GenerateAzureFederatedToken() {
	p := gcp.New()

	token, err := p.GenerateAzureFederatedToken(context.Background(), &gcp.AzureFederatedTokenInput{
		ServiceAccountEmail: "my-sa@project.iam.gserviceaccount.com",
		TenantID:            "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
		ClientID:            "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
	})
	if err != nil {
		log.Fatal(err)
	}

	// token.Token goes to the Azure provider's Token() method.
	_ = token.Token
}
