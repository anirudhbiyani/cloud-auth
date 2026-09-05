package gcp_test

import (
	"context"
	"log"

	"github.com/anirudhbiyani/cloud-auth/provider/gcp"
)

// The examples that used to live in these methods' doc comments, as real Example functions so the compiler checks them.

// GCP workloads can authenticate to AWS with no long-lived credentials.
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

// The Azure direction, via an Entra federated credential trusting the Google issuer.
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
