package azure_test

import (
	"context"
	"log"

	"github.com/anirudhbiyani/cloud-auth/provider/azure"
)

// The examples that used to live in these methods' doc comments, as real Example functions so the compiler checks them.

// Azure workloads can authenticate to AWS with no long-lived credentials: the token is issued by Azure AD and validated by AWS.
func ExampleProvider_GenerateAWSRoleAssumptionToken() {
	p := azure.New()

	token, err := p.GenerateAWSRoleAssumptionToken(context.Background(), &azure.AWSRoleAssumptionInput{
		TenantID: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
		ClientID: "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
		RoleARN:  "arn:aws:iam::123456789012:role/MyRole",
		// Required off an app registration: there is no flow that can mint this token outside Azure, so the method refuses rather than half-trying.
		UseManagedIdentity: true,
	})
	if err != nil {
		log.Fatal(err)
	}

	// token.Token goes to the AWS provider's Token() method.
	_ = token.Token
}

// The GCP direction.
func ExampleProvider_GenerateGCPWorkloadIdentityToken() {
	p := azure.New()

	token, err := p.GenerateGCPWorkloadIdentityToken(context.Background(), &azure.GCPWorkloadIdentityInput{
		TenantID:           "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
		ClientID:           "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
		ProjectNumber:      "123456789012",
		PoolID:             "my-pool",
		ProviderID:         "azure-provider",
		UseManagedIdentity: true,
	})
	if err != nil {
		log.Fatal(err)
	}

	// token.Token goes to the GCP provider's Token() method.
	_ = token.Token
}
