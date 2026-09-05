package azure_test

import (
	"context"
	"log"

	"github.com/anirudhbiyani/cloud-auth/provider/azure"
)

// The examples that used to live in these methods' doc comments, as real
// Example functions so the compiler checks them.
//
// Example functions with no "Output:" comment are compiled but not run, which
// is what we want here: every one of these would talk to Azure AD. Compiling
// them is the point — a documented example that does not build is worse than no
// example, because it is the first thing a new user copies.

// Azure workloads can authenticate to AWS with no long-lived credentials: the
// token is issued by Azure AD and validated by AWS.
//
// The AWS IAM role must trust the Azure AD OIDC issuer —
// https://login.microsoftonline.com/{tenant_id}/v2.0, or
// https://sts.windows.net/{tenant_id}/ — and the app must carry the audience
// AWS expects.
func ExampleProvider_GenerateAWSRoleAssumptionToken() {
	p := azure.New()

	token, err := p.GenerateAWSRoleAssumptionToken(context.Background(), &azure.AWSRoleAssumptionInput{
		TenantID: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
		ClientID: "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
		RoleARN:  "arn:aws:iam::123456789012:role/MyRole",
		// Required off an app registration: there is no flow that can mint this
		// token outside Azure, so the method refuses rather than half-trying.
		UseManagedIdentity: true,
	})
	if err != nil {
		log.Fatal(err)
	}

	// token.Token goes to the AWS provider's Token() method.
	_ = token.Token
}

// The GCP direction. The workload identity pool must have a provider
// configured to trust Azure AD, with issuer
// https://login.microsoftonline.com/{tenant_id}/v2.0.
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
