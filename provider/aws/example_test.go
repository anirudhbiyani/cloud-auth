package aws_test

import (
	"context"
	"log"

	"github.com/anirudhbiyani/cloud-auth/provider/aws"
)

// The example that used to live in this method's doc comment, as a real Example function so the compiler checks it.

// AWS workloads can authenticate to GCP with no long-lived credentials, via a workload identity pool provider that trusts the AWS account.
func ExampleProvider_GenerateGCPWorkloadIdentityToken() {
	p := aws.New()

	token, err := p.GenerateGCPWorkloadIdentityToken(context.Background(), &aws.GCPWorkloadIdentityInput{
		ProjectNumber: "123456789012",
		PoolID:        "my-pool",
		ProviderID:    "aws-provider",
	})
	if err != nil {
		log.Fatal(err)
	}

	// token.Token goes to the GCP provider's Token() method.
	_ = token.Token
}
