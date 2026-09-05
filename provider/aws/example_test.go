package aws_test

import (
	"context"
	"log"

	"github.com/anirudhbiyani/cloud-auth/provider/aws"
)

// The example that used to live in this method's doc comment, as a real Example
// function so the compiler checks it.
//
// Example functions with no "Output:" comment are compiled but not run, which
// is what we want here: this one would talk to AWS STS. Compiling it is the
// point — a documented example that does not build is worse than no example,
// because it is the first thing a new user copies.

// AWS workloads can authenticate to GCP with no long-lived credentials, via a
// workload identity pool provider that trusts the AWS account.
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
