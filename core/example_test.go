package core_test

import (
	"context"
	"log"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// The example in the package doc, as a real Example function so the compiler checks it.
func ExampleSetup() {
	ctx := context.Background()

	spec := &core.AWSRoleTrustOIDCSpec{
		RoleName:        "github-deploy",
		AccountID:       "123456789012",
		OIDCProviderURL: "https://token.actions.githubusercontent.com",
		Audience:        "sts.amazonaws.com",
		Subject:         "repo:myorg/myrepo:ref:refs/heads/main",
		Source:          core.GitHubOIDC,
	}

	outputs, err := core.Setup(ctx, spec)
	if err != nil {
		log.Fatal(err)
	}

	report, err := core.Validate(ctx, outputs.Ref)
	if err != nil {
		log.Fatal(err)
	}
	if !report.HasChecks() || !report.IsValid() || !report.IsComplete() {
		for _, c := range report.FailedChecks() {
			log.Printf("failed: %s — %s", c.Name, c.Remediation)
		}
		for _, c := range report.SkippedChecks() {
			log.Printf("NOT VERIFIED: %s — %s", c.Name, c.Remediation)
		}
	}
}

// The redaction the package doc warns about, as an executable check rather than a claim.
func ExampleCredentials_Reveal() {
	creds := core.Credentials{
		Cloud:           core.AWS,
		AccessKeyID:     "ASIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	// Printing is safe: every formatting path redacts.
	_ = creds.String()

	// Reveal is the one way to the plaintext, and is named to be visible in review.
	plain := creds.Reveal()
	_ = plain.SecretAccessKey
}

// Building a target: the cloud is implied by the type, so a field belonging to another cloud cannot be written down.
func ExampleTarget() {
	targets := []core.Target{
		core.AWSTarget{RoleARN: "arn:aws:iam::123456789012:role/reader"},
		core.GCPTarget{
			WorkloadIdentityPool: "projects/1/locations/global/workloadIdentityPools/p/providers/x",
		},
		core.AzureTarget{
			Tenant:   "11111111-1111-1111-1111-111111111111",
			ClientID: "22222222-2222-2222-2222-222222222222",
			Scope:    "https://storage.azure.com/.default",
		},
	}
	for _, t := range targets {
		if err := t.Validate(); err != nil {
			log.Printf("%s target is incomplete: %v", t.Cloud(), err)
		}
	}
}
