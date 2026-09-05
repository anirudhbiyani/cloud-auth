package vault_test

import (
	"context"
	"log"

	"github.com/anirudhbiyani/cloud-auth/provider/vault"
)

// The examples that used to live in these methods' doc comments, as real
// Example functions so the compiler checks them.
//
// Example functions with no "Output:" comment are compiled but not run, which
// is what we want here: every one of these would talk to a live Vault.
// Compiling them is the point — a documented example that does not build is
// worse than no example, because it is the first thing a new user copies.

// Vault's AWS secrets engine issues short-lived AWS credentials against a role
// the engine already holds.
func ExampleProvider_GenerateAWSCredentials() {
	p := vault.New()

	creds, err := p.GenerateAWSCredentials(context.Background(), &vault.GenerateAWSCredentialsInput{
		SecretsEnginePath: "aws",
		RoleName:          "my-role",
	})
	if err != nil {
		log.Fatal(err)
	}
	_ = creds
}

// The GCP engine. KeyType picks between an OAuth access token and a service
// account key; prefer the token, which expires on its own.
func ExampleProvider_GenerateGCPCredentials() {
	p := vault.New()

	creds, err := p.GenerateGCPCredentials(context.Background(), &vault.GenerateGCPCredentialsInput{
		SecretsEnginePath: "gcp",
		RoleName:          "my-role",
		KeyType:           "access_token",
	})
	if err != nil {
		log.Fatal(err)
	}
	_ = creds
}

// The Azure engine.
func ExampleProvider_GenerateAzureCredentials() {
	p := vault.New()

	creds, err := p.GenerateAzureCredentials(context.Background(), &vault.GenerateAzureCredentialsInput{
		SecretsEnginePath: "azure",
		RoleName:          "my-role",
	})
	if err != nil {
		log.Fatal(err)
	}
	_ = creds
}
