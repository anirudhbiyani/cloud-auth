// Package cloudauth provides cross-cloud authentication lifecycle management.
//
// # Overview
//
// cloudauth enables you to set up, validate, and delete cross-cloud authentication
// mechanisms between major cloud providers (AWS, GCP, Azure) and identity providers
// (GitHub OIDC, Kubernetes, Okta, etc.).
//
// # Core Concepts
//
// ## Providers
//
// A Provider represents a cloud service or identity provider. Providers can support
// different capabilities:
//   - Token acquisition (TokenProvider interface)
//   - Lifecycle management (LifecycleProvider interface)
//
// ## Mechanisms
//
// A Mechanism represents a configured cross-cloud authentication relationship.
// Common mechanism types include:
//   - AWSRoleTrustOIDC: AWS IAM Role trusting an OIDC IdP
//   - GCPWorkloadIdentityPool: GCP Workload Identity Pool configuration
//   - AzureFederatedCredential: Azure AD federated identity credential
//   - K8sServiceAccountFederation: Kubernetes SA to cloud identity mapping
//
// ## Specs and Refs
//
// A MechanismSpec describes the desired configuration for a mechanism.
// A MechanismRef is a stable reference to a created mechanism instance.
//
// ## State Store
//
// The StateStore tracks created mechanisms and ownership for safe lifecycle
// management. By default, only resources created by cloudauth (owned) can be deleted.
//
// # Usage
//
// ## Setting up a mechanism
//
//	spec := &cloudauth.AWSRoleTrustOIDCSpec{
//	    RoleName:        "my-role",
//	    AccountID:       "123456789012",
//	    OIDCProviderURL: "https://token.actions.githubusercontent.com",
//	    Audience:        "sts.amazonaws.com",
//	    Subject:         "repo:myorg/myrepo:ref:refs/heads/main",
//	    Source:          cloudauth.ProviderGitHubOIDC,
//	}
//
//	outputs, err := cloudauth.Setup(ctx, spec)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	fmt.Printf("Created mechanism: %s\n", outputs.Ref.ID)
//
// ## Validating a mechanism
//
//	report, err := cloudauth.Validate(ctx, outputs.Ref)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	if !report.IsValid() {
//	    for _, check := range report.FailedChecks() {
//	        fmt.Printf("Failed: %s - %s\n", check.Name, check.Remediation)
//	    }
//	}
//
// ## Deleting a mechanism
//
//	err := cloudauth.Delete(ctx, outputs.Ref)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # Backward Compatibility
//
// The existing Token(...) flows from the lib package continue to work.
// This new API provides additional lifecycle management capabilities.
//
// # Extension
//
// New providers can be added by implementing the Provider interface and
// registering via cloudauth.Register() or an init() function.
package cloudauth

