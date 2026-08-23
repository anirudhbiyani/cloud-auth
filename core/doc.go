// Package core is the shared vocabulary of cloud-auth: the types every other
// package speaks, plus the control-plane machinery for establishing trust.
//
// It exports a lot, most of it struct fields on the four mechanism specs — those
// are the shape of the YAML an operator writes, so they have to be there. The
// list below is the part you actually need. Everything else is either reachable
// from one of these or an extension point you will only meet if you are writing
// a provider.
//
// # Start here
//
// Establishing trust — the control plane, run once by an operator or a pipeline
// with administrative credentials:
//
//	Setup(ctx, spec)     create or update a trust relationship
//	Validate(ctx, ref)   check a live relationship against what was configured
//	Delete(ctx, ref)     remove one, if cloud-auth created it
//
// Those three use a package-level manager with the default registry. For your
// own registry or state store, build one with NewManager and call its methods
// instead.
//
// The spec you pass to Setup is one of:
//
//	AWSRoleTrustOIDCSpec           an IAM role trusting an OIDC issuer
//	GCPWorkloadIdentityPoolSpec    a workload identity pool, provider and binding
//	AzureFederatedCredentialSpec   an Entra federated identity credential
//	K8sServiceAccountFederationSpec  a Kubernetes SA mapped to a cloud identity
//
// Every spec has a Validate method, and it is worth calling early: it refuses
// the configurations that look fine and are not — a trust with no subject
// condition, a workload identity pool bound to every identity in itself, an
// http issuer that cannot be pinned.
//
// Obtaining credentials — the data plane, run continuously by a workload with no
// static secrets — lives in the sibling packages, not here. This package
// contributes the types they exchange:
//
//	SourceToken   a proof of this workload's identity, pinned to one audience
//	Target        where credentials are wanted: AWSTarget, GCPTarget, AzureTarget
//	Credentials   short-lived native credentials from a target's STS
//	Selector      which runtime a workload is permitted to authenticate as
//
// See the source package to detect a runtime and mint a proof, target to
// exchange one, broker to do both, and adapters to plug the result into an
// AWS, Google or Azure SDK client.
//
// # Two things that will surprise you
//
// Credentials and SourceToken redact themselves. Printing one with %v, %+v,
// json.Marshal or slog gives you a redacted form, deliberately — the fields are
// exported because callers need them, and one careless log line should not write
// a secret access key to disk. Reveal returns the plaintext, and is named to be
// obvious in review.
//
// An unknown expiry counts as EXPIRED for Credentials and NOT expired for
// SourceToken. That asymmetry is intentional: credentials are an authority we
// act on, so an unparseable lifetime must fail closed, while an AWSSigV4 proof
// legitimately carries no exp claim at all and failing closed there would make
// every EC2 and ECS source unusable.
//
// # Reading a validation report
//
// ValidationReport answers two different questions and you almost always want
// both:
//
//	IsValid()      did anything fail?
//	IsComplete()   did everything that matters actually run?
//	HasChecks()    did anything run at all?
//
// A report with no checks is vacuously valid, and a skipped check proves
// nothing. Treat a mechanism as trustworthy only when all three agree.
//
// # Errors
//
// Failures carry a category, so a caller can branch without matching on message
// text: use CategoryOf and IsRetryable rather than inspecting strings. The data
// plane also exposes four sentinels for errors.Is — ErrNotThisRuntime,
// ErrNonFederatableSource, ErrNoFirstClassPath and ErrTrustMissing — and
// ErrRuntimeMismatch when a detected runtime is one the configuration forbids.
//
// # Writing a provider
//
// Implement LifecycleProvider and register it, from an init function or
// explicitly:
//
//	core.Register(myprovider.New())
//
// To make the core's trust-policy and permission checks run against your cloud
// rather than report "skipped", also implement TrustPolicySource and
// GrantedPolicySource. That is how this package reads provider state without
// importing providers: core is a leaf, providers import it, and the dependency
// is inverted through those two interfaces.
//
// # Example
//
//	spec := &core.AWSRoleTrustOIDCSpec{
//	    RoleName:        "github-deploy",
//	    AccountID:       "123456789012",
//	    OIDCProviderURL: "https://token.actions.githubusercontent.com",
//	    Audience:        "sts.amazonaws.com",
//	    Subject:         "repo:myorg/myrepo:ref:refs/heads/main",
//	    Source:          core.GitHubOIDC,
//	}
//
//	outputs, err := core.Setup(ctx, spec)
//	if err != nil {
//	    return err
//	}
//
//	report, err := core.Validate(ctx, outputs.Ref)
//	if err != nil {
//	    return err
//	}
//	if !report.HasChecks() || !report.IsValid() || !report.IsComplete() {
//	    for _, c := range report.FailedChecks() {
//	        log.Printf("failed: %s — %s", c.Name, c.Remediation)
//	    }
//	    for _, c := range report.SkippedChecks() {
//	        log.Printf("NOT VERIFIED: %s — %s", c.Name, c.Remediation)
//	    }
//	}
package core
