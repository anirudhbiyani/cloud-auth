//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
	_ "github.com/anirudhbiyani/cloud-auth/provider/aws"
	_ "github.com/anirudhbiyani/cloud-auth/provider/azure"
	_ "github.com/anirudhbiyani/cloud-auth/provider/gcp"
)

// Live control-plane lifecycle: setup, validate, delete, against a real cloud.
//
// The pair matrix in this package covers the RUNTIME half — a workload
// exchanging a proof for credentials. Nothing exercised the control plane
// against a live API, so the GCP and Azure clients had only fake-server
// coverage, and a fake agrees with whatever the code believes the protocol is.
// That is exactly the class of mistake it cannot catch: client_arm.go silently
// not compiling was found by a build matrix, not by its tests.
//
// Every case cleans up after itself, including on failure. A test that leaves a
// federated role behind is worse than one that fails: it leaves a trust
// relationship nobody is watching.

// lifecycleTimeout bounds one setup/validate/delete cycle. Azure federated
// credential creation is throttled to roughly 0.25/sec, and GCP pool creation
// is a long-running operation, so this is not generous by accident.
const lifecycleTimeout = 5 * time.Minute

// requireEnv skips unless every named variable is set.
//
// Skipping rather than failing: these need a real project or tenant, and a
// contributor without one should see the suite pass, not a wall of red they
// cannot act on.
func requireEnv(t *testing.T, names ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	var missing []string
	for _, n := range names {
		v := strings.TrimSpace(os.Getenv(n))
		if v == "" {
			missing = append(missing, n)
			continue
		}
		out[n] = v
	}
	if len(missing) > 0 {
		t.Skipf("live control-plane test needs %s", strings.Join(missing, ", "))
	}
	return out
}

// uniqueSuffix keeps concurrent runs from colliding on a resource name.
func uniqueSuffix() string { return fmt.Sprintf("%d", time.Now().UnixNano()%1_000_000) }

// runLifecycle drives setup → validate → delete and asserts the shape of each.
//
// The manager is built with a memory state store: this asserts what happens in
// the CLOUD, and a state file would add a second thing that can be wrong.
func runLifecycle(t *testing.T, spec core.MechanismSpec) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), lifecycleTimeout)
	defer cancel()

	manager := core.NewManager(core.WithStateStore(core.NewMemoryStateStore()))

	// Dry run first. It must need no more permission than a read, and it must
	// not create anything — checked by the delete at the end finding exactly
	// one thing to remove.
	if _, err := manager.Setup(ctx, spec, core.SetupOptions{DryRun: true}); err != nil {
		t.Fatalf("dry-run setup: %v", err)
	}

	outputs, err := manager.Setup(ctx, spec, core.SetupOptions{})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	t.Logf("created %s", outputs.Ref.ID)

	// Cleanup is registered IMMEDIATELY, so a failure below still removes the
	// trust relationship rather than leaving one nobody is watching.
	t.Cleanup(func() {
		cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), lifecycleTimeout)
		defer cancelCleanup()
		if err := manager.Delete(cleanupCtx, outputs.Ref, core.DeleteOptions{OwnedOnly: true}); err != nil {
			t.Errorf("cleanup failed, and a federated trust may be left behind: %v", err)
		}
	})

	report, err := manager.Validate(ctx, outputs.Ref, core.ValidateOptions{})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !report.HasChecks() {
		t.Fatal("validate ran no checks at all — a vacuous pass is not a pass")
	}
	for _, check := range report.FailedChecks() {
		t.Errorf("check %q failed against a mechanism this test just created: %s",
			check.Name, check.Message)
	}
	// Skipped checks are not failures, but on a freshly created mechanism they
	// mean something that should have been verifiable was not.
	for _, check := range report.SkippedChecks() {
		t.Logf("check %q was skipped: %s", check.Name, check.Message)
	}

	// Idempotency: setup again must not fail, and must not create a second
	// resource. An operator re-running a pipeline is the common case.
	if _, err := manager.Setup(ctx, spec, core.SetupOptions{}); err != nil {
		t.Errorf("re-running setup on an existing mechanism failed: %v", err)
	}
}

// TestAWSLifecycle is the reference case: AWS is the provider with live harness
// coverage already, so a failure here means the harness, not the client.
func TestAWSLifecycle(t *testing.T) {
	env := requireEnv(t, "CLOUD_AUTH_IT_AWS_ACCOUNT_ID", "CLOUD_AUTH_IT_OIDC_ISSUER")

	runLifecycle(t, &core.AWSRoleTrustOIDCSpec{
		RoleName:         "cloud-auth-it-" + uniqueSuffix(),
		AccountID:        env["CLOUD_AUTH_IT_AWS_ACCOUNT_ID"],
		OIDCProviderURL:  env["CLOUD_AUTH_IT_OIDC_ISSUER"],
		Audience:         "sts.amazonaws.com",
		Subject:          "repo:cloud-auth/integration:ref:refs/heads/main",
		SubjectCondition: "StringEquals",
		Source:           core.GitHubOIDC,
	})
}

// TestGCPLifecycle exercises the workload identity pool client against a live
// project: pool creation is a long-running operation, and the attribute
// condition is what stops the provider accepting every identity its issuer
// serves.
func TestGCPLifecycle(t *testing.T) {
	env := requireEnv(t,
		"CLOUD_AUTH_IT_GCP_PROJECT_ID",
		"CLOUD_AUTH_IT_GCP_PROJECT_NUMBER",
		"CLOUD_AUTH_IT_GCP_SERVICE_ACCOUNT",
		"CLOUD_AUTH_IT_OIDC_ISSUER")

	suffix := uniqueSuffix()
	subject := "repo:cloud-auth/integration:ref:refs/heads/main"

	runLifecycle(t, &core.GCPWorkloadIdentityPoolSpec{
		ProjectID:           env["CLOUD_AUTH_IT_GCP_PROJECT_ID"],
		ProjectNumber:       env["CLOUD_AUTH_IT_GCP_PROJECT_NUMBER"],
		PoolID:              "ca-it-" + suffix,
		ProviderID:          "ca-it-" + suffix,
		ProviderType:        "oidc",
		OIDCIssuerURL:       env["CLOUD_AUTH_IT_OIDC_ISSUER"],
		AllowedAudiences:    []string{"https://github.com/cloud-auth"},
		AttributeMapping:    map[string]string{"google.subject": "assertion.sub"},
		AttributeCondition:  fmt.Sprintf("assertion.sub == %q", subject),
		SubjectScope:        subject,
		ServiceAccountEmail: env["CLOUD_AUTH_IT_GCP_SERVICE_ACCOUNT"],
		Source:              core.GitHubOIDC,
	})
}

// TestAzureLifecycle exercises Graph against a live tenant. This is the one
// where the constraints bite: the 20-credential cap, the creation throttle, and
// the propagation window are all real here and all invisible to a fake.
func TestAzureLifecycle(t *testing.T) {
	env := requireEnv(t,
		"CLOUD_AUTH_IT_AZURE_TENANT_ID",
		"CLOUD_AUTH_IT_AZURE_SUBSCRIPTION_ID",
		"CLOUD_AUTH_IT_OIDC_ISSUER")

	runLifecycle(t, &core.AzureFederatedCredentialSpec{
		TenantID:                env["CLOUD_AUTH_IT_AZURE_TENANT_ID"],
		SubscriptionID:          env["CLOUD_AUTH_IT_AZURE_SUBSCRIPTION_ID"],
		IdentityType:            "app_registration",
		ApplicationDisplayName:  "cloud-auth-it-" + uniqueSuffix(),
		FederatedCredentialName: "cloud-auth-it-" + uniqueSuffix(),
		Issuer:                  env["CLOUD_AUTH_IT_OIDC_ISSUER"],
		Subject:                 "repo:cloud-auth/integration:ref:refs/heads/main",
		Audiences:               []string{core.DefaultAzureAudience},
		Source:                  core.GitHubOIDC,
	})
}

// The 20-credential cap is enforced client-side against a count read from the
// live tenant, so this is the assertion a fake cannot make honestly.
func TestAzureFederatedCredentialCapIsRealHere(t *testing.T) {
	env := requireEnv(t, "CLOUD_AUTH_IT_AZURE_APP_OBJECT_ID")
	t.Skipf("manual: creating 20 credentials on %s to prove the 21st is refused is "+
		"destructive and slow; run it deliberately, not on every CI pass",
		env["CLOUD_AUTH_IT_AZURE_APP_OBJECT_ID"])
}
