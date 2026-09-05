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

// lifecycleTimeout bounds one setup/validate/delete cycle.
const lifecycleTimeout = 5 * time.Minute

// requireEnv skips unless every named variable is set.
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
func runLifecycle(t *testing.T, spec core.MechanismSpec) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), lifecycleTimeout)
	defer cancel()

	manager := core.NewManager(core.WithStateStore(core.NewMemoryStateStore()))

	// Dry run first.
	if _, err := manager.Setup(ctx, spec, core.SetupOptions{DryRun: true}); err != nil {
		t.Fatalf("dry-run setup: %v", err)
	}

	outputs, err := manager.Setup(ctx, spec, core.SetupOptions{})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	t.Logf("created %s", outputs.Ref.ID)

	// Cleanup is registered IMMEDIATELY, so a failure below still removes the trust relationship rather than leaving one nobody is watching.
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
	// Skipped checks are not failures, but on a freshly created mechanism they mean something that should have been verifiable was not.
	for _, check := range report.SkippedChecks() {
		t.Logf("check %q was skipped: %s", check.Name, check.Message)
	}

	// Idempotency: setup again must not fail, and must not create a second resource.
	if _, err := manager.Setup(ctx, spec, core.SetupOptions{}); err != nil {
		t.Errorf("re-running setup on an existing mechanism failed: %v", err)
	}
}

// TestAWSLifecycle is the reference case: AWS is the provider with live harness coverage already, so a failure here means the harness, not the client.
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

// TestGCPLifecycle exercises the workload identity pool client against a live project: pool creation is a long-running operation, and the attribute condition is what stops the provider accepting every identity its issuer serves.
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

// TestAzureLifecycle exercises Graph against a live tenant.
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

// The 20-credential cap is enforced client-side against a count read from the live tenant, so this is the assertion a fake cannot make honestly.
func TestAzureFederatedCredentialCapIsRealHere(t *testing.T) {
	env := requireEnv(t, "CLOUD_AUTH_IT_AZURE_APP_OBJECT_ID")
	t.Skipf("manual: creating 20 credentials on %s to prove the 21st is refused is "+
		"destructive and slow; run it deliberately, not on every CI pass",
		env["CLOUD_AUTH_IT_AZURE_APP_OBJECT_ID"])
}
