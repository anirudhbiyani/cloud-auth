package gcp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// A library must not panic on a supported call, and must not report a vacuous
// pass. This is deliberately a structural test rather than one per method: the
// bug it guards is "somebody added an entry point and forgot the client guard",
// and only a test that walks every entry point catches that.
//
// The file used to claim in this comment that it reached the provider "through
// core.Setup / Validate / Delete on the global registry — which is the
// documented API", while every call went to New() directly. The registry path
// was never exercised. It is now covered by its own test below, separately,
// because the two are different properties: one is "no entry point panics", the
// other is "init() actually put this provider where callers look for it".

// unreachable returns a provider whose client resolution has already failed.
//
// Pinning that is what keeps this file meaningful. Since the provider gained a
// real client it resolves credentials lazily, so a bare New() on a developer
// machine that has logged in would configure itself and these assertions would
// quietly stop testing anything.
func unreachable() *Provider {
	p := New()
	p.resolveFailed = errors.New("test: credentials deliberately unavailable")
	return p
}

func TestNoExportedMethodPanicsWithoutClients(t *testing.T) {
	// A short deadline: some of these reach for real credentials, and a host
	// without them can spend a long time in a resolver. Either a configuration
	// error or a deadline is an acceptable outcome; a panic is not.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	ref := testRef()

	calls := map[string]func() error{
		"Setup": func() error {
			_, err := unreachable().Setup(ctx, unsupportedSpec{}, core.SetupOptions{})
			return err
		},
		"Delete": func() error {
			return unreachable().Delete(ctx, ref, core.DeleteOptions{})
		},
		"TrustPolicy": func() error {
			_, err := unreachable().TrustPolicy(ctx, ref)
			return err
		},
		"GrantedPolicies": func() error {
			_, err := unreachable().GrantedPolicies(ctx, ref)
			return err
		},
	}

	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s panicked on an unconfigured provider: %v", name, r)
				}
			}()
			if err := call(); err == nil {
				t.Errorf("%s returned no error on an unconfigured provider", name)
			}
		})
	}
}

// Validate is separated out because its contract is the opposite of the others':
// an error is NOT required. A report describing failed or skipped checks is the
// correct outcome for a provider that cannot reach its cloud.
//
// What it must never do is report a VACUOUS pass — "nothing failed" because
// nothing ran. That distinction used to be expressed by returning a sentinel
// named errUnverified, which carried a success message through the error channel
// to satisfy an outer "must return an error" check. It worked and it read
// backwards; here the assertion simply says what it means.
func TestValidateNeverReportsAVacuousPass(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Validate panicked on an unconfigured provider: %v", r)
		}
	}()

	report, err := unreachable().Validate(ctx, testRef(), core.ValidateOptions{})
	if err != nil {
		return // refusing outright is a fine answer
	}
	if report == nil {
		t.Fatal("Validate returned no report and no error")
	}
	if report.IsValid() && report.IsComplete() && !report.HasChecks() {
		t.Error("Validate reported a clean bill of health with no checks run — " +
			"\"nothing failed\" is not \"everything passed\"")
	}
}

// The claim the old comment made, now actually tested: init() registers this
// provider into the default registry, which is how core.Setup and friends reach
// it. If the init() were dropped, every direct-instance test above would still
// pass and the documented API would be broken.
func TestProviderIsReachableThroughTheDefaultRegistry(t *testing.T) {
	p, err := core.GetLifecycleProviderFromRegistry(core.GCP)
	if err != nil {
		t.Fatalf("provider is not in the default registry: %v", err)
	}
	if p == nil {
		t.Fatal("registry returned a nil provider")
	}
	if _, ok := p.(*Provider); !ok {
		t.Errorf("registry holds a %T, want *Provider from this package", p)
	}
	if p.Name() != core.GCP {
		t.Errorf("registered under %q, want %q", p.Name(), core.GCP)
	}
}

// testRef is a mechanism reference carrying THIS cloud's resource ids.
//
// It used to be one map copied between packages, so the AWS file carried GCP
// pool paths and an Azure tenant id. Harmless, but it made the fixture read as
// though those ids meant something here.
func testRef() core.MechanismRef {
	return core.MechanismRef{
		ID:       "test-ref",
		Provider: New().Name(),
		ResourceIDs: map[string]string{
			"pool_name":             "projects/1/locations/global/workloadIdentityPools/p",
			"provider_name":         "projects/1/locations/global/workloadIdentityPools/p/providers/x",
			"service_account_email": "sa@proj.iam.gserviceaccount.com",
			"project_id":            "proj",
			"project_number":        "123456789012",
		},
	}
}

// unsupportedSpec is deliberately a spec no provider handles: Setup must reject
// it cleanly rather than reaching a client.
type unsupportedSpec struct{}

func (unsupportedSpec) Type() core.MechanismType   { return core.MechanismType("unsupported") }
func (unsupportedSpec) Validate() error            { return nil }
func (unsupportedSpec) SourceProvider() core.Cloud { return core.Cloud("none") }
func (unsupportedSpec) TargetProvider() core.Cloud { return core.Cloud("none") }
