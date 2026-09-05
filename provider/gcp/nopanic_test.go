package gcp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// A library must not panic on a supported call, and must not report a vacuous pass.

// unreachable returns a provider whose client resolution has already failed.
func unreachable() *Provider {
	p := New()
	p.resolveFailed = errors.New("test: credentials deliberately unavailable")
	return p
}

func TestNoExportedMethodPanicsWithoutClients(t *testing.T) {
	// A short deadline: some of these reach for real credentials, and a host without them can spend a long time in a resolver.
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

// Validate is separated out because its contract is the opposite of the others': an error is NOT required.
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

// The claim the old comment made, now actually tested: init() registers this provider into the default registry, which is how core.Setup and friends reach it.
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

// unsupportedSpec is deliberately a spec no provider handles: Setup must reject it cleanly rather than reaching a client.
type unsupportedSpec struct{}

func (unsupportedSpec) Type() core.MechanismType   { return core.MechanismType("unsupported") }
func (unsupportedSpec) Validate() error            { return nil }
func (unsupportedSpec) SourceProvider() core.Cloud { return core.Cloud("none") }
func (unsupportedSpec) TargetProvider() core.Cloud { return core.Cloud("none") }
