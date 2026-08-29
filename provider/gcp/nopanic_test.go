package gcp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// A library must not panic on a supported call. init() registers a provider with
// no clients, so these are reachable through core.Setup / Validate / Delete on
// the global registry — which is the documented API.
//
// This is deliberately a structural test rather than one per method: the bug it
// guards is "somebody added an entry point and forgot the client guard", and
// only a test that walks every entry point catches that.
func TestNoExportedMethodPanicsWithoutClients(t *testing.T) {
	// A short deadline, because some of these reach for real credentials and a
	// host without them can spend minutes in the AWS IMDS resolver. Either a
	// configuration error or a deadline is an acceptable outcome here; a panic
	// is not.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	ref := core.MechanismRef{
		ID:       "test-ref",
		Provider: New().Name(),
		ResourceIDs: map[string]string{
			"role_name":               "some-role",
			"pool_name":               "projects/1/locations/global/workloadIdentityPools/p",
			"provider_name":           "projects/1/locations/global/workloadIdentityPools/p/providers/x",
			"service_account_email":   "sa@proj.iam.gserviceaccount.com",
			"project_id":              "proj",
			"app_object_id":           "00000000-0000-0000-0000-000000000000",
			"federated_credential_id": "cred",
			"identity_name":           "uami",
			"subscription_id":         "sub",
			"resource_group":          "rg",
			"tenant_id":               "11111111-1111-1111-1111-111111111111",
		},
	}

	calls := map[string]func() error{
		"Setup": func() error {
			_, err := New().Setup(ctx, unsupportedSpec{}, core.SetupOptions{})
			return err
		},
		// Validate is allowed to succeed: a report describing failed checks is
		// the correct outcome, not an error. What it must never do is report a
		// vacuous pass — "nothing failed" because nothing ran.
		"Validate": func() error {
			report, err := New().Validate(ctx, ref, core.ValidateOptions{})
			if err != nil {
				return err
			}
			if report == nil {
				return errNilReport
			}
			if report.HasChecks() && report.IsValid() && report.IsComplete() {
				return nil // genuinely fine
			}
			return errUnverified
		},
		"Delete": func() error {
			return New().Delete(ctx, ref, core.DeleteOptions{})
		},
		"TrustPolicy": func() error {
			_, err := New().TrustPolicy(ctx, ref)
			return err
		},
		"GrantedPolicies": func() error {
			_, err := New().GrantedPolicies(ctx, ref)
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

var (
	errNilReport  = errors.New("Validate returned no report and no error")
	errUnverified = errors.New("Validate reported an unverified or failing mechanism, as expected")
)

// unsupportedSpec is deliberately a spec no provider handles: Setup must reject
// it cleanly rather than reaching a client.
type unsupportedSpec struct{}

func (unsupportedSpec) Type() core.MechanismType   { return core.MechanismType("unsupported") }
func (unsupportedSpec) Validate() error            { return nil }
func (unsupportedSpec) SourceProvider() core.Cloud { return core.Cloud("none") }
func (unsupportedSpec) TargetProvider() core.Cloud { return core.Cloud("none") }
