package vault

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// A library must not panic on a supported call. init() registers a provider with
// no client, so these are reachable through core.Setup / Validate / Delete on
// the global registry — which is the documented API.
//
// This is deliberately a structural test rather than one per method: the bug it
// guards is "somebody added an entry point and forgot the client guard", and
// only a test that walks every entry point catches that.
//
// This file did not exist until Vault gained a real client. It was one of the
// two providers whose nil guards were newest and least exercised — which is
// exactly the wrong pair to leave unguarded.
//
// unreachable() pins the condition the test is about: since the provider now
// builds its own client from VAULT_ADDR and VAULT_TOKEN, a bare New() on a
// machine that has those set would configure itself, and this file would quietly
// stop testing anything.
func TestNoExportedMethodPanicsWithoutClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	ref := core.MechanismRef{
		ID:       "test-ref",
		Provider: New().Name(),
		ResourceIDs: map[string]string{
			"auth_path":     "jwt",
			"role_name":     "some-role",
			"mount_path":    "aws",
			"policy_name":   "some-policy",
			"engine_path":   "aws",
			"vault_address": "https://vault.example.com",
		},
	}

	calls := map[string]func() error{
		"Setup": func() error {
			_, err := unreachable().Setup(ctx, unsupportedSpec{}, core.SetupOptions{})
			return err
		},
		// Validate is allowed to succeed: a report describing failed checks is
		// the correct outcome, not an error. What it must never do is report a
		// vacuous pass — "nothing failed" because nothing ran.
		"Validate": func() error {
			report, err := unreachable().Validate(ctx, ref, core.ValidateOptions{})
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
			return unreachable().Delete(ctx, ref, core.DeleteOptions{})
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

// unreachable returns a provider whose client resolution has already failed,
// which is the state this file exists to exercise.
func unreachable() *Provider {
	p := New()
	p.resolveFailed = errors.New("test: VAULT_ADDR deliberately unset")
	return p
}
