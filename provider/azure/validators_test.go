package azure

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// The three existence validators had no tests. They decide whether `validate`
// reports a mechanism as sound, so a validator that passes wrongly is worse
// than no validator: it turns "unverified" into "verified", which is precisely
// the vacuous pass this project's own nopanic tests guard against elsewhere.

type validatorGraph struct {
	GraphClient
	app     *Application
	cred    *FederatedIdentityCredential
	appErr  error
	credErr error
}

func (s validatorGraph) GetApplication(context.Context, string) (*Application, error) {
	return s.app, s.appErr
}
func (s validatorGraph) GetFederatedIdentityCredential(context.Context, string, string) (*FederatedIdentityCredential, error) {
	return s.cred, s.credErr
}

type validatorARM struct {
	ARMClient
	mi    *ManagedIdentity
	miErr error
}

func (s validatorARM) GetManagedIdentity(context.Context, string, string, string) (*ManagedIdentity, error) {
	return s.mi, s.miErr
}

func TestAppExistsValidator(t *testing.T) {
	ref := core.MechanismRef{ID: "r"}

	t.Run("present", func(t *testing.T) {
		v := &appExistsValidator{
			client: validatorGraph{app: &Application{ID: "app-1", DisplayName: "deploy"}},
			appID:  "app-1",
		}
		check := v.Validate(context.Background(), ref)
		if check.Status != core.CheckStatusPassed {
			t.Errorf("status = %v, want passed", check.Status)
		}
		if check.Evidence["display_name"] != "deploy" {
			t.Errorf("evidence = %v, want the app named", check.Evidence)
		}
	})

	t.Run("absent", func(t *testing.T) {
		v := &appExistsValidator{
			client: validatorGraph{appErr: errors.New("Request_ResourceNotFound")},
			appID:  "app-1",
		}
		check := v.Validate(context.Background(), ref)
		if check.Status != core.CheckStatusFailed {
			t.Fatalf("status = %v, want failed", check.Status)
		}
		// Critical, and the severity is what decides whether the report is
		// invalid: only Error and above count.
		if check.Severity != core.SeverityCritical {
			t.Errorf("severity = %v, want critical — a missing application means nothing "+
				"can authenticate", check.Severity)
		}
		if check.Remediation == "" {
			t.Error("a failed check with no remediation tells nobody what to do")
		}
		if check.Evidence["error"] == nil {
			t.Error("the cause was not recorded as evidence")
		}
	})
}

func TestFederatedCredentialExistsValidator(t *testing.T) {
	ref := core.MechanismRef{ID: "r"}

	t.Run("present records the trust it found", func(t *testing.T) {
		v := &federatedCredentialExistsValidator{
			client: validatorGraph{cred: &FederatedIdentityCredential{
				Name: "gh", Issuer: "https://token.actions.githubusercontent.com",
				Subject: "repo:myorg/myrepo:ref:refs/heads/main",
			}},
			appID: "app-1", credID: "cred-1",
		}
		check := v.Validate(context.Background(), ref)
		if check.Status != core.CheckStatusPassed {
			t.Fatalf("status = %v", check.Status)
		}
		// The issuer and subject go into evidence, which is what makes a
		// passing check reviewable rather than merely green.
		if check.Evidence["issuer"] == nil || check.Evidence["subject"] == nil {
			t.Errorf("evidence = %v, want the issuer and subject recorded", check.Evidence)
		}
	})

	t.Run("absent", func(t *testing.T) {
		v := &federatedCredentialExistsValidator{
			client: validatorGraph{credErr: errors.New("not found")},
			appID:  "app-1", credID: "cred-1",
		}
		check := v.Validate(context.Background(), ref)
		if check.Status != core.CheckStatusFailed {
			t.Errorf("status = %v, want failed", check.Status)
		}
		if check.Severity != core.SeverityCritical {
			t.Errorf("severity = %v, want critical", check.Severity)
		}
	})
}

func TestManagedIdentityExistsValidator(t *testing.T) {
	ref := core.MechanismRef{ID: "r"}

	t.Run("present", func(t *testing.T) {
		v := &managedIdentityExistsValidator{
			client: validatorARM{mi: &ManagedIdentity{
				Name: "uami", ClientID: "client-1", PrincipalID: "principal-1",
			}},
			subscriptionID: "sub", resourceGroup: "rg", identityName: "uami",
		}
		check := v.Validate(context.Background(), ref)
		if check.Status != core.CheckStatusPassed {
			t.Errorf("status = %v, want passed", check.Status)
		}
	})

	t.Run("absent", func(t *testing.T) {
		v := &managedIdentityExistsValidator{
			client:         validatorARM{miErr: errors.New("ResourceNotFound")},
			subscriptionID: "sub", resourceGroup: "rg", identityName: "uami",
		}
		check := v.Validate(context.Background(), ref)
		if check.Status != core.CheckStatusFailed {
			t.Errorf("status = %v, want failed", check.Status)
		}
	})
}

// Every validator must identify itself, or a report's checks cannot be told
// apart and --format json is unparseable by check.
func TestValidatorIdentityIsPopulated(t *testing.T) {
	validators := []core.Validator{
		&appExistsValidator{client: validatorGraph{}},
		&federatedCredentialExistsValidator{client: validatorGraph{}},
		&managedIdentityExistsValidator{client: validatorARM{}},
		core.NewSubjectBreadthValidator(nil),
	}

	seen := map[string]bool{}
	for _, v := range validators {
		if v.ID() == "" || v.Name() == "" || v.Description() == "" {
			t.Errorf("%T has an empty ID, Name or Description", v)
		}
		if seen[v.ID()] {
			t.Errorf("%T reuses the id %q; two checks with one id cannot be told apart", v, v.ID())
		}
		seen[v.ID()] = true

		// And the check it produces must carry that identity, not just the
		// validator.
		check := v.Validate(context.Background(), core.MechanismRef{ID: "r"})
		if check.ID != v.ID() {
			t.Errorf("%T produced a check with id %q, want %q", v, check.ID, v.ID())
		}
	}
}

// Capabilities is what `cloud-auth providers` prints and what the registry
// filters on, so an empty or inconsistent set makes the provider invisible.
func TestCapabilities(t *testing.T) {
	p := New()
	caps := p.Capabilities()
	if len(caps) == 0 {
		t.Fatal("no capabilities declared")
	}

	for _, want := range []core.Capability{
		core.CapabilitySetup, core.CapabilityValidate,
		core.CapabilityDelete, core.CapabilityDryRun,
	} {
		if !p.HasCapability(want) {
			t.Errorf("HasCapability(%v) = false, but the provider implements it", want)
		}
	}
	if p.HasCapability(core.Capability("not-a-capability")) {
		t.Error("HasCapability returned true for a capability that does not exist")
	}

	// Every declared capability must answer true, or the two disagree about
	// the same provider.
	for _, c := range caps {
		if !p.HasCapability(c) {
			t.Errorf("Capabilities lists %v but HasCapability says false", c)
		}
	}
}

// Same-cloud token generation is out of scope by design — the PRD lists it as a
// non-goal — and the refusal must say so rather than fail obscurely.
func TestSameCloudTokenGenerationIsRefused(t *testing.T) {
	p := New()
	ctx := context.Background()

	for name, call := range map[string]func() error{
		"AWS role assumption": func() error {
			_, err := p.GenerateAWSRoleAssumptionToken(ctx, &AWSRoleAssumptionInput{})
			return err
		},
		"GCP workload identity": func() error {
			_, err := p.GenerateGCPWorkloadIdentityToken(ctx, &GCPWorkloadIdentityInput{})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); err == nil {
				t.Error("want an error: this provider has no token client configured")
			} else if strings.TrimSpace(err.Error()) == "" {
				t.Error("the refusal says nothing")
			}
		})
	}
}

// A client returning a nil object with a NIL error is a real answer shape — a
// 200 with an empty body, or a client returning a zero value — and every one of
// these validators dereferenced it. That panics inside a validator, which is
// the one place it must not: a validate over several mechanisms would take the
// whole command down rather than report one bad check.
//
// Skipped rather than passed, and skipped rather than failed: nothing was
// verified, and "we could not tell" is neither "it is there" nor "it is gone".
func TestValidatorsSurviveANilResultWithNoError(t *testing.T) {
	ref := core.MechanismRef{ID: "r"}

	for name, v := range map[string]core.Validator{
		"application":          &appExistsValidator{client: validatorGraph{}, appID: "app-1"},
		"federated credential": &federatedCredentialExistsValidator{client: validatorGraph{}, appID: "a", credID: "c"},
		"managed identity":     &managedIdentityExistsValidator{client: validatorARM{}, identityName: "uami"},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("the %s validator panicked on a nil result: %v", name, r)
				}
			}()

			check := v.Validate(context.Background(), ref)
			if check.Status != core.CheckStatusSkipped {
				t.Errorf("status = %v, want skipped — nothing was verified", check.Status)
			}
			if !strings.Contains(check.Message, "NOT verified") {
				t.Errorf("message = %q, want it to say plainly that nothing was checked",
					check.Message)
			}
		})
	}
}

// Validate assembles the validator set from what the ref actually records.
// The assembly is the logic worth pinning: a ref missing its expected_* keys
// must not silently drop the trust-match check and still report a green run —
// that is the vacuous pass this project treats as worse than no check at all.
func TestValidateBuildsItsChecksFromTheRef(t *testing.T) {
	p := New(
		WithGraphClient(validatorGraph{
			app:  &Application{ID: "obj-1", DisplayName: "deploy"},
			cred: &FederatedIdentityCredential{ID: "fic-1", Issuer: "https://i", Subject: "s"},
		}),
		WithARMClient(validatorARM{mi: &ManagedIdentity{Name: "uami", PrincipalID: "p"}}),
	)

	for _, tc := range []struct {
		name  string
		ids   map[string]string
		names []string
	}{
		{
			name: "application only",
			ids:  map[string]string{"app_object_id": "obj-1"},
			// No credential id recorded, so no credential check — and the report
			// must not imply the credential was verified.
			names: []string{"Application Exists"},
		},
		{
			name: "application and credential",
			ids: map[string]string{
				"app_object_id":           "obj-1",
				"federated_credential_id": "fic-1",
			},
			names: []string{"Application Exists", "Federated Credential Exists"},
		},
		{
			name:  "managed identity",
			ids:   map[string]string{"identity_name": "uami", "subscription_id": "s", "resource_group": "rg"},
			names: []string{"Managed Identity Exists"},
		},
		{
			name: "recorded intent adds the trust and breadth checks",
			ids: map[string]string{
				"app_object_id":     "obj-1",
				"expected_issuer":   "https://token.actions.githubusercontent.com",
				"expected_subject":  "repo:acme/api:ref:refs/heads/main",
				"expected_audience": "api://AzureADTokenExchange",
			},
			names: []string{"Application Exists", "Trust Policy Match", "Subject Breadth"},
		},
		{
			// A type this provider does not own contributes no validators. An
			// empty report is honest; a passed one would not be.
			name:  "unknown mechanism type",
			ids:   map[string]string{"app_object_id": "obj-1"},
			names: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			typ := core.MechanismAzureFederatedCredential
			if tc.name == "unknown mechanism type" {
				typ = core.MechanismAWSRoleTrustOIDC
			}

			report, err := p.Validate(context.Background(),
				core.MechanismRef{ID: "r", Type: typ, ResourceIDs: tc.ids},
				core.ValidateOptions{})
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if len(report.Checks) != len(tc.names) {
				var got []string
				for _, c := range report.Checks {
					got = append(got, c.Name)
				}
				t.Fatalf("checks = %v, want %v", got, tc.names)
			}
			for i, want := range tc.names {
				if report.Checks[i].Name != want {
					t.Errorf("check %d = %q, want %q", i, report.Checks[i].Name, want)
				}
			}
		})
	}
}
