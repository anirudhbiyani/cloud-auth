package azure

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// The managed-identity setup path — the one an AKS workload uses — had no test
// at all. What matters here is not that it creates things, but what it does
// when a step half-way through fails: an identity left behind with no federated
// credential is an orphan nobody will clean up, and an identity marked as ours
// when it was not is one this tool will later delete out from under somebody.

// recordingARM records every mutation so a test can assert what was and was not
// done, including on the rollback paths.
type recordingARM struct {
	ARMClient

	existing *ManagedIdentity

	created         []string
	deleted         []string
	createdCreds    []string
	roleAssignments []string

	createIdentityErr error
	createCredErr     error
	roleAssignErr     error
}

func (r *recordingARM) GetManagedIdentity(_ context.Context, _, _, name string) (*ManagedIdentity, error) {
	if r.existing != nil && r.existing.Name == name {
		return r.existing, nil
	}
	return nil, errors.New("not found")
}

func (r *recordingARM) CreateManagedIdentity(_ context.Context, _, rg, name, location string) (*ManagedIdentity, error) {
	if r.createIdentityErr != nil {
		return nil, r.createIdentityErr
	}
	r.created = append(r.created, name)
	return &ManagedIdentity{
		ID: "/subscriptions/sub/resourceGroups/" + rg + "/providers/Microsoft.ManagedIdentity/" +
			"userAssignedIdentities/" + name,
		Name: name, ResourceGroup: rg, Location: location,
		ClientID: "client-" + name, PrincipalID: "principal-" + name,
	}, nil
}

func (r *recordingARM) DeleteManagedIdentity(_ context.Context, _, _, name string) error {
	r.deleted = append(r.deleted, name)
	return nil
}

func (r *recordingARM) CreateManagedIdentityFederatedCredential(_ context.Context, _, _, _ string, cred *FederatedIdentityCredential) (*FederatedIdentityCredential, error) {
	if r.createCredErr != nil {
		return nil, r.createCredErr
	}
	r.createdCreds = append(r.createdCreds, cred.Name)
	out := *cred
	out.ID = "cred-" + cred.Name
	return &out, nil
}

func (r *recordingARM) CreateRoleAssignment(_ context.Context, scope, roleDef, principal string) error {
	if r.roleAssignErr != nil {
		return r.roleAssignErr
	}
	r.roleAssignments = append(r.roleAssignments, roleDef+"@"+scope+"/"+principal)
	return nil
}

func miSpec(mutate func(*core.AzureFederatedCredentialSpec)) *core.AzureFederatedCredentialSpec {
	s := &core.AzureFederatedCredentialSpec{
		TenantID:                "11111111-1111-1111-1111-111111111111",
		SubscriptionID:          "22222222-2222-2222-2222-222222222222",
		ResourceGroup:           "rg",
		IdentityType:            "managed_identity",
		ManagedIdentityName:     "aks-ledger",
		CreateManagedIdentity:   true,
		FederatedCredentialName: "payments",
		Issuer:                  "https://oidc.prod-aks.azure.com/tenant/",
		Subject:                 "system:serviceaccount:payments:ledger",
		Audiences:               []string{core.DefaultAzureAudience},
		Source:                  core.Kubernetes,
	}
	if mutate != nil {
		mutate(s)
	}
	return s
}

func TestSetupManagedIdentityCreatesAndRecordsIntent(t *testing.T) {
	arm := &recordingARM{}
	outputs, err := New(WithGraphClient(&listingGraph{}), WithARMClient(arm)).
		Setup(context.Background(), miSpec(nil), core.SetupOptions{})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}

	if len(arm.created) != 1 || len(arm.createdCreds) != 1 {
		t.Fatalf("created identities %v, credentials %v", arm.created, arm.createdCreds)
	}

	// Ownership gates deletion. Marking a pre-existing identity as ours is how
	// this tool would later delete something it did not create.
	if !outputs.Ref.Owned {
		t.Error("Owned = false for an identity this run created")
	}

	// The intent has to be recorded, or the trust-policy validator has nothing
	// to compare the live credential against and reports skipped forever.
	for key, want := range map[string]string{
		"expected_issuer":   "https://oidc.prod-aks.azure.com/tenant/",
		"expected_subject":  "system:serviceaccount:payments:ledger",
		"expected_audience": core.DefaultAzureAudience,
	} {
		if got := outputs.Ref.ResourceIDs[key]; got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	// Entra matches case-sensitively, so the recorded values must be verbatim.
	if outputs.Ref.ResourceIDs["expected_subject"] != miSpec(nil).Subject {
		t.Error("the recorded subject was normalized; Entra compares it case-sensitively")
	}
}

// The rollback that matters: an identity created by this run, whose federated
// credential then fails, must be removed. Leaving it is an orphan nobody will
// clean up, and it can authenticate as soon as somebody adds a credential.
func TestSetupManagedIdentityRollsBackAnIdentityItCreated(t *testing.T) {
	arm := &recordingARM{createCredErr: errors.New("Authorization_RequestDenied")}

	_, err := New(WithGraphClient(&listingGraph{}), WithARMClient(arm)).
		Setup(context.Background(), miSpec(nil), core.SetupOptions{})
	if err == nil {
		t.Fatal("want an error when the federated credential cannot be created")
	}

	if len(arm.created) != 1 {
		t.Fatalf("created = %v", arm.created)
	}
	if len(arm.deleted) != 1 || arm.deleted[0] != "aks-ledger" {
		t.Errorf("deleted = %v; an identity created by this run must be rolled back when the "+
			"credential fails", arm.deleted)
	}
}

// The other half, and the one that would be destructive if wrong: a
// PRE-EXISTING identity must never be deleted by a failed run. It belongs to
// somebody else, and other workloads may already federate through it.
func TestSetupManagedIdentityNeverDeletesAPreexistingIdentity(t *testing.T) {
	arm := &recordingARM{
		existing: &ManagedIdentity{
			Name: "aks-ledger", ResourceGroup: "rg",
			ID: "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ManagedIdentity/" +
				"userAssignedIdentities/aks-ledger",
			ClientID: "client-x", PrincipalID: "principal-x",
		},
		createCredErr: errors.New("Authorization_RequestDenied"),
	}

	_, err := New(WithGraphClient(&listingGraph{}), WithARMClient(arm)).
		Setup(context.Background(), miSpec(nil), core.SetupOptions{})
	if err == nil {
		t.Fatal("want an error")
	}
	if len(arm.deleted) != 0 {
		t.Errorf("deleted %v — a pre-existing identity was destroyed by a failed run, and other "+
			"workloads may federate through it", arm.deleted)
	}
	if len(arm.created) != 0 {
		t.Errorf("created %v when the identity already existed", arm.created)
	}
}

// An identity that does not exist and was not asked to be created is a
// not-found, not a silent creation.
func TestSetupManagedIdentityRefusesWhenAbsentAndNotAskedToCreate(t *testing.T) {
	arm := &recordingARM{}
	_, err := New(WithGraphClient(&listingGraph{}), WithARMClient(arm)).
		Setup(context.Background(), miSpec(func(s *core.AzureFederatedCredentialSpec) {
			s.CreateManagedIdentity = false
		}), core.SetupOptions{})
	if err == nil {
		t.Fatal("want a not-found error")
	}
	if !core.IsCategory(err, core.ErrCategoryNotFound) {
		t.Errorf("category = %v, want not_found", core.CategoryOf(err))
	}
	if len(arm.created) != 0 {
		t.Errorf("created %v without being asked to", arm.created)
	}
}

// A failed role assignment must NOT fail the setup — the trust is established
// and working — but it must be surfaced, because the identity can now
// authenticate without the permissions the spec asked for. Silence there is the
// dangerous outcome: it looks like success.
func TestRoleAssignmentFailuresAreWarnedNotFatal(t *testing.T) {
	arm := &recordingARM{roleAssignErr: errors.New("Authorization_RequestDenied")}

	outputs, err := New(WithGraphClient(&listingGraph{}), WithARMClient(arm)).
		Setup(context.Background(), miSpec(func(s *core.AzureFederatedCredentialSpec) {
			s.RoleAssignments = []core.AzureRoleAssignment{
				{RoleDefinitionID: "/roleDefinitions/reader", Scope: "/subscriptions/sub"},
			}
		}), core.SetupOptions{})
	if err != nil {
		t.Fatalf("a failed role assignment aborted the setup: %v", err)
	}
	if outputs == nil {
		t.Fatal("no outputs")
	}
	if len(arm.createdCreds) != 1 {
		t.Error("the federated credential was not created")
	}
}

func TestRoleAssignmentWarnings(t *testing.T) {
	if got := roleAssignmentWarnings(nil); got != nil {
		t.Errorf("no failures should produce no warnings, got %v", got)
	}

	warnings := roleAssignmentWarnings([]error{
		errors.New("role reader on scope /subscriptions/sub: denied"),
		errors.New("role writer on scope /subscriptions/sub: denied"),
	})
	if len(warnings) != 3 {
		t.Fatalf("got %d lines, want a header plus one per failure: %v", len(warnings), warnings)
	}
	// The header has to say what the state actually is, not just that something
	// failed: the identity exists and can authenticate, without the permissions.
	if !strings.Contains(warnings[0], "can authenticate without having the permissions") {
		t.Errorf("the warning does not say what the resulting state is: %q", warnings[0])
	}
}

// A dry run must not create anything, and must still produce a plan naming
// every resource it would touch.
func TestSetupManagedIdentityDryRunCreatesNothing(t *testing.T) {
	arm := &recordingARM{}
	outputs, err := New(WithGraphClient(&listingGraph{}), WithARMClient(arm)).
		Setup(context.Background(), miSpec(func(s *core.AzureFederatedCredentialSpec) {
			s.RoleAssignments = []core.AzureRoleAssignment{
				{RoleDefinitionID: "/roleDefinitions/reader", Scope: "/subscriptions/sub"},
			}
		}), core.SetupOptions{DryRun: true})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}

	if len(arm.created) != 0 || len(arm.createdCreds) != 0 || len(arm.roleAssignments) != 0 {
		t.Errorf("a dry run mutated: identities %v, credentials %v, roles %v",
			arm.created, arm.createdCreds, arm.roleAssignments)
	}
	// Three planned actions: the identity, the credential, the role assignment.
	if !strings.Contains(outputs.Values["plan"], "3 resources") {
		t.Errorf("plan = %q, want it to name every resource it would touch",
			outputs.Values["plan"])
	}
	// A dry run creates nothing, so it owns nothing.
	if outputs.Ref.Owned {
		t.Error("a dry run reported ownership of a resource it did not create")
	}
}

func TestRecordExpectedTrust(t *testing.T) {
	t.Run("a nil spec is a no-op", func(t *testing.T) {
		ids := map[string]string{}
		recordExpectedTrust(ids, nil)
		if len(ids) != 0 {
			t.Errorf("ids = %v", ids)
		}
	})

	t.Run("empty fields are not recorded as empty strings", func(t *testing.T) {
		// An empty recorded value is not the same as an unrecorded one: the
		// validator treats a missing expectation as "nothing to compare" and
		// skips, while an empty one would compare against "" and fail.
		ids := map[string]string{}
		recordExpectedTrust(ids, &core.AzureFederatedCredentialSpec{})
		if len(ids) != 0 {
			t.Errorf("ids = %v, want nothing recorded for an empty spec", ids)
		}
	})

	t.Run("only the first audience is recorded", func(t *testing.T) {
		ids := map[string]string{}
		recordExpectedTrust(ids, &core.AzureFederatedCredentialSpec{
			Issuer: "https://issuer", Subject: "sub",
			Audiences: []string{"first", "second"},
		})
		if ids["expected_audience"] != "first" {
			t.Errorf("expected_audience = %q", ids["expected_audience"])
		}
	})
}
