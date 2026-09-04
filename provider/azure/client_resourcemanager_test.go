package azure

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// The ARM half. A user-assigned managed identity carries federated credentials
// exactly as an application does, and every constraint that applies to the
// Graph path applies here too — the cap, the wildcards, the creation throttle.
// Those were asserted for applications and not for identities, which is the
// half an AKS workload actually uses.

const (
	testSub = "22222222-2222-2222-2222-222222222222"
	testRG  = "rg"
	testMI  = "uami"
)

// identityPath is the ARM path of the test identity's credential collection.
func identityPath(suffix string) string {
	return fmt.Sprintf(
		"/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ManagedIdentity/userAssignedIdentities/%s%s",
		testSub, testRG, testMI, suffix)
}

func micred(name string) *FederatedIdentityCredential {
	return &FederatedIdentityCredential{
		Name: name, Issuer: "https://oidc.prod-aks.azure.com/tenant/",
		Subject:   "system:serviceaccount:payments:ledger",
		Audiences: []string{core.DefaultAzureAudience},
	}
}

func TestManagedIdentityFederatedCredentialLifecycle(t *testing.T) {
	f := newFakeAzure(t)

	f.handle(identityPath("/federatedIdentityCredentials"), func(w http.ResponseWriter, r *http.Request) {
		f.json(w, http.StatusOK, map[string]any{"value": []any{}})
	})
	f.handle(identityPath("/federatedIdentityCredentials/aks-ledger"),
		func(w http.ResponseWriter, r *http.Request) {
			// ARM nests the credential under "properties"; Graph does not, and
			// sending the Graph shape here creates a credential with no issuer.
			if r.Method == http.MethodPut {
				body := f.lastJSON()
				props, ok := body["properties"].(map[string]any)
				if !ok {
					t.Errorf("ARM body is not nested under properties: %s", f.body())
				} else if props["issuer"] == nil || props["subject"] == nil {
					t.Errorf("issuer/subject missing from properties: %v", props)
				}
			}
			f.json(w, http.StatusOK, map[string]any{
				"id":   identityPath("/federatedIdentityCredentials/aks-ledger"),
				"name": "aks-ledger",
				"properties": map[string]any{
					"issuer":    "https://oidc.prod-aks.azure.com/tenant/",
					"subject":   "system:serviceaccount:payments:ledger",
					"audiences": []string{core.DefaultAzureAudience},
				},
			})
		})

	c := f.client(t)
	ctx := context.Background()

	created, err := c.CreateManagedIdentityFederatedCredential(ctx, testSub, testRG, testMI,
		micred("aks-ledger"))
	if err != nil {
		t.Fatalf("CreateManagedIdentityFederatedCredential: %v", err)
	}
	if created.Name != "aks-ledger" || created.Subject == "" {
		t.Errorf("created = %+v", created)
	}

	got, err := c.GetManagedIdentityFederatedCredential(ctx, testSub, testRG, testMI, "aks-ledger")
	if err != nil {
		t.Fatalf("GetManagedIdentityFederatedCredential: %v", err)
	}
	if got.Issuer != "https://oidc.prod-aks.azure.com/tenant/" {
		t.Errorf("Issuer = %q — the ARM response nests these under properties", got.Issuer)
	}

	if err := c.DeleteManagedIdentityFederatedCredential(ctx, testSub, testRG, testMI, "aks-ledger"); err != nil {
		t.Fatalf("DeleteManagedIdentityFederatedCredential: %v", err)
	}
}

// The 20-credential cap is per RESOURCE, so it applies to a managed identity
// just as to an application. Asserting it only for applications left the half
// an AKS workload uses unchecked.
func TestManagedIdentityCapIsEnforcedToo(t *testing.T) {
	f := newFakeAzure(t)

	existing := make([]map[string]any, maxFederatedCredentials)
	for i := range existing {
		existing[i] = map[string]any{"name": fmt.Sprintf("cred-%d", i)}
	}
	f.handle(identityPath("/federatedIdentityCredentials"), func(w http.ResponseWriter, _ *http.Request) {
		f.json(w, http.StatusOK, map[string]any{"value": existing})
	})
	f.handle(identityPath("/federatedIdentityCredentials/twenty-first"),
		func(http.ResponseWriter, *http.Request) {
			t.Error("the credential was created despite the cap")
		})

	_, err := f.client(t).CreateManagedIdentityFederatedCredential(
		context.Background(), testSub, testRG, testMI, micred("twenty-first"))
	if err == nil {
		t.Fatal("want an error at the cap")
	}
	if !strings.Contains(err.Error(), "20 federated identity credentials") {
		t.Errorf("error should name the count and limit: %v", err)
	}
}

// Wildcards are rejected on this path too: Azure matches literally, so a
// wildcard creates a credential that never matches a token.
func TestManagedIdentityRejectsWildcards(t *testing.T) {
	cred := micred("aks-*")
	_, err := f0(t).CreateManagedIdentityFederatedCredential(
		context.Background(), testSub, testRG, testMI, cred)
	if err == nil {
		t.Fatal("want a refusal for a wildcard name")
	}
	if !strings.Contains(err.Error(), "literal") {
		t.Errorf("error = %v", err)
	}
}

// f0 is a client whose fake answers nothing: validation must refuse before any
// request is made, so no handler is needed.
func f0(t *testing.T) *restClient {
	t.Helper()
	return newFakeAzure(t).client(t)
}

// Creation is paced on the ARM path as well. Azure throttles per resource, and
// a loop over namespaces hits it exactly as a loop over repositories does.
func TestManagedIdentityCreationIsPaced(t *testing.T) {
	f := newFakeAzure(t)
	var inFlight, maxInFlight atomic.Int32

	f.handle(identityPath("/federatedIdentityCredentials"), func(w http.ResponseWriter, _ *http.Request) {
		f.json(w, http.StatusOK, map[string]any{"value": []any{}})
	})
	f.mux.HandleFunc(identityPath("/federatedIdentityCredentials/"),
		func(w http.ResponseWriter, _ *http.Request) {
			n := inFlight.Add(1)
			for {
				old := maxInFlight.Load()
				if n <= old || maxInFlight.CompareAndSwap(old, n) {
					break
				}
			}
			time.Sleep(3 * time.Millisecond)
			inFlight.Add(-1)
			f.json(w, http.StatusOK, map[string]any{"id": "x", "name": "y"})
		})

	c := f.client(t)
	var waited []time.Duration
	c.sleep = func(_ context.Context, d time.Duration) error {
		waited = append(waited, d)
		return nil
	}

	done := make(chan error, 3)
	for i := range 3 {
		go func() {
			_, err := c.CreateManagedIdentityFederatedCredential(
				context.Background(), testSub, testRG, testMI,
				micred(fmt.Sprintf("cred-%d", i)))
			done <- err
		}()
	}
	for range 3 {
		if err := <-done; err != nil {
			t.Fatalf("create: %v", err)
		}
	}

	if got := maxInFlight.Load(); got > 1 {
		t.Errorf("%d creates were in flight at once; ARM throttles per resource too", got)
	}
	if len(waited) == 0 {
		t.Error("no pacing delay was applied on the ARM path")
	}
}

func TestManagedIdentityCRUD(t *testing.T) {
	f := newFakeAzure(t)
	f.handle(identityPath(""), func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && f.lastJSON()["location"] == nil {
			t.Error("a managed identity was created with no location")
		}
		f.json(w, http.StatusOK, map[string]any{
			"id": identityPath(""), "name": testMI, "location": "eastus",
			"properties": map[string]any{
				"principalId": "principal-1", "clientId": "client-1", "tenantId": "tenant-1",
			},
		})
	})

	c := f.client(t)
	ctx := context.Background()

	mi, err := c.CreateManagedIdentity(ctx, testSub, testRG, testMI, "eastus")
	if err != nil {
		t.Fatalf("CreateManagedIdentity: %v", err)
	}
	if mi.PrincipalID != "principal-1" || mi.ClientID != "client-1" {
		t.Errorf("identity = %+v — the ARM response nests these under properties", mi)
	}
	if mi.ResourceGroup != testRG {
		t.Errorf("ResourceGroup = %q, want it carried through", mi.ResourceGroup)
	}

	if _, err := c.GetManagedIdentity(ctx, testSub, testRG, testMI); err != nil {
		t.Fatalf("GetManagedIdentity: %v", err)
	}
	if err := c.DeleteManagedIdentity(ctx, testSub, testRG, testMI); err != nil {
		t.Fatalf("DeleteManagedIdentity: %v", err)
	}
}

// A location is required, and refusing before the call beats ARM's own message.
func TestCreateManagedIdentityRequiresALocation(t *testing.T) {
	_, err := f0(t).CreateManagedIdentity(context.Background(), testSub, testRG, testMI, "")
	if err == nil {
		t.Fatal("want an error with no location")
	}
	if !strings.Contains(err.Error(), "location is required") {
		t.Errorf("error = %v", err)
	}
}

func TestRoleAssignmentListAndDelete(t *testing.T) {
	f := newFakeAzure(t)
	scope := "/subscriptions/" + testSub + "/resourceGroups/" + testRG

	var gotFilter string
	f.handle(scope+"/providers/Microsoft.Authorization/roleAssignments",
		func(w http.ResponseWriter, r *http.Request) {
			gotFilter = r.URL.Query().Get("$filter")
			f.json(w, http.StatusOK, map[string]any{"value": []map[string]any{{
				"id": "ra-1",
				"properties": map[string]any{
					"roleDefinitionId": "/roleDefinitions/reader",
					"principalId":      "principal-1",
					"scope":            scope,
				},
			}}})
		})
	f.handle(scope+"/providers/Microsoft.Authorization/roleAssignments/ra-1",
		func(w http.ResponseWriter, _ *http.Request) {
			f.json(w, http.StatusOK, map[string]any{})
		})

	c := f.client(t)
	ctx := context.Background()

	assignments, err := c.ListRoleAssignments(ctx, scope, "principal-1")
	if err != nil {
		t.Fatalf("ListRoleAssignments: %v", err)
	}
	if len(assignments) != 1 || assignments[0].PrincipalID != "principal-1" {
		t.Errorf("assignments = %+v", assignments)
	}
	// Filtering server-side matters: a subscription can hold thousands of
	// assignments and filtering client-side would page through all of them.
	if !strings.Contains(gotFilter, "principalId eq 'principal-1'") {
		t.Errorf("$filter = %q, want a principalId filter", gotFilter)
	}

	if err := c.DeleteRoleAssignment(ctx, scope, "ra-1"); err != nil {
		t.Fatalf("DeleteRoleAssignment: %v", err)
	}

	t.Run("no principal means no filter", func(t *testing.T) {
		if _, err := c.ListRoleAssignments(ctx, scope, ""); err != nil {
			t.Fatalf("ListRoleAssignments: %v", err)
		}
		if gotFilter != "" {
			t.Errorf("$filter = %q, want none when no principal is named", gotFilter)
		}
	})
}

// An ARM scope arrives with a leading slash and the base URL ends without one.
// Joining them naively produces a double slash, which ARM answers with a 400
// that says nothing about the URL.
func TestARMScopeIsNormalized(t *testing.T) {
	for _, scope := range []string{
		"/subscriptions/sub",
		"subscriptions/sub",
		"///subscriptions/sub",
	} {
		if got := trimLeadingSlash(scope); strings.HasPrefix(got, "/") {
			t.Errorf("trimLeadingSlash(%q) = %q, still leading with a slash", scope, got)
		}
	}
}

// Reading IMDS belongs to the data plane, where source/azure.go already does it
// behind the check that matters: IDENTITY_ENDPOINT must be loopback or
// link-local before the IDENTITY_HEADER secret is sent. A second copy of a
// security control is a second place for it to rot.
func TestManagedIdentityTokenIsDeliberatelyNotImplemented(t *testing.T) {
	_, err := f0(t).GetManagedIdentityToken(context.Background(),
		&GetManagedIdentityTokenInput{Resource: "https://management.azure.com/"})
	if err == nil {
		t.Fatal("want a refusal")
	}
	if !strings.Contains(err.Error(), "runtime concern") {
		t.Errorf("the refusal does not explain where this belongs: %v", err)
	}
	if !strings.Contains(err.Error(), "cloud-auth exchange") {
		t.Errorf("the refusal offers nowhere to go: %v", err)
	}
}
