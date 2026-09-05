package azure

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// The app-registration half of Setup, the counterpart to the managed-identity tests.

type recordingGraph struct {
	GraphClient

	existing *Application // returned by GetApplication when non-nil
	getErr   error
	spErr    error
	credErr  error

	created  []string // resource types created, in order
	deleted  []string // object ids deleted, in order
	sawCred  *FederatedIdentityCredential
	credApp  string // the app id CreateFederatedIdentityCredential was addressed with
	appSeqNo int
}

func (g *recordingGraph) GetApplication(context.Context, string) (*Application, error) {
	if g.getErr != nil {
		return nil, g.getErr
	}
	return g.existing, nil
}

func (g *recordingGraph) CreateApplication(_ context.Context, app *Application) (*Application, error) {
	g.appSeqNo++
	g.created = append(g.created, "application")
	return &Application{
		ID:          "obj-1",
		AppID:       "client-1",
		DisplayName: app.DisplayName,
	}, nil
}

func (g *recordingGraph) DeleteApplication(_ context.Context, id string) error {
	g.deleted = append(g.deleted, id)
	return nil
}

func (g *recordingGraph) CreateServicePrincipal(context.Context, string) (*ServicePrincipal, error) {
	if g.spErr != nil {
		return nil, g.spErr
	}
	g.created = append(g.created, "service-principal")
	return &ServicePrincipal{ID: "sp-1"}, nil
}

func (g *recordingGraph) CreateFederatedIdentityCredential(_ context.Context, appID string, cred *FederatedIdentityCredential) (*FederatedIdentityCredential, error) {
	if g.credErr != nil {
		return nil, g.credErr
	}
	g.created = append(g.created, "federated-credential")
	g.credApp = appID
	g.sawCred = cred
	return &FederatedIdentityCredential{ID: "fic-1"}, nil
}

func (g *recordingGraph) DeleteFederatedIdentityCredential(_ context.Context, _, credID string) error {
	g.deleted = append(g.deleted, credID)
	return nil
}

func appSpec(mutate func(*core.AzureFederatedCredentialSpec)) *core.AzureFederatedCredentialSpec {
	s := &core.AzureFederatedCredentialSpec{
		IdentityType:            "app_registration",
		TenantID:                "11111111-1111-1111-1111-111111111111",
		ApplicationDisplayName:  "cloud-auth-deploy",
		FederatedCredentialName: "github-main",
		Issuer:                  "https://token.actions.githubusercontent.com",
		Subject:                 "repo:acme/api:ref:refs/heads/main",
	}
	if mutate != nil {
		mutate(s)
	}
	return s
}

func setupApp(t *testing.T, g *recordingGraph, a ARMClient, spec *core.AzureFederatedCredentialSpec, opts core.SetupOptions) (*core.Outputs, error) {
	t.Helper()
	p := New(WithGraphClient(g), WithARMClient(a))
	return p.Setup(context.Background(), spec, opts)
}

func TestSetupAppRegistrationCreatesAllThreeObjects(t *testing.T) {
	g := &recordingGraph{}
	out, err := setupApp(t, g, &recordingARM{}, appSpec(nil), core.SetupOptions{})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}

	want := []string{"application", "service-principal", "federated-credential"}
	if strings.Join(g.created, ",") != strings.Join(want, ",") {
		t.Errorf("created %v, want %v in that order", g.created, want)
	}
	// The credential must be addressed by the OBJECT id, not the client id.
	if g.credApp != "obj-1" {
		t.Errorf("credential addressed to %q, want the object id obj-1", g.credApp)
	}
	if !out.Ref.Owned {
		t.Error("Ref.Owned = false — we created the application, so delete may reclaim it")
	}
	// Azure's own default audience, applied because the spec named none.
	if got := g.sawCred.Audiences; len(got) != 1 || got[0] != "api://AzureADTokenExchange" {
		t.Errorf("audiences = %v, want the Azure default", got)
	}
	if out.Ref.ResourceIDs["expected_subject"] != "repo:acme/api:ref:refs/heads/main" {
		t.Errorf("intent not recorded: %v", out.Ref.ResourceIDs)
	}
}

// Rollback.
func TestSetupAppRegistrationRollsBackWhatItCreated(t *testing.T) {
	boom := errors.New("insufficient privileges")

	for name, g := range map[string]*recordingGraph{
		"service principal fails": {spErr: boom},
		"credential fails":        {credErr: boom},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := setupApp(t, g, &recordingARM{}, appSpec(nil), core.SetupOptions{}); err == nil {
				t.Fatal("want an error")
			}
			if len(g.deleted) != 1 || g.deleted[0] != "obj-1" {
				t.Errorf("deleted %v, want the application we created rolled back", g.deleted)
			}
		})
	}
}

func TestSetupAppRegistrationNeverDeletesAPreexistingApplication(t *testing.T) {
	g := &recordingGraph{
		existing: &Application{ID: "theirs", AppID: "their-client"},
		credErr:  errors.New("insufficient privileges"),
	}
	spec := appSpec(func(s *core.AzureFederatedCredentialSpec) {
		s.ApplicationDisplayName = ""
		s.ApplicationID = "their-client"
	})

	if _, err := setupApp(t, g, &recordingARM{}, spec, core.SetupOptions{}); err == nil {
		t.Fatal("want an error")
	}
	if len(g.deleted) != 0 {
		t.Errorf("deleted %v — the application was the operator's, not ours", g.deleted)
	}
}

// Graph exposes appId and id as different identifiers.
func TestSetupAppRegistrationRefusesAnApplicationWithNoObjectID(t *testing.T) {
	g := &recordingGraph{existing: &Application{AppID: "their-client"}}
	spec := appSpec(func(s *core.AzureFederatedCredentialSpec) {
		s.ApplicationDisplayName = ""
		s.ApplicationID = "their-client"
	})

	_, err := setupApp(t, g, &recordingARM{}, spec, core.SetupOptions{})
	if err == nil {
		t.Fatal("want an error, not a credential call against an empty id")
	}
	if !strings.Contains(err.Error(), "object id") {
		t.Errorf("error = %v, want it to name the missing object id", err)
	}
}

func TestSetupAppRegistrationDryRunCreatesNothing(t *testing.T) {
	g := &recordingGraph{}
	out, err := setupApp(t, g, &recordingARM{}, appSpec(nil), core.SetupOptions{DryRun: true})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if len(g.created) != 0 || len(g.deleted) != 0 {
		t.Errorf("dry run touched the tenant: created=%v deleted=%v", g.created, g.deleted)
	}
	if out.Values["plan"] == "" {
		t.Error("a dry run must still say what it would do")
	}
}

func TestSetupRejectsAnUnknownIdentityType(t *testing.T) {
	spec := appSpec(func(s *core.AzureFederatedCredentialSpec) { s.IdentityType = "service_account" })
	if _, err := setupApp(t, &recordingGraph{}, &recordingARM{}, spec, core.SetupOptions{}); err == nil {
		t.Fatal("want an error for an unknown identity_type")
	}
}

// Delete.
func TestDeleteIsIdempotentAndRespectsOwnership(t *testing.T) {
	ref := func(owned bool) core.MechanismRef {
		return core.MechanismRef{
			Type:  core.MechanismAzureFederatedCredential,
			Owned: owned,
			ResourceIDs: map[string]string{
				"app_object_id":           "obj-1",
				"federated_credential_id": "fic-1",
			},
		}
	}

	t.Run("owned deletes the application too", func(t *testing.T) {
		g := &recordingGraph{}
		p := New(WithGraphClient(g), WithARMClient(&recordingARM{}))
		if err := p.Delete(context.Background(), ref(true), core.DeleteOptions{}); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if strings.Join(g.deleted, ",") != "fic-1,obj-1" {
			t.Errorf("deleted %v, want the credential then the application", g.deleted)
		}
	})

	t.Run("not owned leaves the application alone", func(t *testing.T) {
		g := &recordingGraph{}
		p := New(WithGraphClient(g), WithARMClient(&recordingARM{}))
		if err := p.Delete(context.Background(), ref(false), core.DeleteOptions{}); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if strings.Join(g.deleted, ",") != "fic-1" {
			t.Errorf("deleted %v — the application was not ours", g.deleted)
		}
	})

	t.Run("dry run deletes nothing", func(t *testing.T) {
		g := &recordingGraph{}
		p := New(WithGraphClient(g), WithARMClient(&recordingARM{}))
		if err := p.Delete(context.Background(), ref(true), core.DeleteOptions{DryRun: true}); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if len(g.deleted) != 0 {
			t.Errorf("dry run deleted %v", g.deleted)
		}
	})
}

// The two cross-cloud token paths.
func TestGenerateCrossCloudTokens(t *testing.T) {
	expiry := time.Now().Add(time.Hour).Truncate(time.Second)
	tc := &fakeTokenClient{token: "eyJ-mi", expires: expiry}
	p := New(WithTokenClient(tc))

	t.Run("aws", func(t *testing.T) {
		out, err := p.GenerateAWSRoleAssumptionToken(context.Background(), &AWSRoleAssumptionInput{
			TenantID: "t", ClientID: "c", RoleARN: "arn:aws:iam::1:role/r",
			UseManagedIdentity: true,
		})
		if err != nil {
			t.Fatalf("GenerateAWSRoleAssumptionToken: %v", err)
		}
		// AWS STS validates the audience; anything else is rejected at exchange.
		if tc.sawResource != "sts.amazonaws.com" {
			t.Errorf("resource = %q, want the STS audience", tc.sawResource)
		}
		if out.Token != "eyJ-mi" || !out.ExpiresAt.Equal(expiry) {
			t.Errorf("output = %+v", out)
		}
		if out.Issuer != "https://login.microsoftonline.com/t/v2.0" {
			t.Errorf("issuer = %q", out.Issuer)
		}
	})

	t.Run("gcp", func(t *testing.T) {
		out, err := p.GenerateGCPWorkloadIdentityToken(context.Background(), &GCPWorkloadIdentityInput{
			TenantID: "t", ClientID: "c", ProjectNumber: "123", PoolID: "pool",
			ProviderID: "azure", UseManagedIdentity: true,
		})
		if err != nil {
			t.Fatalf("GenerateGCPWorkloadIdentityToken: %v", err)
		}
		// GCP's audience is the provider's full resource name, and it must match character for character or the exchange fails with no useful detail.
		want := "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/azure"
		if out.Audience != want {
			t.Errorf("audience = %q, want %q", out.Audience, want)
		}
	})
}

func TestGenerateCrossCloudTokensRefuseBadInput(t *testing.T) {
	full := &AWSRoleAssumptionInput{TenantID: "t", ClientID: "c", RoleARN: "r", UseManagedIdentity: true}
	fullGCP := &GCPWorkloadIdentityInput{
		TenantID: "t", ClientID: "c", ProjectNumber: "p", PoolID: "l",
		ProviderID: "v", UseManagedIdentity: true,
	}

	t.Run("no token client", func(t *testing.T) {
		p := New()
		if _, err := p.GenerateAWSRoleAssumptionToken(context.Background(), full); err == nil {
			t.Error("aws: want an error with no token client")
		}
		if _, err := p.GenerateGCPWorkloadIdentityToken(context.Background(), fullGCP); err == nil {
			t.Error("gcp: want an error with no token client")
		}
	})

	p := New(WithTokenClient(&fakeTokenClient{token: "x"}))

	t.Run("nil input", func(t *testing.T) {
		// These are exported methods.
		if _, err := p.GenerateAWSRoleAssumptionToken(context.Background(), nil); err == nil {
			t.Error("aws: want an error, not a panic")
		}
		if _, err := p.GenerateGCPWorkloadIdentityToken(context.Background(), nil); err == nil {
			t.Error("gcp: want an error, not a panic")
		}
	})

	for name, in := range map[string]*AWSRoleAssumptionInput{
		"no tenant":   {ClientID: "c", RoleARN: "r", UseManagedIdentity: true},
		"no client":   {TenantID: "t", RoleARN: "r", UseManagedIdentity: true},
		"no role arn": {TenantID: "t", ClientID: "c", UseManagedIdentity: true},
		// Not a missing field: an app registration has no way to obtain a token off-Azure, so it is refused rather than half-attempted.
		"app registration": {TenantID: "t", ClientID: "c", RoleARN: "r"},
	} {
		t.Run("aws/"+name, func(t *testing.T) {
			if _, err := p.GenerateAWSRoleAssumptionToken(context.Background(), in); err == nil {
				t.Errorf("want an error for %s", name)
			}
		})
	}

	for name, in := range map[string]*GCPWorkloadIdentityInput{
		"no tenant":        {ClientID: "c", ProjectNumber: "p", PoolID: "l", ProviderID: "v", UseManagedIdentity: true},
		"no client":        {TenantID: "t", ProjectNumber: "p", PoolID: "l", ProviderID: "v", UseManagedIdentity: true},
		"no project":       {TenantID: "t", ClientID: "c", PoolID: "l", ProviderID: "v", UseManagedIdentity: true},
		"no pool":          {TenantID: "t", ClientID: "c", ProjectNumber: "p", ProviderID: "v", UseManagedIdentity: true},
		"no provider":      {TenantID: "t", ClientID: "c", ProjectNumber: "p", PoolID: "l", UseManagedIdentity: true},
		"app registration": {TenantID: "t", ClientID: "c", ProjectNumber: "p", PoolID: "l", ProviderID: "v"},
	} {
		t.Run("gcp/"+name, func(t *testing.T) {
			if _, err := p.GenerateGCPWorkloadIdentityToken(context.Background(), in); err == nil {
				t.Errorf("want an error for %s", name)
			}
		})
	}
}

func TestGenerateCrossCloudTokensSurfaceTheIMDSError(t *testing.T) {
	p := New(WithTokenClient(&fakeTokenClient{err: errors.New("imds refused")}))

	_, err := p.GenerateAWSRoleAssumptionToken(context.Background(), &AWSRoleAssumptionInput{
		TenantID: "t", ClientID: "c", RoleARN: "r", UseManagedIdentity: true,
	})
	if err == nil || !strings.Contains(err.Error(), "imds refused") {
		t.Errorf("error = %v, want the underlying cause preserved", err)
	}
}

type fakeTokenClient struct {
	TokenClient
	token       string
	expires     time.Time
	err         error
	sawResource string
}

func (c *fakeTokenClient) GetManagedIdentityToken(_ context.Context, in *GetManagedIdentityTokenInput) (*GetManagedIdentityTokenOutput, error) {
	c.sawResource = in.Resource
	if c.err != nil {
		return nil, c.err
	}
	return &GetManagedIdentityTokenOutput{AccessToken: c.token, ExpiresOn: c.expires}, nil
}
