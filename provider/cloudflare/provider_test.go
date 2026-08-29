package cloudflare

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// fakeAPI records what the provider asked for and returns whatever the test
// arranges. Recording matters as much as returning: several of the checks below
// are about which calls happen and in what order, not about the reply.
type fakeAPI struct {
	APIClient

	createdTokens []string
	createdApps   []string
	deletedApps   []string
	deletedTokens []string
	// order records every mutating call, so deletion order can be asserted.
	order []string

	token   *AccessServiceToken
	app     *AccessApplication
	getErr  error
	makeErr error
	delErr  error
}

func (f *fakeAPI) CreateAccessServiceToken(_ context.Context, accountID, name string, duration int) (*AccessServiceToken, error) {
	f.order = append(f.order, "create-token")
	if f.makeErr != nil {
		return nil, f.makeErr
	}
	f.createdTokens = append(f.createdTokens, name)
	tok := &AccessServiceToken{
		ID: "tok-1", Name: name, ClientID: "client-id-value",
		ClientSecret: "client-secret-value",
		ExpiresAt:    time.Now().Add(time.Duration(duration) * 24 * time.Hour).Unix(),
	}
	if f.token != nil {
		tok = f.token
	}
	return tok, nil
}

func (f *fakeAPI) GetAccessServiceToken(_ context.Context, accountID, tokenID string) (*AccessServiceToken, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.token != nil {
		return f.token, nil
	}
	return &AccessServiceToken{ID: tokenID, Name: "n", ClientID: "client-id-value", ExpiresAt: 42}, nil
}

func (f *fakeAPI) DeleteAccessServiceToken(_ context.Context, accountID, tokenID string) error {
	f.order = append(f.order, "delete-token")
	f.deletedTokens = append(f.deletedTokens, tokenID)
	return f.delErr
}

func (f *fakeAPI) CreateAccessApplication(_ context.Context, accountID string, app *AccessApplication) (*AccessApplication, error) {
	f.order = append(f.order, "create-app")
	if f.makeErr != nil {
		return nil, f.makeErr
	}
	f.createdApps = append(f.createdApps, app.Name)
	if f.app != nil {
		return f.app, nil
	}
	return &AccessApplication{ID: "app-1", Name: app.Name, Domain: app.Domain}, nil
}

func (f *fakeAPI) DeleteAccessApplication(_ context.Context, accountID, appID string) error {
	f.order = append(f.order, "delete-app")
	f.deletedApps = append(f.deletedApps, appID)
	return f.delErr
}

func accessSpec() *CloudflareAccessSpec {
	return &CloudflareAccessSpec{
		AccountID: "acct-123",
		TokenName: "ci-deploy",
		Source:    core.GitHubOIDC,
	}
}

func TestCloudflareSpecValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*CloudflareAccessSpec)
		wantErr string
	}{
		{"valid", func(*CloudflareAccessSpec) {}, ""},
		{"no account", func(s *CloudflareAccessSpec) { s.AccountID = "" }, "account_id is required"},
		{"no token name", func(s *CloudflareAccessSpec) { s.TokenName = "" }, "token_name is required"},
		{"negative duration", func(s *CloudflareAccessSpec) { s.TokenDuration = -1 }, "must be positive"},
		{"explicit duration", func(s *CloudflareAccessSpec) { s.TokenDuration = 30 }, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := accessSpec()
			tc.mutate(s)
			err := s.Validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("want valid, got %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("want %q, got nil", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("want %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestCloudflareSetupCreatesTheToken(t *testing.T) {
	api := &fakeAPI{}
	p := New(WithAPIClient(api))

	out, err := p.Setup(context.Background(), accessSpec(), core.SetupOptions{})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if len(api.createdTokens) != 1 || api.createdTokens[0] != "ci-deploy" {
		t.Errorf("created tokens = %v, want one named ci-deploy", api.createdTokens)
	}
	if out.Ref.ResourceIDs["token_id"] != "tok-1" {
		t.Errorf("token_id not recorded: %v", out.Ref.ResourceIDs)
	}
	if out.Ref.ResourceIDs["account_id"] != "acct-123" {
		t.Errorf("account_id not recorded: %v", out.Ref.ResourceIDs)
	}
}

// A dry run must not touch the account. This is the property an operator relies
// on when checking what a change would do.
func TestCloudflareDryRunMakesNoCalls(t *testing.T) {
	api := &fakeAPI{}
	p := New(WithAPIClient(api))

	if _, err := p.Setup(context.Background(), accessSpec(), core.SetupOptions{DryRun: true}); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if len(api.order) != 0 {
		t.Errorf("dry run performed calls: %v", api.order)
	}
}

// The client secret is only ever returned by the create call, so if a SecretSink
// is configured it must receive it — and it must not appear in the outputs.
func TestCloudflareSetupRoutesTheSecretToTheSink(t *testing.T) {
	api := &fakeAPI{}
	sink := &recordingSink{}
	p := New(WithAPIClient(api))

	out, err := p.Setup(context.Background(), accessSpec(), core.SetupOptions{SecretSink: sink})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if len(sink.stored) != 1 {
		t.Fatalf("secret sink received %d secrets, want 1", len(sink.stored))
	}
	if got := string(sink.stored[0]); got != "client-secret-value" {
		t.Errorf("sink received %q, want the client secret", got)
	}
	for k, v := range out.Values {
		if strings.Contains(v, "client-secret-value") {
			t.Errorf("output %q leaked the client secret", k)
		}
	}
}

func TestCloudflareSetupRejectsAForeignSpec(t *testing.T) {
	p := New(WithAPIClient(&fakeAPI{}))
	_, err := p.Setup(context.Background(), &core.AWSRoleTrustOIDCSpec{}, core.SetupOptions{})
	if err == nil {
		t.Fatal("want an error for a spec this provider does not handle")
	}
	if !strings.Contains(err.Error(), "unsupported spec type") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCloudflareSetupSurfacesACreateFailure(t *testing.T) {
	api := &fakeAPI{makeErr: errors.New("403 forbidden")}
	p := New(WithAPIClient(api))

	if _, err := p.Setup(context.Background(), accessSpec(), core.SetupOptions{}); err == nil {
		t.Fatal("want the create failure to surface")
	}
}

// The application depends on the token, so deletion must go application-first or
// Cloudflare refuses the token delete.
func TestCloudflareDeleteRemovesApplicationBeforeToken(t *testing.T) {
	api := &fakeAPI{}
	p := New(WithAPIClient(api))

	ref := core.MechanismRef{
		ResourceIDs: map[string]string{
			"account_id":     "acct-123",
			"application_id": "app-1",
			"token_id":       "tok-1",
		},
	}
	if err := p.Delete(context.Background(), ref, core.DeleteOptions{}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	want := []string{"delete-app", "delete-token"}
	if len(api.order) != 2 || api.order[0] != want[0] || api.order[1] != want[1] {
		t.Errorf("deletion order = %v, want %v", api.order, want)
	}
}

// Delete is documented as idempotent, so an already-absent resource is success.
func TestCloudflareDeleteIsIdempotent(t *testing.T) {
	api := &fakeAPI{delErr: errors.New("404 not found")}
	p := New(WithAPIClient(api))

	ref := core.MechanismRef{
		ResourceIDs: map[string]string{"account_id": "a", "token_id": "tok-1"},
	}
	if err := p.Delete(context.Background(), ref, core.DeleteOptions{}); err != nil {
		t.Errorf("deleting an absent token should succeed, got %v", err)
	}
}

func TestCloudflareDeleteDryRunMakesNoCalls(t *testing.T) {
	api := &fakeAPI{}
	p := New(WithAPIClient(api))
	ref := core.MechanismRef{ResourceIDs: map[string]string{"token_id": "tok-1"}}

	if err := p.Delete(context.Background(), ref, core.DeleteOptions{DryRun: true}); err != nil {
		t.Fatal(err)
	}
	if len(api.order) != 0 {
		t.Errorf("dry run deleted things: %v", api.order)
	}
}

// GetServiceTokenCredentials must never claim to return a secret: Cloudflare does
// not vend it after creation, and a caller that believed otherwise would ship an
// empty header.
func TestGetServiceTokenCredentialsNeverReturnsASecret(t *testing.T) {
	api := &fakeAPI{token: &AccessServiceToken{
		ID: "tok-1", Name: "n", ClientID: "client-id-value",
		ClientSecret: "should-not-be-propagated", ExpiresAt: 1700000000,
	}}
	p := New(WithAPIClient(api))

	creds, err := p.GetServiceTokenCredentials(context.Background(),
		&GetServiceTokenCredentialsInput{AccountID: "a", TokenID: "tok-1"})
	if err != nil {
		t.Fatalf("GetServiceTokenCredentials: %v", err)
	}
	if creds.ClientSecret != "" {
		t.Errorf("ClientSecret = %q; the API does not vend it after creation, so returning "+
			"anything here is a lie the caller cannot detect", creds.ClientSecret)
	}
	if creds.ClientID != "client-id-value" {
		t.Errorf("ClientID = %q", creds.ClientID)
	}
}

func TestGetServiceTokenCredentialsValidatesInput(t *testing.T) {
	p := New(WithAPIClient(&fakeAPI{}))
	for name, in := range map[string]*GetServiceTokenCredentialsInput{
		"no account": {TokenID: "t"},
		"no token":   {AccountID: "a"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := p.GetServiceTokenCredentials(context.Background(), in); err == nil {
				t.Error("want a validation error")
			}
		})
	}

	// And with no client at all it must error rather than panic.
	if _, err := New().GetServiceTokenCredentials(context.Background(),
		&GetServiceTokenCredentialsInput{AccountID: "a", TokenID: "t"}); err == nil {
		t.Error("want an error when no API client is configured")
	}
}

func TestGenerateServiceTokenHeaders(t *testing.T) {
	got := New().GenerateServiceTokenHeaders("cid", "csecret")
	if got["CF-Access-Client-Id"] != "cid" {
		t.Errorf("client id header = %q", got["CF-Access-Client-Id"])
	}
	if got["CF-Access-Client-Secret"] != "csecret" {
		t.Errorf("client secret header = %q", got["CF-Access-Client-Secret"])
	}
	if len(got) != 2 {
		t.Errorf("headers = %v, want exactly the two CF-Access ones", got)
	}
}

func TestCloudflareProviderIdentity(t *testing.T) {
	p := New()
	if p.Name() != core.Cloudflare {
		t.Errorf("Name() = %s", p.Name())
	}
	if !p.HasCapability(core.CapabilitySetup) {
		t.Error("should advertise setup")
	}
	if p.HasCapability(core.Capability("nonexistent")) {
		t.Error("should not advertise an unknown capability")
	}
}

// A library must not panic on a supported call with nothing configured.
func TestCloudflareNoPanicWithoutAClient(t *testing.T) {
	ctx := context.Background()
	ref := core.MechanismRef{ResourceIDs: map[string]string{"token_id": "t", "account_id": "a"}}

	calls := map[string]func() error{
		"Setup": func() error {
			_, err := New().Setup(ctx, accessSpec(), core.SetupOptions{})
			return err
		},
		"Delete": func() error { return New().Delete(ctx, ref, core.DeleteOptions{}) },
		"Validate": func() error {
			_, err := New().Validate(ctx, ref, core.ValidateOptions{})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s panicked with no client: %v", name, r)
				}
			}()
			_ = call()
		})
	}
}

type recordingSink struct{ stored [][]byte }

func (r *recordingSink) StoreSecret(_ context.Context, name string, value []byte) (core.SecretRef, error) {
	r.stored = append(r.stored, value)
	return core.SecretRef{Provider: "test", ID: name}, nil
}
