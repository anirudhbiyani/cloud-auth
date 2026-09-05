package vault

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// fakeVault records the calls made against it.
type fakeVault struct {
	VaultClient

	order []string

	authMethod    *AuthMethod
	readAuthErr   error
	enableErr     error
	writeRoleErr  error
	deleteErrs    map[string]error
	awsCreds      *AWSCredentials
	genCredsErr   error
	writePolicyOK bool
}

func newFakeVault() *fakeVault {
	return &fakeVault{deleteErrs: map[string]error{}}
}

func (f *fakeVault) record(op string) { f.order = append(f.order, op) }

func (f *fakeVault) ReadAuthMethod(context.Context, string) (*AuthMethod, error) {
	f.record("read-auth")
	return f.authMethod, f.readAuthErr
}

func (f *fakeVault) EnableAuthMethod(context.Context, string, string, *AuthMethodConfig) error {
	f.record("enable-auth")
	return f.enableErr
}

func (f *fakeVault) DisableAuthMethod(context.Context, string) error {
	f.record("disable-auth")
	return f.deleteErrs["disable-auth"]
}

func (f *fakeVault) WriteJWTConfig(context.Context, string, *JWTAuthConfig) error {
	f.record("write-jwt-config")
	return nil
}

func (f *fakeVault) WriteJWTRole(context.Context, string, string, *JWTRole) error {
	f.record("write-jwt-role")
	return f.writeRoleErr
}

func (f *fakeVault) DeleteJWTRole(context.Context, string, string) error {
	f.record("delete-jwt-role")
	return f.deleteErrs["delete-jwt-role"]
}

func (f *fakeVault) WriteAWSConfig(context.Context, string, *AWSAuthConfig) error {
	f.record("write-aws-config")
	return nil
}

func (f *fakeVault) WriteAWSRole(context.Context, string, string, *AWSRole) error {
	f.record("write-aws-role")
	return f.writeRoleErr
}

func (f *fakeVault) DeleteAWSRole(context.Context, string, string) error {
	f.record("delete-aws-role")
	return f.deleteErrs["delete-aws-role"]
}

func (f *fakeVault) WritePolicy(context.Context, string, string) error {
	f.record("write-policy")
	f.writePolicyOK = true
	return nil
}

func (f *fakeVault) DeletePolicy(context.Context, string) error {
	f.record("delete-policy")
	return f.deleteErrs["delete-policy"]
}

func (f *fakeVault) GenerateAWSCredentials(context.Context, string, string) (*AWSCredentials, error) {
	f.record("gen-aws-creds")
	if f.genCredsErr != nil {
		return nil, f.genCredsErr
	}
	if f.awsCreds != nil {
		return f.awsCreds, nil
	}
	return &AWSCredentials{AccessKey: "AKIA-vault", SecretKey: "secret", LeaseDuration: 3600}, nil
}

func jwtSpec() *VaultBrokerSpec {
	return &VaultBrokerSpec{
		VaultAddress:   "https://vault.example.com:8200",
		AuthMethodPath: "jwt-github",
		AuthMethodType: "jwt",
		RoleName:       "github-actions",
		JWTConfig: &JWTAuthConfig{
			OIDCDiscoveryURL: "https://token.actions.githubusercontent.com",
			BoundIssuer:      "https://token.actions.githubusercontent.com",
		},
		JWTRole: &JWTRole{
			RoleType:       "jwt",
			BoundAudiences: []string{"https://github.com/myorg"},
			UserClaim:      "actor",
			TokenPolicies:  []string{"deploy"},
		},
		Source: core.GitHubOIDC,
	}
}

func TestVaultSpecValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*VaultBrokerSpec)
		wantErr string
	}{
		{"valid jwt", func(*VaultBrokerSpec) {}, ""},
		{"no address", func(s *VaultBrokerSpec) { s.VaultAddress = "" }, "vault_address is required"},
		{"no auth path", func(s *VaultBrokerSpec) { s.AuthMethodPath = "" }, "auth_method_path"},
		{"no role name", func(s *VaultBrokerSpec) { s.RoleName = "" }, "role_name"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := jwtSpec()
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

// The mechanism type is the string loadSpec dispatches on, so it is part of the file format and must not drift.
func TestVaultMechanismTypeIsStable(t *testing.T) {
	if got := (&VaultBrokerSpec{}).Type(); got != "vault_broker" {
		t.Errorf("Type() = %q, want vault_broker: this string is the on-disk format", got)
	}
	if MechanismVaultBroker != "vault_broker" {
		t.Errorf("MechanismVaultBroker = %q", MechanismVaultBroker)
	}
}

// The auth method is only enabled when it is absent.
func TestVaultSetupEnablesTheAuthMethodOnlyWhenAbsent(t *testing.T) {
	absent := newFakeVault()
	absent.readAuthErr = errors.New("404 not found")
	if _, err := New(WithVaultClient(absent)).Setup(context.Background(), jwtSpec(), core.SetupOptions{}); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if !contains(absent.order, "enable-auth") {
		t.Errorf("an absent auth method should be enabled; calls = %v", absent.order)
	}

	present := newFakeVault()
	present.authMethod = &AuthMethod{Type: "jwt", Path: "jwt-github"}
	if _, err := New(WithVaultClient(present)).Setup(context.Background(), jwtSpec(), core.SetupOptions{}); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if contains(present.order, "enable-auth") {
		t.Errorf("an existing auth method must not be re-enabled (it would reset its "+
			"configuration); calls = %v", present.order)
	}
}

func TestVaultSetupWritesTheRoleForItsAuthType(t *testing.T) {
	jwt := newFakeVault()
	jwt.readAuthErr = errors.New("not found")
	if _, err := New(WithVaultClient(jwt)).Setup(context.Background(), jwtSpec(), core.SetupOptions{}); err != nil {
		t.Fatal(err)
	}
	if !contains(jwt.order, "write-jwt-role") {
		t.Errorf("a jwt spec should write a jwt role; calls = %v", jwt.order)
	}
	if contains(jwt.order, "write-aws-role") {
		t.Errorf("a jwt spec must not write an aws role; calls = %v", jwt.order)
	}

	awsFake := newFakeVault()
	awsFake.readAuthErr = errors.New("not found")
	spec := jwtSpec()
	spec.AuthMethodType = "aws"
	spec.JWTConfig, spec.JWTRole = nil, nil
	spec.AWSConfig = &AWSAuthConfig{}
	spec.AWSRole = &AWSRole{}
	if _, err := New(WithVaultClient(awsFake)).Setup(context.Background(), spec, core.SetupOptions{}); err != nil {
		t.Fatal(err)
	}
	if !contains(awsFake.order, "write-aws-role") {
		t.Errorf("an aws spec should write an aws role; calls = %v", awsFake.order)
	}
}

func TestVaultDryRunMakesNoCalls(t *testing.T) {
	f := newFakeVault()
	if _, err := New(WithVaultClient(f)).Setup(context.Background(), jwtSpec(),
		core.SetupOptions{DryRun: true}); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	for _, op := range f.order {
		if op != "read-auth" {
			t.Errorf("dry run performed a mutating call %q; calls = %v", op, f.order)
		}
	}
}

func TestVaultSetupRejectsAForeignSpec(t *testing.T) {
	_, err := New(WithVaultClient(newFakeVault())).
		Setup(context.Background(), &core.AWSRoleTrustOIDCSpec{}, core.SetupOptions{})
	if err == nil || !strings.Contains(err.Error(), "unsupported spec type") {
		t.Errorf("want an unsupported-spec error, got %v", err)
	}
}

func TestVaultSetupSurfacesAWriteFailure(t *testing.T) {
	f := newFakeVault()
	f.readAuthErr = errors.New("not found")
	f.writeRoleErr = errors.New("permission denied")
	if _, err := New(WithVaultClient(f)).Setup(context.Background(), jwtSpec(), core.SetupOptions{}); err == nil {
		t.Fatal("a failed role write must surface")
	}
}

// Delete tries both role kinds because the ref does not record which was used.
func TestVaultDeleteAttemptsBothRoleKinds(t *testing.T) {
	f := newFakeVault()
	ref := core.MechanismRef{
		ResourceIDs: map[string]string{"auth_path": "jwt-github", "role_name": "r"},
	}
	if err := New(WithVaultClient(f)).Delete(context.Background(), ref, core.DeleteOptions{}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	for _, want := range []string{"delete-jwt-role", "delete-aws-role"} {
		if !contains(f.order, want) {
			t.Errorf("Delete should attempt %s; calls = %v", want, f.order)
		}
	}
}

// The auth method is shared infrastructure, so it is only disabled for a mechanism cloud-auth created.
func TestVaultDeleteDisablesTheAuthMethodOnlyWhenOwned(t *testing.T) {
	owned := newFakeVault()
	ref := core.MechanismRef{
		Owned:       true,
		ResourceIDs: map[string]string{"auth_path": "jwt-github", "role_name": "r"},
	}
	if err := New(WithVaultClient(owned)).Delete(context.Background(), ref, core.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if !contains(owned.order, "disable-auth") {
		t.Errorf("an owned mechanism's auth method should be disabled; calls = %v", owned.order)
	}

	notOwned := newFakeVault()
	ref.Owned = false
	if err := New(WithVaultClient(notOwned)).Delete(context.Background(), ref, core.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if contains(notOwned.order, "disable-auth") {
		t.Errorf("a mechanism cloud-auth did not create must keep its auth method "+
			"(it is shared infrastructure); calls = %v", notOwned.order)
	}
}

func TestVaultDeleteDryRunMakesNoCalls(t *testing.T) {
	f := newFakeVault()
	ref := core.MechanismRef{Owned: true, ResourceIDs: map[string]string{"auth_path": "p", "role_name": "r"}}
	if err := New(WithVaultClient(f)).Delete(context.Background(), ref, core.DeleteOptions{DryRun: true}); err != nil {
		t.Fatal(err)
	}
	if len(f.order) != 0 {
		t.Errorf("dry run deleted things: %v", f.order)
	}
}

// Vault mints real AWS credentials, so the redaction rules apply to whatever it hands back.
func TestVaultGeneratedCredentialsCarryALifetime(t *testing.T) {
	f := newFakeVault()
	out, err := New(WithVaultClient(f)).GenerateAWSCredentials(context.Background(),
		&GenerateAWSCredentialsInput{SecretsEnginePath: "aws", RoleName: "deploy"})
	if err != nil {
		t.Fatalf("GenerateAWSCredentials: %v", err)
	}
	if out.ExpiresAt.IsZero() {
		t.Error("generated credentials must carry an expiry, or a cache cannot date them")
	}
	if out.Token == "" {
		t.Error("no credentials returned")
	}
}

func TestVaultGenerateSurfacesAFailure(t *testing.T) {
	f := newFakeVault()
	f.genCredsErr = errors.New("lease denied")
	if _, err := New(WithVaultClient(f)).GenerateAWSCredentials(context.Background(),
		&GenerateAWSCredentialsInput{SecretsEnginePath: "aws", RoleName: "deploy"}); err == nil {
		t.Fatal("want the failure to surface")
	}
}

func TestVaultProviderIdentity(t *testing.T) {
	p := New()
	if p.Name() != core.Vault {
		t.Errorf("Name() = %s", p.Name())
	}
	if !p.HasCapability(core.CapabilitySetup) {
		t.Error("should advertise setup")
	}
}

// A library must not panic on a supported call with nothing configured.
func TestVaultNoPanicWithoutAClient(t *testing.T) {
	ctx := context.Background()
	ref := core.MechanismRef{ResourceIDs: map[string]string{"auth_path": "p", "role_name": "r"}}

	calls := map[string]func() error{
		"Setup": func() error {
			_, err := New().Setup(ctx, jwtSpec(), core.SetupOptions{})
			return err
		},
		"Delete": func() error { return New().Delete(ctx, ref, core.DeleteOptions{}) },
		"Validate": func() error {
			_, err := New().Validate(ctx, ref, core.ValidateOptions{})
			return err
		},
		"GenerateAWSCredentials": func() error {
			_, err := New().GenerateAWSCredentials(ctx, &GenerateAWSCredentialsInput{
				SecretsEnginePath: "aws", RoleName: "r",
			})
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
			if err := call(); err == nil {
				t.Errorf("%s returned no error with no client configured", name)
			}
		})
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// A dry run must work with no client at all: it describes a plan, and requiring Vault credentials to be told what would happen defeats the purpose.
func TestVaultDryRunNeedsNoClient(t *testing.T) {
	out, err := New().Setup(context.Background(), jwtSpec(), core.SetupOptions{DryRun: true})
	if err != nil {
		t.Fatalf("a dry run must not require a client: %v", err)
	}
	if out == nil || out.Values["plan"] == "" {
		t.Errorf("a dry run should describe a plan, got %+v", out)
	}
}
