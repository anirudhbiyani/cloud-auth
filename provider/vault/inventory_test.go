package vault

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// Vault was the one wired provider `audit` did not cover, which made "which
// external identities can assume anything" a question with a Vault-shaped hole
// in it. A JWT auth role is a federated trust relationship in exactly the sense
// the clouds' are.

type listingVault struct {
	VaultClient
	mounts    map[string]*AuthMethod
	roles     map[string][]string
	jwtRoles  map[string]*JWTRole
	configs   map[string]*JWTAuthConfig
	mountsErr error
	rolesErr  map[string]error
	roleErr   map[string]error
}

func (l *listingVault) ListAuthMethods(context.Context) (map[string]*AuthMethod, error) {
	return l.mounts, l.mountsErr
}
func (l *listingVault) ListRoleNames(_ context.Context, path string) ([]string, error) {
	if err := l.rolesErr[path]; err != nil {
		return nil, err
	}
	return l.roles[path], nil
}
func (l *listingVault) ReadJWTRole(_ context.Context, path, name string) (*JWTRole, error) {
	key := path + "/" + name
	if err := l.roleErr[key]; err != nil {
		return nil, err
	}
	return l.jwtRoles[key], nil
}
func (l *listingVault) ReadJWTConfig(_ context.Context, path string) (*JWTAuthConfig, error) {
	cfg, ok := l.configs[path]
	if !ok {
		return nil, errors.New("no config")
	}
	return cfg, nil
}

func TestVaultListTrustRecords(t *testing.T) {
	v := &listingVault{
		mounts: map[string]*AuthMethod{
			// Mounted at a non-conventional path on purpose: the conventional
			// "jwt" is a convention, not a rule, and an inventory that only
			// looked there would miss most real installations.
			"github": {Type: "jwt", Path: "github"},
			// aws auth federates too, but by verifying signed cloud metadata
			// rather than a JWT against a JWKS. Claiming to inventory it and
			// then reporting an empty subject would be worse than the gap.
			"aws":   {Type: "aws", Path: "aws"},
			"token": {Type: "token", Path: "token"},
		},
		roles: map[string][]string{"github": {"deploy", "readonly"}},
		configs: map[string]*JWTAuthConfig{
			"github": {OIDCDiscoveryURL: "https://token.actions.githubusercontent.com"},
		},
		jwtRoles: map[string]*JWTRole{
			"github/deploy": {
				RoleType: "jwt", BoundSubject: "repo:myorg/myrepo:ref:refs/heads/main",
				BoundAudiences: []string{"https://github.com/myorg"},
			},
			// bound_claims is the alternative spelling of the same constraint.
			"github/readonly": {
				RoleType:       "jwt",
				BoundClaims:    map[string]interface{}{"sub": "repo:myorg/other:ref:refs/heads/main"},
				BoundAudiences: []string{"https://github.com/myorg"},
			},
		},
	}

	records, err := New(WithVaultClient(v)).ListTrustRecords(context.Background())
	if err != nil {
		t.Fatalf("ListTrustRecords: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2 (only the jwt mount's roles):\n%+v", len(records), records)
	}

	byResource := map[string]core.TrustRecord{}
	for _, r := range records {
		byResource[r.Resource] = r
	}

	deploy := byResource["auth/github/role/deploy"]
	if deploy.Cloud != core.Vault {
		t.Errorf("Cloud = %q", deploy.Cloud)
	}
	if deploy.Issuer != "https://token.actions.githubusercontent.com" {
		t.Errorf("Issuer = %q — the issuer is mount-level config", deploy.Issuer)
	}
	if deploy.SubjectCondition != "repo:myorg/myrepo:ref:refs/heads/main" {
		t.Errorf("SubjectCondition = %q", deploy.SubjectCondition)
	}
	// Vault compares bound_subject exactly; there is no pattern operator, so
	// recording one would invite the wildcard detector to reason about matching
	// Vault does not do.
	if deploy.Operator != "bound_subject" {
		t.Errorf("Operator = %q", deploy.Operator)
	}
	// A legacy GitHub subject is rename-fragile through Vault exactly as
	// through AWS — the issuer is the same global one.
	if !core.IsRenameFragile(deploy.Issuer, deploy.SubjectCondition) {
		t.Error("a legacy GitHub subject should be flagged rename-fragile")
	}

	readonly := byResource["auth/github/role/readonly"]
	if readonly.SubjectCondition != "repo:myorg/other:ref:refs/heads/main" {
		t.Errorf("bound_claims[\"sub\"] was not read: %q", readonly.SubjectCondition)
	}
}

// A role with neither bound_subject nor a sub claim accepts ANY token the
// issuer signs. That is the confused-deputy hole, and it must score as such.
func TestVaultRoleWithNoSubjectScoresCritical(t *testing.T) {
	v := &listingVault{
		mounts:  map[string]*AuthMethod{"jwt": {Type: "jwt", Path: "jwt"}},
		roles:   map[string][]string{"jwt": {"wide"}},
		configs: map[string]*JWTAuthConfig{"jwt": {BoundIssuer: "https://issuer.example.com"}},
		jwtRoles: map[string]*JWTRole{
			"jwt/wide": {RoleType: "jwt", BoundAudiences: []string{"aud"}},
		},
	}

	records, err := New(WithVaultClient(v)).ListTrustRecords(context.Background())
	if err != nil {
		t.Fatalf("ListTrustRecords: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records", len(records))
	}
	if got := core.ScoreSubject(records[0].SubjectCondition).Breadth; got != core.BreadthCritical {
		t.Errorf("breadth = %s, want critical for a role that pins no subject", got)
	}
}

// bound_claims may hold a LIST of accepted values.
func TestVaultBoundClaimsList(t *testing.T) {
	v := &listingVault{
		mounts:  map[string]*AuthMethod{"jwt": {Type: "jwt", Path: "jwt"}},
		roles:   map[string][]string{"jwt": {"multi"}},
		configs: map[string]*JWTAuthConfig{"jwt": {BoundIssuer: "https://issuer.example.com"}},
		jwtRoles: map[string]*JWTRole{
			"jwt/multi": {BoundClaims: map[string]interface{}{
				"sub": []interface{}{"repo:a/b:ref:refs/heads/main", "repo:c/d:ref:refs/heads/main"},
			}},
		},
	}

	records, err := New(WithVaultClient(v)).ListTrustRecords(context.Background())
	if err != nil {
		t.Fatalf("ListTrustRecords: %v", err)
	}
	if records[0].SubjectCondition != "repo:a/b:ref:refs/heads/main" {
		t.Errorf("SubjectCondition = %q, want the first bound claim value", records[0].SubjectCondition)
	}
}

// One unreadable mount or role must not abort the inventory, and must be
// recorded as a gap: a mount nobody can list is missing information, not an
// absence of trust.
func TestVaultUnreadableMountIsRecordedAsUnknown(t *testing.T) {
	v := &listingVault{
		mounts: map[string]*AuthMethod{
			"good":   {Type: "jwt", Path: "good"},
			"denied": {Type: "jwt", Path: "denied"},
		},
		roles: map[string][]string{"good": {"r"}},
		configs: map[string]*JWTAuthConfig{
			"good": {BoundIssuer: "https://issuer.example.com"},
		},
		jwtRoles: map[string]*JWTRole{"good/r": {BoundSubject: "sub"}},
		rolesErr: map[string]error{"denied": errors.New("permission denied")},
	}

	records, err := New(WithVaultClient(v)).ListTrustRecords(context.Background())
	if err != nil {
		t.Fatalf("one unreadable mount aborted the inventory: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2 (one real, one gap)", len(records))
	}

	var gaps int
	for _, r := range records {
		if r.Liveness.State == core.NamespaceUnknown &&
			strings.Contains(r.Liveness.Detail, "permission denied") {
			gaps++
		}
	}
	if gaps != 1 {
		t.Errorf("the unreadable mount was not recorded as a gap: %+v", records)
	}
}

// Order is stable: the mount table is a map and Go randomizes iteration, so two
// runs of the inventory would otherwise not diff cleanly.
func TestVaultRecordOrderIsStable(t *testing.T) {
	mounts := map[string]*AuthMethod{}
	roles := map[string][]string{}
	configs := map[string]*JWTAuthConfig{}
	jwtRoles := map[string]*JWTRole{}
	for _, p := range []string{"alpha", "beta", "gamma", "delta", "epsilon"} {
		mounts[p] = &AuthMethod{Type: "jwt", Path: p}
		roles[p] = []string{"r"}
		configs[p] = &JWTAuthConfig{BoundIssuer: "https://issuer.example.com"}
		jwtRoles[p+"/r"] = &JWTRole{BoundSubject: "sub-" + p}
	}
	v := &listingVault{mounts: mounts, roles: roles, configs: configs, jwtRoles: jwtRoles}
	p := New(WithVaultClient(v))

	first, err := p.ListTrustRecords(context.Background())
	if err != nil {
		t.Fatalf("ListTrustRecords: %v", err)
	}
	for range 10 {
		got, err := p.ListTrustRecords(context.Background())
		if err != nil {
			t.Fatalf("ListTrustRecords: %v", err)
		}
		for i := range got {
			if got[i].Resource != first[i].Resource {
				t.Fatalf("order changed at %d: %q then %q",
					i, first[i].Resource, got[i].Resource)
			}
		}
	}
}

// A failure listing mounts at all is a real error: unlike one bad mount, it
// means nothing about the Vault was seen, and an empty inventory would read as
// "no federated trust here".
func TestVaultListAuthMethodsFailureIsAnError(t *testing.T) {
	v := &listingVault{mountsErr: errors.New("permission denied on sys/auth")}
	if _, err := New(WithVaultClient(v)).ListTrustRecords(context.Background()); err == nil {
		t.Fatal("a total listing failure was reported as an empty inventory")
	}
}

func TestVaultInventoryCloud(t *testing.T) {
	if got := New().InventoryCloud(); got != core.Vault {
		t.Errorf("InventoryCloud() = %q", got)
	}
}
