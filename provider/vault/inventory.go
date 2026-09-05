package vault

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// Vault side of the cross-cloud trust inventory.

// InventoryCloud implements core.InventorySource.
func (p *Provider) InventoryCloud() core.Cloud { return core.Vault }

// ListTrustRecords enumerates every role on every JWT or OIDC auth mount.
func (p *Provider) ListTrustRecords(ctx context.Context) ([]core.TrustRecord, error) {
	if err := p.requireClient(); err != nil {
		return nil, err
	}

	mounts, err := p.client.ListAuthMethods(ctx)
	if err != nil {
		return nil, fmt.Errorf("vault: listing auth methods: %w", err)
	}

	// Sorted, so two runs of the inventory diff cleanly.
	paths := make([]string, 0, len(mounts))
	for path := range mounts {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	var records []core.TrustRecord
	for _, path := range paths {
		mount := mounts[path]
		if !isFederatedAuthType(mount.Type) {
			continue
		}
		records = append(records, p.recordsForMount(ctx, path)...)
	}
	return records, nil
}

// isFederatedAuthType reports whether a mount type federates an external OIDC identity.
func isFederatedAuthType(t string) bool {
	switch strings.ToLower(t) {
	case "jwt", "oidc":
		return true
	}
	return false
}

// recordsForMount enumerates one mount's roles.
func (p *Provider) recordsForMount(ctx context.Context, path string) []core.TrustRecord {
	// The issuer is mount-level configuration, read once rather than per role.
	issuer := p.issuerForMount(ctx, path)

	names, err := p.client.ListRoleNames(ctx, path)
	if err != nil {
		// One unreadable mount must not abort the inventory, and it is recorded as a gap rather than skipped: a mount nobody can list is missing information, not an absence of trust.
		return []core.TrustRecord{{
			Cloud: core.Vault, Resource: "auth/" + path, Name: path, Issuer: issuer,
			Liveness: core.LivenessResult{
				State:  core.NamespaceUnknown,
				Detail: fmt.Sprintf("could not list this mount's roles: %v", err),
			},
		}}
	}

	var records []core.TrustRecord
	for _, name := range names {
		role, err := p.client.ReadJWTRole(ctx, path, name)
		if err != nil || role == nil {
			records = append(records, core.TrustRecord{
				Cloud: core.Vault, Resource: roleResource(path, name), Name: path + "/" + name,
				Issuer: issuer,
				Liveness: core.LivenessResult{
					State:  core.NamespaceUnknown,
					Detail: fmt.Sprintf("could not read this role: %v", err),
				},
			})
			continue
		}

		records = append(records, core.TrustRecord{
			Cloud:            core.Vault,
			Resource:         roleResource(path, name),
			Name:             path + "/" + name,
			Issuer:           issuer,
			SubjectCondition: subjectConditionOf(role),
			// Vault compares bound_subject exactly and bound_claims exactly; there is no pattern operator, so recording one would invite the wildcard detector to reason about matching Vault does not do.
			Operator:  "bound_subject",
			Audiences: role.BoundAudiences,
		})
	}
	return records
}

// issuerForMount reads the mount's configured issuer.
func (p *Provider) issuerForMount(ctx context.Context, path string) string {
	cfg, err := p.client.ReadJWTConfig(ctx, path)
	if err != nil || cfg == nil {
		return ""
	}
	if cfg.BoundIssuer != "" {
		return cfg.BoundIssuer
	}
	// oidc_discovery_url is the issuer for a JWKS-discovery mount, and is what most GitHub Actions configurations set.
	return cfg.OIDCDiscoveryURL
}

// subjectConditionOf extracts the subject a role pins.
func subjectConditionOf(role *JWTRole) string {
	if role.BoundSubject != "" {
		return role.BoundSubject
	}
	if sub, ok := role.BoundClaims["sub"]; ok {
		if s, ok := sub.(string); ok {
			return s
		}
		// bound_claims values may be a list of accepted values.
		if list, ok := sub.([]interface{}); ok && len(list) > 0 {
			if s, ok := list[0].(string); ok {
				return s
			}
		}
	}
	return ""
}

// roleResource is the addressable path of a role.
func roleResource(path, name string) string {
	return fmt.Sprintf("auth/%s/role/%s", path, name)
}
