package gcp

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// GCP side of the cross-cloud trust inventory.

// inventoryProjectEnv names the project to enumerate.
const inventoryProjectEnv = "GOOGLE_CLOUD_PROJECT"

// InventoryCloud implements core.InventorySource.
func (p *Provider) InventoryCloud() core.Cloud { return core.GCP }

// ListTrustRecords enumerates every workload identity pool provider in the project, one record per provider.
func (p *Provider) ListTrustRecords(ctx context.Context) ([]core.TrustRecord, error) {
	project := strings.TrimSpace(os.Getenv(inventoryProjectEnv))
	if project == "" {
		return nil, fmt.Errorf("gcp: set %s to the project to inventory — a workload identity "+
			"pool is project-scoped and GCP has no tenant-wide listing, so there is no project "+
			"to infer", inventoryProjectEnv)
	}
	if err := p.requireClients(ctx, true, false); err != nil {
		return nil, err
	}

	parent := "projects/" + project + "/locations/global"
	pools, err := p.wifClient.ListWorkloadIdentityPools(ctx, parent)
	if err != nil {
		return nil, fmt.Errorf("gcp: listing workload identity pools in %s: %w", project, err)
	}

	var records []core.TrustRecord
	for _, pool := range pools {
		if pool == nil || pool.Name == "" {
			continue
		}
		// GCP keeps a deleted pool listed with state DELETED for 30 days, its name reserved.
		if isDeleted(pool.State) {
			continue
		}
		providers, err := p.wifClient.ListWorkloadIdentityPoolProviders(ctx, pool.Name)
		if err != nil {
			// One unreadable pool must not abort the project, and it is recorded as an unknown rather than skipped: a pool nobody can read is a gap in the inventory, not an absence of trust.
			records = append(records, core.TrustRecord{
				Cloud: core.GCP, Resource: pool.Name, Name: pool.DisplayName,
				Liveness: core.LivenessResult{
					State:  core.NamespaceUnknown,
					Detail: fmt.Sprintf("could not read this pool's providers: %v", err),
				},
			})
			continue
		}

		for _, prov := range providers {
			if prov == nil || isDeleted(prov.State) {
				continue
			}
			records = append(records, trustRecordForProvider(pool, prov))
		}
	}
	return records, nil
}

// isDeleted reports whether a pool or provider is in GCP's soft-deleted state.
func isDeleted(state string) bool { return strings.EqualFold(state, "DELETED") }

// trustRecordForProvider normalizes one pool provider.
func trustRecordForProvider(pool *WorkloadIdentityPool, prov *WorkloadIdentityPoolProvider) core.TrustRecord {
	rec := core.TrustRecord{
		Cloud:    core.GCP,
		Resource: prov.Name,
		Name:     providerDisplayName(pool, prov),
		// subjectsFromAttributeCondition already returns "*" for an absent condition, which is the honest answer: a provider with no attribute condition admits every identity its issuer will mint.
		SubjectCondition: firstSubject(subjectsFromAttributeCondition(prov.AttributeCondition)),
		// CEL, not an IAM operator.
		Operator: "CEL",
	}
	switch {
	case prov.OIDC != nil:
		rec.Issuer = prov.OIDC.IssuerURI
		rec.Audiences = prov.OIDC.AllowedAudiences
	case prov.AWS != nil:
		// An aws-type provider trusts an AWS ACCOUNT, verified by a SigV4 GetCallerIdentity call rather than a JWT.
		rec.Issuer = "aws:" + prov.AWS.AccountID
	}
	return rec
}

func providerDisplayName(pool *WorkloadIdentityPool, prov *WorkloadIdentityPoolProvider) string {
	name := prov.DisplayName
	if name == "" {
		name = lastSegment(prov.Name)
	}
	poolName := pool.DisplayName
	if poolName == "" {
		poolName = lastSegment(pool.Name)
	}
	return poolName + "/" + name
}

func lastSegment(resource string) string {
	if i := strings.LastIndex(resource, "/"); i >= 0 {
		return resource[i+1:]
	}
	return resource
}

func firstSubject(subjects []string) string {
	if len(subjects) == 0 {
		return ""
	}
	return subjects[0]
}
