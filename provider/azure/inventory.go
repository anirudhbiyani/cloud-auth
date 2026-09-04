package azure

import (
	"context"
	"fmt"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// Azure side of the cross-cloud trust inventory.
//
// Enumerating the TENANT, not cloud-auth's state file, for the same reason the
// AWS source does: the interesting population is federated credentials that
// predate this tool. Published telemetry put 24% of GitHub namespaces
// referenced in Azure trust configuration at unregistered and claimable — a
// higher rate than AWS, and none of it created by cloud-auth.

// InventoryCloud implements core.InventorySource.
func (p *Provider) InventoryCloud() core.Cloud { return core.Azure }

// ListTrustRecords enumerates every federated identity credential on every
// application in the tenant.
//
// Applications only. A user-assigned managed identity can also carry federated
// credentials, but ARM has no tenant-wide list of them — they are addressed per
// resource group — so enumerating those needs a subscription scan this does not
// do. That gap is reported rather than passed over silently: an inventory that
// quietly covers half the tenant is worse than one that says which half.
func (p *Provider) ListTrustRecords(ctx context.Context) ([]core.TrustRecord, error) {
	if err := p.requireClients(ctx, true, false); err != nil {
		return nil, err
	}

	apps, err := p.graphClient.ListApplications(ctx)
	if err != nil {
		return nil, fmt.Errorf("azure: listing applications: %w", err)
	}

	var records []core.TrustRecord
	for _, app := range apps {
		if app == nil || app.ID == "" {
			continue
		}
		creds, err := p.graphClient.ListFederatedIdentityCredentials(ctx, app.ID)
		if err != nil {
			// One unreadable application must not abort the tenant: a single
			// app the caller cannot read would otherwise hide every other
			// finding. It IS recorded, as an unknown, so the gap is visible.
			records = append(records, core.TrustRecord{
				Cloud: core.Azure, Resource: app.ID, Name: app.DisplayName,
				Liveness: core.LivenessResult{
					State:  core.NamespaceUnknown,
					Detail: fmt.Sprintf("could not read this application's federated credentials: %v", err),
				},
			})
			continue
		}

		for _, cred := range creds {
			if cred == nil {
				continue
			}
			records = append(records, core.TrustRecord{
				Cloud:    core.Azure,
				Resource: app.ID + "/federatedIdentityCredentials/" + cred.Name,
				Name:     appCredentialName(app, cred),
				Issuer:   cred.Issuer,
				// Azure has no condition OPERATOR: subjects are compared
				// literally, always. Recording that explicitly matters because
				// the breadth scorer and the wildcard detector both read the
				// operator, and an absent one would read as "unknown" rather
				// than "exact by construction".
				SubjectCondition: cred.Subject,
				Operator:         "StringEquals",
				Audiences:        cred.Audiences,
			})
		}
	}
	return records, nil
}

// appCredentialName is what a human recognises in the table.
func appCredentialName(app *Application, cred *FederatedIdentityCredential) string {
	name := app.DisplayName
	if name == "" {
		name = app.AppID
	}
	if cred.Name == "" {
		return name
	}
	return name + "/" + cred.Name
}
