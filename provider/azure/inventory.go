package azure

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// Azure side of the cross-cloud trust inventory.

// InventoryCloud implements core.InventorySource.
func (p *Provider) InventoryCloud() core.Cloud { return core.Azure }

// inventorySubscriptionEnv names the subscription whose user-assigned managed identities to enumerate.
const inventorySubscriptionEnv = "AZURE_SUBSCRIPTION_ID"

// ListTrustRecords enumerates every federated identity credential in the tenant: those on application objects, and those on user-assigned managed identities in AZURE_SUBSCRIPTION_ID.
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
			// One unreadable application must not abort the tenant: a single app the caller cannot read would otherwise hide every other finding.
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
				// Azure has no condition OPERATOR: subjects are compared literally, always.
				SubjectCondition: cred.Subject,
				Operator:         "StringEquals",
				Audiences:        cred.Audiences,
			})
		}
	}

	records = append(records, p.managedIdentityRecords(ctx)...)
	return records, nil
}

// managedIdentityRecords enumerates federated credentials on user-assigned managed identities.
func (p *Provider) managedIdentityRecords(ctx context.Context) []core.TrustRecord {
	subscription := strings.TrimSpace(os.Getenv(inventorySubscriptionEnv))
	if subscription == "" {
		return []core.TrustRecord{{
			Cloud: core.Azure, Resource: "(user-assigned managed identities)",
			Name: "managed identities",
			Liveness: core.LivenessResult{
				State: core.NamespaceUnknown,
				Detail: "not enumerated: set " + inventorySubscriptionEnv + " — ARM has no " +
					"tenant-wide list of user-assigned identities, so a subscription must be named",
			},
		}}
	}

	if err := p.requireClients(ctx, false, true); err != nil {
		return []core.TrustRecord{gapRecord("(user-assigned managed identities)",
			fmt.Sprintf("no ARM client: %v", err))}
	}

	identities, err := p.armClient.ListManagedIdentities(ctx, subscription)
	if err != nil {
		return []core.TrustRecord{gapRecord("(user-assigned managed identities)",
			fmt.Sprintf("could not list identities in subscription %s: %v", subscription, err))}
	}

	var records []core.TrustRecord
	for _, id := range identities {
		if id == nil || id.Name == "" {
			continue
		}
		if id.ResourceGroup == "" {
			// Every subsequent call is addressed by resource group, and it is parsed out of the ARM id.
			records = append(records, gapRecord(id.ID,
				"could not determine this identity's resource group from its ARM id"))
			continue
		}

		creds, err := p.armClient.ListManagedIdentityFederatedCredentials(
			ctx, subscription, id.ResourceGroup, id.Name)
		if err != nil {
			records = append(records, gapRecord(id.ID,
				fmt.Sprintf("could not read this identity's federated credentials: %v", err)))
			continue
		}

		for _, cred := range creds {
			if cred == nil {
				continue
			}
			records = append(records, core.TrustRecord{
				Cloud:            core.Azure,
				Resource:         id.ID + "/federatedIdentityCredentials/" + cred.Name,
				Name:             id.Name + "/" + cred.Name,
				Issuer:           cred.Issuer,
				SubjectCondition: cred.Subject,
				Operator:         "StringEquals",
				Audiences:        cred.Audiences,
			})
		}
	}
	return records
}

// gapRecord is a row that records missing information rather than trust.
func gapRecord(resource, detail string) core.TrustRecord {
	return core.TrustRecord{
		Cloud: core.Azure, Resource: resource, Name: resource,
		Liveness: core.LivenessResult{State: core.NamespaceUnknown, Detail: detail},
	}
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
