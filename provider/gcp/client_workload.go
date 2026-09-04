package gcp

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Workload Identity Pool and provider operations.
//
// Every mutation here is a long-running operation. They are awaited rather than
// fired and forgotten, because Setup's next step binds IAM against the resource
// this step created.

// wifPool is the wire shape of a workload identity pool.
type wifPool struct {
	Name        string `json:"name,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	Description string `json:"description,omitempty"`
	State       string `json:"state,omitempty"`
	Disabled    bool   `json:"disabled,omitempty"`
}

// wifProvider is the wire shape of a pool provider.
type wifProvider struct {
	Name               string            `json:"name,omitempty"`
	DisplayName        string            `json:"displayName,omitempty"`
	Description        string            `json:"description,omitempty"`
	State              string            `json:"state,omitempty"`
	Disabled           bool              `json:"disabled,omitempty"`
	AttributeMapping   map[string]string `json:"attributeMapping,omitempty"`
	AttributeCondition string            `json:"attributeCondition,omitempty"`
	AWS                *wifAWS           `json:"aws,omitempty"`
	OIDC               *wifOIDC          `json:"oidc,omitempty"`
}

type wifAWS struct {
	AccountID string `json:"accountId,omitempty"`
}

type wifOIDC struct {
	IssuerURI        string   `json:"issuerUri,omitempty"`
	AllowedAudiences []string `json:"allowedAudiences,omitempty"`
}

func (p *wifPool) toDomain() *WorkloadIdentityPool {
	return &WorkloadIdentityPool{
		Name: p.Name, DisplayName: p.DisplayName, Description: p.Description,
		State: p.State, Disabled: p.Disabled,
	}
}

func (p *wifProvider) toDomain() *WorkloadIdentityPoolProvider {
	out := &WorkloadIdentityPoolProvider{
		Name: p.Name, DisplayName: p.DisplayName, Description: p.Description,
		State: p.State, Disabled: p.Disabled,
		AttributeMapping: p.AttributeMapping, AttributeCondition: p.AttributeCondition,
	}
	if p.AWS != nil {
		out.AWS = &AWSProviderConfig{AccountID: p.AWS.AccountID}
	}
	if p.OIDC != nil {
		out.OIDC = &OIDCProviderConfig{IssuerURI: p.OIDC.IssuerURI, AllowedAudiences: p.OIDC.AllowedAudiences}
	}
	return out
}

// GetWorkloadIdentityPool reads a pool by resource name.
func (c *restClient) GetWorkloadIdentityPool(ctx context.Context, name string) (*WorkloadIdentityPool, error) {
	var out wifPool
	if err := c.do(ctx, http.MethodGet, c.iamURL+"/"+name, nil, &out, name); err != nil {
		return nil, err
	}
	return out.toDomain(), nil
}

// CreateWorkloadIdentityPool creates a pool under parent and waits for it.
func (c *restClient) CreateWorkloadIdentityPool(ctx context.Context, parent, poolID string, pool *WorkloadIdentityPool) (*WorkloadIdentityPool, error) {
	if pool == nil {
		pool = &WorkloadIdentityPool{}
	}
	endpoint := fmt.Sprintf("%s/%s/workloadIdentityPools?workloadIdentityPoolId=%s",
		c.iamURL, parent, url.QueryEscape(poolID))

	body := &wifPool{
		DisplayName: pool.DisplayName,
		Description: pool.Description,
		Disabled:    pool.Disabled,
	}
	release, err := c.paceWrite(ctx)
	if err != nil {
		return nil, err
	}
	var op operation
	err = c.do(ctx, http.MethodPost, endpoint, body, &op, poolID)
	release()
	if err != nil {
		return nil, err
	}
	var created wifPool
	if err := c.await(ctx, &op, &created); err != nil {
		return nil, err
	}
	if created.Name == "" {
		created.Name = fmt.Sprintf("%s/workloadIdentityPools/%s", parent, poolID)
	}
	return created.toDomain(), nil
}

// DeleteWorkloadIdentityPool soft-deletes a pool and waits for it.
//
// GCP soft-deletes: the pool moves to DELETED and its id stays reserved for 30
// days. That is the API's behaviour, not something this client can change, and
// it is why re-running setup with the same pool id shortly after a delete fails
// with ALREADY_EXISTS rather than creating a fresh pool.
func (c *restClient) DeleteWorkloadIdentityPool(ctx context.Context, name string) error {
	var op operation
	if err := c.do(ctx, http.MethodDelete, c.iamURL+"/"+name, nil, &op, name); err != nil {
		return err
	}
	return c.await(ctx, &op, nil)
}

// GetWorkloadIdentityPoolProvider reads a provider by resource name.
func (c *restClient) GetWorkloadIdentityPoolProvider(ctx context.Context, name string) (*WorkloadIdentityPoolProvider, error) {
	var out wifProvider
	if err := c.do(ctx, http.MethodGet, c.iamURL+"/"+name, nil, &out, name); err != nil {
		return nil, err
	}
	return out.toDomain(), nil
}

// CreateWorkloadIdentityPoolProvider creates a provider in a pool and waits.
func (c *restClient) CreateWorkloadIdentityPoolProvider(ctx context.Context, parent, providerID string, provider *WorkloadIdentityPoolProvider) (*WorkloadIdentityPoolProvider, error) {
	if provider == nil {
		return nil, fmt.Errorf("gcp: provider configuration is required")
	}
	if err := checkAttributeMapping(provider.AttributeMapping); err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/%s/providers?workloadIdentityPoolProviderId=%s",
		c.iamURL, parent, url.QueryEscape(providerID))

	body := &wifProvider{
		DisplayName:        provider.DisplayName,
		Description:        provider.Description,
		Disabled:           provider.Disabled,
		AttributeMapping:   provider.AttributeMapping,
		AttributeCondition: provider.AttributeCondition,
	}
	if provider.AWS != nil {
		body.AWS = &wifAWS{AccountID: provider.AWS.AccountID}
	}
	if provider.OIDC != nil {
		body.OIDC = &wifOIDC{
			IssuerURI:        provider.OIDC.IssuerURI,
			AllowedAudiences: provider.OIDC.AllowedAudiences,
		}
	}

	release, err := c.paceWrite(ctx)
	if err != nil {
		return nil, err
	}
	var op operation
	err = c.do(ctx, http.MethodPost, endpoint, body, &op, providerID)
	release()
	if err != nil {
		return nil, err
	}
	var created wifProvider
	if err := c.await(ctx, &op, &created); err != nil {
		return nil, err
	}
	if created.Name == "" {
		created.Name = fmt.Sprintf("%s/providers/%s", parent, providerID)
	}
	return created.toDomain(), nil
}

// DeleteWorkloadIdentityPoolProvider soft-deletes a provider and waits.
func (c *restClient) DeleteWorkloadIdentityPoolProvider(ctx context.Context, name string) error {
	var op operation
	if err := c.do(ctx, http.MethodDelete, c.iamURL+"/"+name, nil, &op, name); err != nil {
		return err
	}
	return c.await(ctx, &op, nil)
}

// checkAttributeMapping enforces GCP's documented mapping limits before the
// call.
//
// The API rejects an over-limit mapping with a message naming the ceiling but
// not which entry crossed it, and by then the pool has already been created —
// so the operator is left rolling back a half-built setup to fix a typo. The
// google.subject length limit is the one that cannot be checked here: its value
// is produced at exchange time by CEL over a token this code has not seen. A
// literal mapping can be checked, and GitHub's immutable subject claims made
// overflow materially more likely, so a literal that is already too long is
// worth catching.
func checkAttributeMapping(mapping map[string]string) error {
	if len(mapping) == 0 {
		return nil
	}
	if len(mapping) > maxAttributeMappings {
		return fmt.Errorf("gcp: %d attribute mappings exceeds the limit of %d",
			len(mapping), maxAttributeMappings)
	}

	total := 0
	for k, v := range mapping {
		total += len(k) + len(v)
	}
	if total > maxAttributeMappingBytes {
		return fmt.Errorf("gcp: attribute mapping is %d bytes, over the %d-byte limit",
			total, maxAttributeMappingBytes)
	}

	subject, ok := mapping["google.subject"]
	if !ok {
		// google.subject is the only required mapping; without it the provider
		// cannot name the federated principal at all.
		return fmt.Errorf("gcp: attribute_mapping must include google.subject")
	}
	// Only a literal can be measured. Anything referencing the assertion is
	// resolved per-token at exchange time.
	if !strings.Contains(subject, "assertion") && len(subject) > maxMappedSubjectBytes {
		return fmt.Errorf("gcp: google.subject is %d bytes, over the %d-byte limit",
			len(subject), maxMappedSubjectBytes)
	}
	return nil
}

// ListWorkloadIdentityPools enumerates the pools under a parent.
//
// Returns what the API returns, INCLUDING soft-deleted pools. GCP keeps a
// deleted pool listed with state DELETED for 30 days, and a client that
// silently dropped them would hide the reason a create fails with
// ALREADY_EXISTS on a name nothing appears to be using. Deciding which pools
// are a live trust relationship belongs to the consumer; see inventory.go.
func (c *restClient) ListWorkloadIdentityPools(ctx context.Context, parent string) ([]*WorkloadIdentityPool, error) {
	var out []*WorkloadIdentityPool
	pageToken := ""

	for {
		endpoint := fmt.Sprintf("%s/%s/workloadIdentityPools", c.iamURL, parent)
		if pageToken != "" {
			endpoint += "?pageToken=" + url.QueryEscape(pageToken)
		}

		var page struct {
			WorkloadIdentityPools []wifPool `json:"workloadIdentityPools"`
			NextPageToken         string    `json:"nextPageToken"`
		}
		if err := c.do(ctx, http.MethodGet, endpoint, nil, &page, parent); err != nil {
			return nil, err
		}
		for i := range page.WorkloadIdentityPools {
			out = append(out, page.WorkloadIdentityPools[i].toDomain())
		}
		if page.NextPageToken == "" {
			return out, nil
		}
		pageToken = page.NextPageToken
	}
}

// ListWorkloadIdentityPoolProviders enumerates the providers in one pool.
func (c *restClient) ListWorkloadIdentityPoolProviders(ctx context.Context, parent string) ([]*WorkloadIdentityPoolProvider, error) {
	var out []*WorkloadIdentityPoolProvider
	pageToken := ""

	for {
		endpoint := fmt.Sprintf("%s/%s/providers", c.iamURL, parent)
		if pageToken != "" {
			endpoint += "?pageToken=" + url.QueryEscape(pageToken)
		}

		var page struct {
			WorkloadIdentityPoolProviders []wifProvider `json:"workloadIdentityPoolProviders"`
			NextPageToken                 string        `json:"nextPageToken"`
		}
		if err := c.do(ctx, http.MethodGet, endpoint, nil, &page, parent); err != nil {
			return nil, err
		}
		for i := range page.WorkloadIdentityPoolProviders {
			out = append(out, page.WorkloadIdentityPoolProviders[i].toDomain())
		}
		if page.NextPageToken == "" {
			return out, nil
		}
		pageToken = page.NextPageToken
	}
}
