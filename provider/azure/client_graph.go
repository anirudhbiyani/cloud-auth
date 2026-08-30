package azure

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Microsoft Graph: applications, service principals and federated identity
// credentials.

// wireApplication is the Graph shape of an application object.
type wireApplication struct {
	ID             string   `json:"id,omitempty"`
	AppID          string   `json:"appId,omitempty"`
	DisplayName    string   `json:"displayName,omitempty"`
	IdentifierUris []string `json:"identifierUris,omitempty"`
	SignInAudience string   `json:"signInAudience,omitempty"`
}

func (a *wireApplication) toDomain() *Application {
	return &Application{
		ID: a.ID, AppID: a.AppID, DisplayName: a.DisplayName,
		IdentifierUris: a.IdentifierUris, SignInAudience: a.SignInAudience,
	}
}

// wireFIC is the shape of a federated identity credential. Graph and ARM use
// the same field names, so one type serves both.
type wireFIC struct {
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name,omitempty"`
	Issuer      string   `json:"issuer,omitempty"`
	Subject     string   `json:"subject,omitempty"`
	Audiences   []string `json:"audiences,omitempty"`
	Description string   `json:"description,omitempty"`
}

func (f *wireFIC) toDomain() *FederatedIdentityCredential {
	return &FederatedIdentityCredential{
		ID: f.ID, Name: f.Name, Issuer: f.Issuer, Subject: f.Subject,
		Audiences: f.Audiences, Description: f.Description,
	}
}

func ficFromDomain(c *FederatedIdentityCredential) *wireFIC {
	return &wireFIC{
		Name: c.Name, Issuer: c.Issuer, Subject: c.Subject,
		Audiences: c.Audiences, Description: c.Description,
	}
}

// GetApplication reads an application by object id.
func (c *restClient) GetApplication(ctx context.Context, id string) (*Application, error) {
	var out wireApplication
	endpoint := fmt.Sprintf("%s/applications/%s", c.graphURL, url.PathEscape(id))
	if err := c.do(ctx, http.MethodGet, endpoint, graphScope, nil, &out, id); err != nil {
		return nil, err
	}
	return out.toDomain(), nil
}

// CreateApplication registers a new application.
func (c *restClient) CreateApplication(ctx context.Context, app *Application) (*Application, error) {
	if app == nil || app.DisplayName == "" {
		return nil, fmt.Errorf("azure: application display name is required")
	}
	body := &wireApplication{
		DisplayName:    app.DisplayName,
		IdentifierUris: app.IdentifierUris,
		SignInAudience: app.SignInAudience,
	}
	if body.SignInAudience == "" {
		// Single tenant unless asked otherwise. The multi-tenant values make the
		// app assumable from directories the operator does not control, which is
		// not a default anyone should get by omission.
		body.SignInAudience = "AzureADMyOrg"
	}
	var out wireApplication
	if err := c.do(ctx, http.MethodPost, c.graphURL+"/applications", graphScope, body, &out, app.DisplayName); err != nil {
		return nil, err
	}
	return out.toDomain(), nil
}

// UpdateApplication patches an application.
func (c *restClient) UpdateApplication(ctx context.Context, id string, app *Application) error {
	if app == nil {
		return fmt.Errorf("azure: application is required")
	}
	endpoint := fmt.Sprintf("%s/applications/%s", c.graphURL, url.PathEscape(id))
	body := &wireApplication{
		DisplayName:    app.DisplayName,
		IdentifierUris: app.IdentifierUris,
		SignInAudience: app.SignInAudience,
	}
	return c.do(ctx, http.MethodPatch, endpoint, graphScope, body, nil, id)
}

// DeleteApplication deletes an application by object id.
func (c *restClient) DeleteApplication(ctx context.Context, id string) error {
	endpoint := fmt.Sprintf("%s/applications/%s", c.graphURL, url.PathEscape(id))
	return c.do(ctx, http.MethodDelete, endpoint, graphScope, nil, nil, id)
}

// ListApplications lists applications in the tenant, following Graph paging.
func (c *restClient) ListApplications(ctx context.Context) ([]*Application, error) {
	endpoint := c.graphURL + "/applications"
	var all []*Application

	// Graph pages with @odata.nextLink. Stopping at the first page would silently
	// answer "these are your applications" with a prefix of them, and callers
	// here use the result to decide whether something already exists.
	for endpoint != "" {
		var page struct {
			Value    []wireApplication `json:"value"`
			NextLink string            `json:"@odata.nextLink"`
		}
		if err := c.do(ctx, http.MethodGet, endpoint, graphScope, nil, &page, "applications"); err != nil {
			return nil, err
		}
		for i := range page.Value {
			all = append(all, page.Value[i].toDomain())
		}
		endpoint = page.NextLink
	}
	return all, nil
}

// GetServicePrincipal reads a service principal by object id.
func (c *restClient) GetServicePrincipal(ctx context.Context, id string) (*ServicePrincipal, error) {
	var out struct {
		ID          string `json:"id"`
		AppID       string `json:"appId"`
		DisplayName string `json:"displayName"`
	}
	endpoint := fmt.Sprintf("%s/servicePrincipals/%s", c.graphURL, url.PathEscape(id))
	if err := c.do(ctx, http.MethodGet, endpoint, graphScope, nil, &out, id); err != nil {
		return nil, err
	}
	return &ServicePrincipal{ID: out.ID, AppID: out.AppID, DisplayName: out.DisplayName, ObjectID: out.ID}, nil
}

// CreateServicePrincipal creates a service principal for an application.
func (c *restClient) CreateServicePrincipal(ctx context.Context, appID string) (*ServicePrincipal, error) {
	if appID == "" {
		return nil, fmt.Errorf("azure: application id is required")
	}
	var out struct {
		ID          string `json:"id"`
		AppID       string `json:"appId"`
		DisplayName string `json:"displayName"`
	}
	body := map[string]string{"appId": appID}
	if err := c.do(ctx, http.MethodPost, c.graphURL+"/servicePrincipals", graphScope, body, &out, appID); err != nil {
		return nil, err
	}
	return &ServicePrincipal{ID: out.ID, AppID: out.AppID, DisplayName: out.DisplayName, ObjectID: out.ID}, nil
}

// DeleteServicePrincipal deletes a service principal by object id.
func (c *restClient) DeleteServicePrincipal(ctx context.Context, id string) error {
	endpoint := fmt.Sprintf("%s/servicePrincipals/%s", c.graphURL, url.PathEscape(id))
	return c.do(ctx, http.MethodDelete, endpoint, graphScope, nil, nil, id)
}

// GetFederatedIdentityCredential reads one credential on an application.
func (c *restClient) GetFederatedIdentityCredential(ctx context.Context, appID, credentialID string) (*FederatedIdentityCredential, error) {
	var out wireFIC
	endpoint := fmt.Sprintf("%s/applications/%s/federatedIdentityCredentials/%s",
		c.graphURL, url.PathEscape(appID), url.PathEscape(credentialID))
	if err := c.do(ctx, http.MethodGet, endpoint, graphScope, nil, &out, credentialID); err != nil {
		return nil, err
	}
	return out.toDomain(), nil
}

// ListFederatedIdentityCredentials lists the credentials on an application.
func (c *restClient) ListFederatedIdentityCredentials(ctx context.Context, appID string) ([]*FederatedIdentityCredential, error) {
	var page struct {
		Value []wireFIC `json:"value"`
	}
	endpoint := fmt.Sprintf("%s/applications/%s/federatedIdentityCredentials",
		c.graphURL, url.PathEscape(appID))
	if err := c.do(ctx, http.MethodGet, endpoint, graphScope, nil, &page, appID); err != nil {
		return nil, err
	}
	out := make([]*FederatedIdentityCredential, 0, len(page.Value))
	for i := range page.Value {
		out = append(out, page.Value[i].toDomain())
	}
	return out, nil
}

// CreateFederatedIdentityCredential adds a credential to an application.
func (c *restClient) CreateFederatedIdentityCredential(ctx context.Context, appID string, cred *FederatedIdentityCredential) (*FederatedIdentityCredential, error) {
	if err := validateFIC(cred); err != nil {
		return nil, err
	}

	existing, err := c.ListFederatedIdentityCredentials(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("azure: counting existing federated credentials: %w", err)
	}
	if err := checkFICCapacity(len(existing), appID); err != nil {
		return nil, err
	}

	var out wireFIC
	endpoint := fmt.Sprintf("%s/applications/%s/federatedIdentityCredentials",
		c.graphURL, url.PathEscape(appID))
	if err := c.createFICPaced(ctx, endpoint, graphScope, cred, &out); err != nil {
		return nil, err
	}
	return out.toDomain(), nil
}

// DeleteFederatedIdentityCredential removes a credential from an application.
func (c *restClient) DeleteFederatedIdentityCredential(ctx context.Context, appID, credentialID string) error {
	endpoint := fmt.Sprintf("%s/applications/%s/federatedIdentityCredentials/%s",
		c.graphURL, url.PathEscape(appID), url.PathEscape(credentialID))
	return c.do(ctx, http.MethodDelete, endpoint, graphScope, nil, nil, credentialID)
}

// createFICPaced serializes and paces federated-credential creation.
//
// Azure throttles these to roughly 0.25 requests per second per resource and
// answers a concurrent create under the same identity with HTTP 409. A caller
// that fans out therefore gets conflicts rather than speed, and the conflict is
// indistinguishable from "this credential already exists" — so the two get
// conflated and a setup reports success having created nothing.
func (c *restClient) createFICPaced(ctx context.Context, endpoint, scope string, cred *FederatedIdentityCredential, out any) error {
	c.ficMu.Lock()
	defer c.ficMu.Unlock()

	if !c.lastFIC.IsZero() {
		if wait := c.ficInterval - c.now().Sub(c.lastFIC); wait > 0 {
			if err := c.sleep(ctx, wait); err != nil {
				return err
			}
		}
	}
	err := c.do(ctx, http.MethodPost, endpoint, scope, ficFromDomain(cred), out, cred.Name)
	c.lastFIC = c.now()
	return err
}

// checkFICCapacity refuses the credential that would exceed Azure's cap.
//
// Reported before the call, naming the limit and the count, because the API's
// own refusal says only that a limit was reached — leaving the operator to
// discover both the number and what is already occupying the slots.
func checkFICCapacity(existing int, resource string) error {
	if existing < maxFederatedCredentials {
		return nil
	}
	return fmt.Errorf("azure: %s already has %d federated identity credentials, "+
		"which is the limit; delete an unused one first "+
		"(the flexible-FIC preview raises this, but is readable only through Graph or the portal — "+
		"Azure CLI, PowerShell and Terraform error on both read and write — so adopting it makes "+
		"existing infrastructure-as-code state unreadable)",
		resource, maxFederatedCredentials)
}

// validateFIC rejects a credential Azure will refuse, or worse, accept.
//
// No property of a federated identity credential accepts a wildcard. Azure does
// not expand one; it matches the literal characters, so a subject of
// "repo:org/*" silently matches nothing and the credential is created
// successfully and then never works — the failure mode Microsoft's own
// documentation describes as failing without error.
func validateFIC(cred *FederatedIdentityCredential) error {
	if cred == nil {
		return fmt.Errorf("azure: federated identity credential is required")
	}
	if cred.Name == "" {
		return fmt.Errorf("azure: federated identity credential name is required")
	}
	if cred.Issuer == "" || cred.Subject == "" {
		return fmt.Errorf("azure: federated identity credential issuer and subject are required")
	}
	if len(cred.Audiences) == 0 {
		return fmt.Errorf("azure: federated identity credential audiences are required")
	}

	for field, value := range map[string]string{
		"issuer":  cred.Issuer,
		"subject": cred.Subject,
		"name":    cred.Name,
	} {
		if strings.ContainsAny(value, "*?") {
			return fmt.Errorf("azure: federated identity credential %s %q contains a wildcard; "+
				"Azure matches these literally, so the credential would be created successfully "+
				"and never match any token", field, value)
		}
	}
	for _, aud := range cred.Audiences {
		if strings.ContainsAny(aud, "*?") {
			return fmt.Errorf("azure: federated identity credential audience %q contains a wildcard; "+
				"Azure matches audiences literally", aud)
		}
	}
	return nil
}
