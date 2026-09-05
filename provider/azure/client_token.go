package azure

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Entra token acquisition: the client-credentials grant with a federated token as the client assertion.

const (
	// entraEndpoint is the Entra v2.0 token endpoint template.
	entraEndpoint = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"

	// clientAssertionType is the only assertion type Entra accepts here.
	clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

	// propagationCode is Entra's answer while a newly created federated identity credential has not yet propagated.
	propagationCode = "AADSTS70021"

	// propagationRetries and propagationBackoff bound the wait for that propagation.
	propagationRetries = 4
	propagationBackoff = 3 * time.Second
)

// ExchangeToken trades a federated token for an Entra access token.
func (c *restClient) ExchangeToken(ctx context.Context, input *ExchangeTokenInput) (*ExchangeTokenOutput, error) {
	if input == nil {
		return nil, fmt.Errorf("azure: exchange input is required")
	}
	if input.TenantID == "" || input.ClientID == "" {
		return nil, fmt.Errorf("azure: tenant id and client id are required")
	}

	assertion := input.ClientAssertion
	if assertion == "" {
		assertion = input.FederatedToken
	}
	if assertion == "" {
		return nil, fmt.Errorf("azure: a federated token or client assertion is required")
	}
	scope := input.Scope
	if scope == "" {
		return nil, fmt.Errorf("azure: scope is required; there is no safe default " +
			"(a resource-wide scope would hand out more than was asked for)")
	}
	assertionType := input.ClientAssertionType
	if assertionType == "" {
		assertionType = clientAssertionType
	}

	form := url.Values{
		"client_id":             {input.ClientID},
		"scope":                 {scope},
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {assertionType},
		"client_assertion":      {assertion},
	}
	endpoint := fmt.Sprintf(entraEndpoint, url.PathEscape(input.TenantID))
	return c.exchangeWithPropagationRetry(ctx, endpoint, form)
}

// exchangeWithPropagationRetry posts the grant, retrying only AADSTS70021.
func (c *restClient) exchangeWithPropagationRetry(ctx context.Context, endpoint string, form url.Values) (*ExchangeTokenOutput, error) {
	var lastErr error
	for attempt := range propagationRetries {
		out, err := c.postForm(ctx, endpoint, form)
		if err == nil {
			return out, nil
		}
		lastErr = err

		var apiErr *apiError
		if !asAPIError(err, &apiErr) || apiErr.Code != propagationCode {
			return nil, err
		}
		if attempt == propagationRetries-1 {
			break
		}
		// Linear, not exponential: propagation is a fixed-ish delay, not congestion, so backing off harder only makes the caller wait longer for the same answer.
		if err := c.sleep(ctx, propagationBackoff); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("%w (the federated credential still had not propagated after %d attempts; "+
		"Entra takes a few minutes after one is created)", lastErr, propagationRetries)
}

// postForm posts an application/x-www-form-urlencoded grant to Entra.
func (c *restClient) postForm(ctx context.Context, endpoint string, form url.Values) (*ExchangeTokenOutput, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("azure: building token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("azure: POST %s: %w", redactedPath(endpoint), err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := readLimited(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// Entra error descriptions echo the assertion back; parseAPIError scrubs.
		return nil, parseAPIError(resp.StatusCode, raw, "")
	}

	var out struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		ExtExpiresIn int    `json:"ext_expires_in"`
	}
	if err := jsonUnmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &ExchangeTokenOutput{
		AccessToken:  out.AccessToken,
		TokenType:    out.TokenType,
		ExpiresIn:    out.ExpiresIn,
		ExtExpiresIn: out.ExtExpiresIn,
		ExpiresOn:    c.now().Add(time.Duration(out.ExpiresIn) * time.Second),
	}, nil
}

// GetManagedIdentityToken is not implemented on the control-plane client.
func (c *restClient) GetManagedIdentityToken(_ context.Context, _ *GetManagedIdentityTokenInput) (*GetManagedIdentityTokenOutput, error) {
	return nil, fmt.Errorf("azure: managed identity tokens are a runtime concern, not a control-plane one; " +
		"use `cloud-auth exchange` or the source package")
}
