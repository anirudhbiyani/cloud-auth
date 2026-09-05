package gcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// STS and IAM Credentials operations: exchanging an external proof for a federated token, and minting tokens as a service account.

// errorsAs is errors.As, wrapped so the other files in this package can use it without each importing errors for one call.
func errorsAs(err error, target any) bool { return errors.As(err, target) }

// ExchangeToken trades an external identity token for a federated access token.
func (c *restClient) ExchangeToken(ctx context.Context, input *ExchangeTokenInput) (*ExchangeTokenOutput, error) {
	if input == nil {
		return nil, fmt.Errorf("gcp: exchange input is required")
	}
	if input.Audience == "" || input.SubjectToken == "" {
		return nil, fmt.Errorf("gcp: audience and subject token are required")
	}

	body := map[string]string{
		"audience":           input.Audience,
		"grantType":          input.GrantType,
		"requestedTokenType": input.RequestedTokenType,
		"subjectToken":       input.SubjectToken,
		"subjectTokenType":   input.SubjectTokenType,
		"scope":              input.Scope,
	}
	for k, v := range map[string]string{
		"grantType":          "urn:ietf:params:oauth:grant-type:token-exchange",
		"requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
		"scope":              cloudPlatformScope,
	} {
		if body[k] == "" {
			body[k] = v
		}
	}

	var out struct {
		AccessToken     string `json:"access_token"`
		IssuedTokenType string `json:"issued_token_type"`
		TokenType       string `json:"token_type"`
		ExpiresIn       int    `json:"expires_in"`
	}
	// The STS token endpoint is unauthenticated — the subject token IS the credential — so this deliberately bypasses c.do and its bearer header.
	if err := c.postUnauthenticated(ctx, c.stsURL+"/token", body, &out); err != nil {
		return nil, err
	}
	return &ExchangeTokenOutput{
		AccessToken:     out.AccessToken,
		IssuedTokenType: out.IssuedTokenType,
		TokenType:       out.TokenType,
		ExpiresIn:       out.ExpiresIn,
	}, nil
}

// GenerateAccessToken mints an OAuth access token as a service account.
func (c *restClient) GenerateAccessToken(ctx context.Context, input *GenerateAccessTokenInput) (*GenerateAccessTokenOutput, error) {
	if input == nil || input.ServiceAccountEmail == "" {
		return nil, fmt.Errorf("gcp: service account email is required")
	}
	body := map[string]any{"scope": input.Scope}
	if len(input.Scope) == 0 {
		body["scope"] = []string{cloudPlatformScope}
	}
	if input.Lifetime > 0 {
		body["lifetime"] = fmt.Sprintf("%ds", input.Lifetime)
	}
	if len(input.Delegates) > 0 {
		body["delegates"] = input.Delegates
	}

	var out struct {
		AccessToken string `json:"accessToken"`
		ExpireTime  string `json:"expireTime"`
	}
	endpoint := fmt.Sprintf("%s/projects/-/serviceAccounts/%s:generateAccessToken",
		c.credentialsURL, input.ServiceAccountEmail)
	if err := c.do(ctx, http.MethodPost, endpoint, body, &out, input.ServiceAccountEmail); err != nil {
		return nil, err
	}

	result := &GenerateAccessTokenOutput{AccessToken: out.AccessToken}
	if out.ExpireTime != "" {
		expiry, err := time.Parse(time.RFC3339, out.ExpireTime)
		if err != nil {
			return nil, fmt.Errorf("gcp: parsing token expiry %q: %w", out.ExpireTime, err)
		}
		result.ExpireTime = expiry
	}
	return result, nil
}

// GenerateIDToken mints an OIDC identity token as a service account.
func (c *restClient) GenerateIDToken(ctx context.Context, input *GenerateIDTokenInput) (*GenerateIDTokenOutput, error) {
	if input == nil || input.ServiceAccountEmail == "" {
		return nil, fmt.Errorf("gcp: service account email is required")
	}
	if input.Audience == "" {
		// An ID token with no audience is a bearer proof no recipient can verify was meant for them.
		return nil, fmt.Errorf("gcp: audience is required for an identity token")
	}

	body := map[string]any{
		"audience":     input.Audience,
		"includeEmail": input.IncludeEmail,
	}
	if len(input.Delegates) > 0 {
		body["delegates"] = input.Delegates
	}

	var out struct {
		Token string `json:"token"`
	}
	endpoint := fmt.Sprintf("%s/projects/-/serviceAccounts/%s:generateIdToken",
		c.credentialsURL, input.ServiceAccountEmail)
	if err := c.do(ctx, http.MethodPost, endpoint, body, &out, input.ServiceAccountEmail); err != nil {
		return nil, err
	}
	return &GenerateIDTokenOutput{Token: out.Token}, nil
}
