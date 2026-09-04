package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// The VaultClient surface. Vault's API is uniform — a JSON write to a path, a
// JSON read from a path — so most of these are one line of routing over do().
// What is worth attention is where a path differs from the obvious guess, and
// those carry a comment.

// --- Auth methods ---

// EnableAuthMethod mounts an auth method at path.
func (c *restClient) EnableAuthMethod(ctx context.Context, path, methodType string, config *AuthMethodConfig) error {
	body := map[string]any{"type": methodType}
	if config != nil {
		if config.Description != "" {
			body["description"] = config.Description
		}
		if cfg := tuneConfig(config); len(cfg) > 0 {
			body["config"] = cfg
		}
	}
	return c.do(ctx, http.MethodPost, "sys/auth/"+trimPath(path), body, nil)
}

// DisableAuthMethod unmounts the auth method at path.
func (c *restClient) DisableAuthMethod(ctx context.Context, path string) error {
	return c.do(ctx, http.MethodDelete, "sys/auth/"+trimPath(path), nil, nil)
}

// ReadAuthMethod reads the auth method mounted at path.
//
// sys/auth/<path> is a WRITE-only endpoint; the read lives at
// sys/mounts/auth/<path> in newer Vault and at sys/auth (the full list) in
// older. Reading the mount directly is the portable form and is what the
// create-or-update decision depends on.
func (c *restClient) ReadAuthMethod(ctx context.Context, path string) (*AuthMethod, error) {
	var resp secret
	if err := c.do(ctx, http.MethodGet, "sys/mounts/auth/"+trimPath(path), nil, &resp); err != nil {
		return nil, err
	}
	var data struct {
		Type        string `json:"type"`
		Description string `json:"description"`
		Config      struct {
			DefaultLeaseTTL int `json:"default_lease_ttl"`
			MaxLeaseTTL     int `json:"max_lease_ttl"`
		} `json:"config"`
	}
	if err := resp.decodeData(&data); err != nil {
		return nil, err
	}
	return &AuthMethod{
		Type:        data.Type,
		Path:        trimPath(path),
		Description: data.Description,
		Config: &AuthMethodConfig{
			DefaultLeaseTTL: secondsToTTL(data.Config.DefaultLeaseTTL),
			MaxLeaseTTL:     secondsToTTL(data.Config.MaxLeaseTTL),
			Description:     data.Description,
		},
	}, nil
}

// TuneAuthMethod adjusts the mount configuration of an auth method.
func (c *restClient) TuneAuthMethod(ctx context.Context, path string, config *AuthMethodConfig) error {
	if config == nil {
		return fmt.Errorf("vault: tune configuration is required")
	}
	return c.do(ctx, http.MethodPost, "sys/auth/"+trimPath(path)+"/tune", tuneConfig(config), nil)
}

// --- JWT/OIDC auth ---

// WriteJWTRole creates or updates a JWT auth role.
func (c *restClient) WriteJWTRole(ctx context.Context, path, roleName string, role *JWTRole) error {
	if role == nil {
		return fmt.Errorf("vault: role is required")
	}
	return c.do(ctx, http.MethodPost, authRolePath(path, roleName), role, nil)
}

// ReadJWTRole reads a JWT auth role.
func (c *restClient) ReadJWTRole(ctx context.Context, path, roleName string) (*JWTRole, error) {
	var resp secret
	if err := c.do(ctx, http.MethodGet, authRolePath(path, roleName), nil, &resp); err != nil {
		return nil, err
	}
	var role JWTRole
	if err := resp.decodeData(&role); err != nil {
		return nil, err
	}
	return &role, nil
}

// DeleteJWTRole deletes a JWT auth role.
func (c *restClient) DeleteJWTRole(ctx context.Context, path, roleName string) error {
	return c.do(ctx, http.MethodDelete, authRolePath(path, roleName), nil, nil)
}

// WriteJWTConfig configures the JWT auth method's issuer trust.
func (c *restClient) WriteJWTConfig(ctx context.Context, path string, config *JWTAuthConfig) error {
	if config == nil {
		return fmt.Errorf("vault: config is required")
	}
	return c.do(ctx, http.MethodPost, "auth/"+trimPath(path)+"/config", config, nil)
}

// ReadJWTConfig reads the JWT auth method's configuration.
func (c *restClient) ReadJWTConfig(ctx context.Context, path string) (*JWTAuthConfig, error) {
	var resp secret
	if err := c.do(ctx, http.MethodGet, "auth/"+trimPath(path)+"/config", nil, &resp); err != nil {
		return nil, err
	}
	var config JWTAuthConfig
	if err := resp.decodeData(&config); err != nil {
		return nil, err
	}
	return &config, nil
}

// --- AWS auth ---

// WriteAWSRole creates or updates an AWS auth role.
func (c *restClient) WriteAWSRole(ctx context.Context, path, roleName string, role *AWSRole) error {
	if role == nil {
		return fmt.Errorf("vault: role is required")
	}
	return c.do(ctx, http.MethodPost, authRolePath(path, roleName), role, nil)
}

// ReadAWSRole reads an AWS auth role.
func (c *restClient) ReadAWSRole(ctx context.Context, path, roleName string) (*AWSRole, error) {
	var resp secret
	if err := c.do(ctx, http.MethodGet, authRolePath(path, roleName), nil, &resp); err != nil {
		return nil, err
	}
	var role AWSRole
	if err := resp.decodeData(&role); err != nil {
		return nil, err
	}
	return &role, nil
}

// DeleteAWSRole deletes an AWS auth role.
func (c *restClient) DeleteAWSRole(ctx context.Context, path, roleName string) error {
	return c.do(ctx, http.MethodDelete, authRolePath(path, roleName), nil, nil)
}

// WriteAWSConfig configures the AWS auth method's client credentials.
//
// The path is config/client, not config: the AWS auth method has several config
// endpoints (client, identity, certificate, sts) and writing to the wrong one
// succeeds while configuring nothing that matters.
func (c *restClient) WriteAWSConfig(ctx context.Context, path string, config *AWSAuthConfig) error {
	if config == nil {
		return fmt.Errorf("vault: config is required")
	}
	return c.do(ctx, http.MethodPost, "auth/"+trimPath(path)+"/config/client", config, nil)
}

// --- Secrets engines ---

// EnableSecretsEngine mounts a secrets engine at path.
func (c *restClient) EnableSecretsEngine(ctx context.Context, path, engineType string, config *SecretsEngineConfig) error {
	body := map[string]any{"type": engineType}
	if config != nil {
		if config.Description != "" {
			body["description"] = config.Description
		}
		if cfg := mountConfig(config); len(cfg) > 0 {
			body["config"] = cfg
		}
	}
	return c.do(ctx, http.MethodPost, "sys/mounts/"+trimPath(path), body, nil)
}

// DisableSecretsEngine unmounts the secrets engine at path.
func (c *restClient) DisableSecretsEngine(ctx context.Context, path string) error {
	return c.do(ctx, http.MethodDelete, "sys/mounts/"+trimPath(path), nil, nil)
}

// --- AWS secrets engine ---

// WriteAWSSecretsRole creates or updates an AWS secrets engine role.
func (c *restClient) WriteAWSSecretsRole(ctx context.Context, path, roleName string, role *AWSSecretsRole) error {
	if role == nil {
		return fmt.Errorf("vault: role is required")
	}
	return c.do(ctx, http.MethodPost, secretsRolePath(path, roleName), role, nil)
}

// ReadAWSSecretsRole reads an AWS secrets engine role.
func (c *restClient) ReadAWSSecretsRole(ctx context.Context, path, roleName string) (*AWSSecretsRole, error) {
	var resp secret
	if err := c.do(ctx, http.MethodGet, secretsRolePath(path, roleName), nil, &resp); err != nil {
		return nil, err
	}
	var role AWSSecretsRole
	if err := resp.decodeData(&role); err != nil {
		return nil, err
	}
	return &role, nil
}

// GenerateAWSCredentials issues dynamic AWS credentials for a role.
func (c *restClient) GenerateAWSCredentials(ctx context.Context, path, roleName string) (*AWSCredentials, error) {
	return c.awsCreds(ctx, "creds", path, roleName, nil)
}

// GenerateAWSCredentialsWithTTL issues dynamic AWS credentials with an explicit TTL.
func (c *restClient) GenerateAWSCredentialsWithTTL(ctx context.Context, path, roleName, ttl string) (*AWSCredentials, error) {
	query := map[string]string{}
	if ttl != "" {
		query["ttl"] = ttl
	}
	return c.awsCreds(ctx, "creds", path, roleName, query)
}

// GenerateAWSSTSCredentials issues STS credentials, optionally for a role ARN.
//
// The sts endpoint, not creds: they issue different credential kinds, and the
// STS one is what an assumed-role credential type requires.
func (c *restClient) GenerateAWSSTSCredentials(ctx context.Context, path, roleName, roleARN, ttl string) (*AWSCredentials, error) {
	query := map[string]string{}
	if roleARN != "" {
		query["role_arn"] = roleARN
	}
	if ttl != "" {
		query["ttl"] = ttl
	}
	return c.awsCreds(ctx, "sts", path, roleName, query)
}

// awsCreds reads one of the AWS secrets engine's credential endpoints.
func (c *restClient) awsCreds(ctx context.Context, kind, path, roleName string, query map[string]string) (*AWSCredentials, error) {
	endpoint := fmt.Sprintf("%s/%s/%s", trimPath(path), kind, roleName) + encodeQuery(query)
	var resp secret
	if err := c.do(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		return nil, err
	}
	var data struct {
		AccessKey     string `json:"access_key"`
		SecretKey     string `json:"secret_key"`
		SecurityToken string `json:"security_token"`
	}
	if err := resp.decodeData(&data); err != nil {
		return nil, err
	}
	return &AWSCredentials{
		AccessKey:     data.AccessKey,
		SecretKey:     data.SecretKey,
		SessionToken:  data.SecurityToken,
		LeaseDuration: resp.LeaseDuration,
		LeaseID:       resp.LeaseID,
	}, nil
}

// --- GCP secrets engine ---

// GenerateGCPAccessToken issues a GCP OAuth access token for a roleset.
func (c *restClient) GenerateGCPAccessToken(ctx context.Context, path, roleName string) (*GCPAccessToken, error) {
	var resp secret
	endpoint := fmt.Sprintf("%s/roleset/%s/token", trimPath(path), roleName)
	if err := c.do(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		return nil, err
	}
	var data struct {
		Token            string `json:"token"`
		ExpiresAtSeconds int64  `json:"expires_at_seconds"`
		TokenTTL         int    `json:"token_ttl"`
	}
	if err := resp.decodeData(&data); err != nil {
		return nil, err
	}
	return &GCPAccessToken{
		Token:            data.Token,
		ExpiresAtSeconds: data.ExpiresAtSeconds,
		TokenTTL:         data.TokenTTL,
		LeaseID:          resp.LeaseID,
		LeaseDuration:    resp.LeaseDuration,
	}, nil
}

// GenerateGCPServiceAccountKey issues a GCP service account key for a roleset.
//
// This mints a LONG-LIVED credential, unlike every other call here. It exists
// because the Vault broker supports it, not because it is a good idea: prefer
// GenerateGCPAccessToken, which expires.
func (c *restClient) GenerateGCPServiceAccountKey(ctx context.Context, path, roleName string) (*GCPServiceAccountKey, error) {
	var resp secret
	endpoint := fmt.Sprintf("%s/roleset/%s/key", trimPath(path), roleName)
	if err := c.do(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		return nil, err
	}
	var data struct {
		PrivateKeyData string `json:"private_key_data"`
		KeyAlgorithm   string `json:"key_algorithm"`
		KeyType        string `json:"key_type"`
	}
	if err := resp.decodeData(&data); err != nil {
		return nil, err
	}
	return &GCPServiceAccountKey{
		PrivateKeyData: data.PrivateKeyData,
		KeyAlgorithm:   data.KeyAlgorithm,
		KeyType:        data.KeyType,
		LeaseID:        resp.LeaseID,
		LeaseDuration:  resp.LeaseDuration,
	}, nil
}

// --- Azure secrets engine ---

// GenerateAzureCredentials issues Azure service principal credentials.
func (c *restClient) GenerateAzureCredentials(ctx context.Context, path, roleName string) (*AzureCredentials, error) {
	var resp secret
	endpoint := fmt.Sprintf("%s/creds/%s", trimPath(path), roleName)
	if err := c.do(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		return nil, err
	}
	var data struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := resp.decodeData(&data); err != nil {
		return nil, err
	}
	return &AzureCredentials{
		ClientID:      data.ClientID,
		ClientSecret:  data.ClientSecret,
		LeaseDuration: resp.LeaseDuration,
		LeaseID:       resp.LeaseID,
	}, nil
}

// --- Policies ---

// WritePolicy creates or updates an ACL policy.
func (c *restClient) WritePolicy(ctx context.Context, name, policy string) error {
	body := map[string]string{"policy": policy}
	return c.do(ctx, http.MethodPut, "sys/policies/acl/"+name, body, nil)
}

// DeletePolicy deletes an ACL policy.
func (c *restClient) DeletePolicy(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, "sys/policies/acl/"+name, nil, nil)
}

// ReadPolicy reads an ACL policy document.
func (c *restClient) ReadPolicy(ctx context.Context, name string) (string, error) {
	var resp secret
	if err := c.do(ctx, http.MethodGet, "sys/policies/acl/"+name, nil, &resp); err != nil {
		return "", err
	}
	var data struct {
		Policy string `json:"policy"`
	}
	if err := resp.decodeData(&data); err != nil {
		return "", err
	}
	return data.Policy, nil
}

// --- Tokens ---

// CreateToken issues a new Vault token.
func (c *restClient) CreateToken(ctx context.Context, opts *CreateTokenOptions) (*TokenResponse, error) {
	if opts == nil {
		opts = &CreateTokenOptions{}
	}
	body := map[string]any{"renewable": opts.Renewable}
	if len(opts.Policies) > 0 {
		body["policies"] = opts.Policies
	}
	if opts.TTL != "" {
		body["ttl"] = opts.TTL
	}
	if opts.DisplayName != "" {
		body["display_name"] = opts.DisplayName
	}
	if opts.NumUses > 0 {
		body["num_uses"] = opts.NumUses
	}
	if len(opts.Metadata) > 0 {
		body["meta"] = opts.Metadata
	}

	var resp secret
	if err := c.do(ctx, http.MethodPost, "auth/token/create", body, &resp); err != nil {
		return nil, err
	}
	if resp.Auth == nil {
		return nil, fmt.Errorf("vault: token response carried no auth block")
	}
	return &TokenResponse{
		Token:         resp.Auth.ClientToken,
		Accessor:      resp.Auth.Accessor,
		LeaseDuration: resp.Auth.LeaseDuration,
		Renewable:     resp.Auth.Renewable,
		Policies:      resp.Auth.Policies,
	}, nil
}

// --- Path helpers ---

// trimPath normalizes a mount path: no leading or trailing slash.
//
// Vault treats "auth/jwt/" and "auth/jwt" as the same mount but builds different
// request URLs from them, and a doubled slash is a 404 that reads like a missing
// mount rather than a typo.
func trimPath(path string) string {
	return strings.Trim(path, "/")
}

// authRolePath builds auth/<mount>/role/<name>.
func authRolePath(mount, role string) string {
	return fmt.Sprintf("auth/%s/role/%s", trimPath(mount), role)
}

// secretsRolePath builds <mount>/roles/<name>.
//
// Note "roles", plural — the secrets engines use it where the auth methods use
// the singular "role". Getting this wrong is a 404 on a mount that exists.
func secretsRolePath(mount, role string) string {
	return fmt.Sprintf("%s/roles/%s", trimPath(mount), role)
}

// tuneConfig renders the mount-tuning fields Vault accepts.
func tuneConfig(config *AuthMethodConfig) map[string]any {
	out := map[string]any{}
	if config == nil {
		return out
	}
	if config.DefaultLeaseTTL != "" {
		out["default_lease_ttl"] = config.DefaultLeaseTTL
	}
	if config.MaxLeaseTTL != "" {
		out["max_lease_ttl"] = config.MaxLeaseTTL
	}
	if config.Description != "" {
		out["description"] = config.Description
	}
	return out
}

// mountConfig renders the same fields for a secrets engine mount.
func mountConfig(config *SecretsEngineConfig) map[string]any {
	if config == nil {
		return map[string]any{}
	}
	return tuneConfig(&AuthMethodConfig{
		DefaultLeaseTTL: config.DefaultLeaseTTL,
		MaxLeaseTTL:     config.MaxLeaseTTL,
		Description:     config.Description,
	})
}

// secondsToTTL renders a Vault duration as the string form the write side takes,
// so a value read back can be written back unchanged.
func secondsToTTL(seconds int) string {
	if seconds == 0 {
		return ""
	}
	return strconv.Itoa(seconds) + "s"
}

// encodeQuery renders a sorted query string, or "" when empty.
func encodeQuery(query map[string]string) string {
	if len(query) == 0 {
		return ""
	}
	parts := make([]string, 0, len(query))
	for k, v := range query {
		parts = append(parts, k+"="+urlQueryEscape(v))
	}
	// Sorted so a request is reproducible and diffable in a test.
	sortStrings(parts)
	return "?" + strings.Join(parts, "&")
}

// --- Enumeration ---

// ListAuthMethods returns the mounted auth methods keyed by path.
//
// sys/auth returns the mount table as a map whose KEYS are the paths, with a
// trailing slash on each. The trailing slash is stripped here so a caller can
// join the path without producing a doubled separator — the same normalization
// trimPath does everywhere else.
func (c *restClient) ListAuthMethods(ctx context.Context) (map[string]*AuthMethod, error) {
	var resp secret
	if err := c.do(ctx, http.MethodGet, "sys/auth", nil, &resp); err != nil {
		return nil, err
	}

	// sys/auth answers with the mount table at the TOP level on older Vault and
	// under "data" on newer. Try data first, then fall back.
	raw := resp.Data
	if len(raw) == 0 {
		return map[string]*AuthMethod{}, nil
	}

	var table map[string]struct {
		Type        string `json:"type"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(raw, &table); err != nil {
		return nil, fmt.Errorf("vault: decoding the auth mount table: %w", err)
	}

	out := make(map[string]*AuthMethod, len(table))
	for path, mount := range table {
		trimmed := trimPath(path)
		out[trimmed] = &AuthMethod{
			Type: mount.Type, Path: trimmed, Description: mount.Description,
		}
	}
	return out, nil
}

// ListRoleNames lists the role names on one auth mount.
//
// Vault lists with the LIST verb, which most HTTP clients cannot send; the
// documented equivalent is GET with ?list=true. A mount with no roles answers
// 404, which is not an error — it is an empty list, and treating it as a failure
// would abort an inventory over the first unused mount it met.
func (c *restClient) ListRoleNames(ctx context.Context, path string) ([]string, error) {
	var resp secret
	endpoint := fmt.Sprintf("auth/%s/role?list=true", trimPath(path))
	if err := c.do(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		var apiErr *apiError
		if errors.As(err, &apiErr) && apiErr.NotFound() {
			return nil, nil
		}
		return nil, err
	}

	var data struct {
		Keys []string `json:"keys"`
	}
	if err := resp.decodeData(&data); err != nil {
		return nil, nil
	}
	return data.Keys, nil
}
