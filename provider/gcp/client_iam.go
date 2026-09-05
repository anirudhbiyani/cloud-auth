package gcp

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Service account and IAM policy operations.

// saResource is the wire shape of a service account.
type saResource struct {
	Name        string `json:"name,omitempty"`
	ProjectID   string `json:"projectId,omitempty"`
	UniqueID    string `json:"uniqueId,omitempty"`
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

func (s *saResource) toDomain() *ServiceAccount {
	return &ServiceAccount{
		Name: s.Name, ProjectID: s.ProjectID, UniqueID: s.UniqueID,
		Email: s.Email, DisplayName: s.DisplayName,
	}
}

// GetServiceAccount reads a service account by resource name (projects/{project}/serviceAccounts/{email}).
func (c *restClient) GetServiceAccount(ctx context.Context, name string) (*ServiceAccount, error) {
	var out saResource
	if err := c.do(ctx, http.MethodGet, c.iamURL+"/"+name, nil, &out, name); err != nil {
		return nil, err
	}
	return out.toDomain(), nil
}

// CreateServiceAccount creates a service account in projectID.
func (c *restClient) CreateServiceAccount(ctx context.Context, projectID, accountID, displayName string) (*ServiceAccount, error) {
	endpoint := fmt.Sprintf("%s/projects/%s/serviceAccounts", c.iamURL, url.PathEscape(projectID))
	body := map[string]any{
		"accountId": accountID,
		"serviceAccount": map[string]string{
			"displayName": displayName,
		},
	}
	var out saResource
	if err := c.do(ctx, http.MethodPost, endpoint, body, &out, accountID); err != nil {
		return nil, err
	}
	return out.toDomain(), nil
}

// DeleteServiceAccount deletes a service account by resource name.
func (c *restClient) DeleteServiceAccount(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, c.iamURL+"/"+name, nil, nil, name)
}

// wirePolicy is the wire shape of an IAM policy.
type wirePolicy struct {
	Version  int           `json:"version,omitempty"`
	Etag     string        `json:"etag,omitempty"`
	Bindings []wireBinding `json:"bindings,omitempty"`
}

type wireBinding struct {
	Role      string         `json:"role"`
	Members   []string       `json:"members,omitempty"`
	Condition *wireCondition `json:"condition,omitempty"`
}

type wireCondition struct {
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Expression  string `json:"expression"`
}

// policyVersion 3 is required for conditional bindings.
const policyVersion = 3

// GetIAMPolicy reads the IAM policy on a resource.
func (c *restClient) GetIAMPolicy(ctx context.Context, resource string) (*IAMPolicy, error) {
	endpoint := fmt.Sprintf("%s/%s:getIamPolicy", c.iamURL, resource)
	body := map[string]any{
		"options": map[string]any{"requestedPolicyVersion": policyVersion},
	}
	var out wirePolicy
	if err := c.do(ctx, http.MethodPost, endpoint, body, &out, resource); err != nil {
		return nil, err
	}

	policy := &IAMPolicy{Etag: out.Etag, Version: out.Version}
	for _, b := range out.Bindings {
		binding := &IAMBinding{Role: b.Role, Members: b.Members}
		if b.Condition != nil {
			binding.Condition = &IAMCondition{
				Title:       b.Condition.Title,
				Description: b.Condition.Description,
				Expression:  b.Condition.Expression,
			}
		}
		policy.Bindings = append(policy.Bindings, binding)
	}
	return policy, nil
}

// SetIAMPolicy writes the IAM policy on a resource.
func (c *restClient) SetIAMPolicy(ctx context.Context, resource string, policy *IAMPolicy) error {
	if policy == nil {
		return fmt.Errorf("gcp: policy is required")
	}

	wire := wirePolicy{Etag: policy.Etag, Version: policyVersion}
	for _, b := range policy.Bindings {
		binding := wireBinding{Role: b.Role, Members: b.Members}
		if b.Condition != nil {
			binding.Condition = &wireCondition{
				Title:       b.Condition.Title,
				Description: b.Condition.Description,
				Expression:  b.Condition.Expression,
			}
		}
		wire.Bindings = append(wire.Bindings, binding)
	}

	endpoint := fmt.Sprintf("%s/%s:setIamPolicy", c.iamURL, resource)
	err := c.do(ctx, http.MethodPost, endpoint, map[string]any{"policy": wire}, nil, resource)
	if isEtagConflict(err) {
		return fmt.Errorf("%w (the policy changed since it was read; re-run to retry)", err)
	}
	return err
}

// isEtagConflict reports a lost compare-and-swap, so the caller can say what actually happened instead of reporting a bare 409.
func isEtagConflict(err error) bool {
	var apiErr *apiError
	if !errorsAs(err, &apiErr) {
		return false
	}
	return apiErr.StatusCode == http.StatusConflict &&
		strings.Contains(strings.ToLower(apiErr.Message), "etag")
}
