package aws

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// IAM's own bounds for a role's maximum session duration. Mirrors the range
// core.AWSRoleTrustOIDCSpec validates, so a library caller bypassing the spec
// gets the same answer the CLI would give.
const (
	iamMinSessionDuration = 3600
	iamMaxSessionDuration = 43200
)

// This file is the concrete IAMClient: the bridge between the provider's
// cloud-neutral interface and the real AWS IAM API. Without it the control
// plane could describe what it would do but never do it — Setup failed with
// "AWS IAM client not configured" because nothing ever supplied a client.

// iamAPI is the subset of *iam.Client the wrapper uses. Depending on an
// interface rather than the concrete client keeps pagination, decoding and
// error-mapping testable without AWS credentials.
type iamAPI interface {
	GetRole(context.Context, *iam.GetRoleInput, ...func(*iam.Options)) (*iam.GetRoleOutput, error)
	CreateRole(context.Context, *iam.CreateRoleInput, ...func(*iam.Options)) (*iam.CreateRoleOutput, error)
	UpdateAssumeRolePolicy(context.Context, *iam.UpdateAssumeRolePolicyInput, ...func(*iam.Options)) (*iam.UpdateAssumeRolePolicyOutput, error)
	DeleteRole(context.Context, *iam.DeleteRoleInput, ...func(*iam.Options)) (*iam.DeleteRoleOutput, error)
	TagRole(context.Context, *iam.TagRoleInput, ...func(*iam.Options)) (*iam.TagRoleOutput, error)

	AttachRolePolicy(context.Context, *iam.AttachRolePolicyInput, ...func(*iam.Options)) (*iam.AttachRolePolicyOutput, error)
	DetachRolePolicy(context.Context, *iam.DetachRolePolicyInput, ...func(*iam.Options)) (*iam.DetachRolePolicyOutput, error)
	PutRolePolicy(context.Context, *iam.PutRolePolicyInput, ...func(*iam.Options)) (*iam.PutRolePolicyOutput, error)
	DeleteRolePolicy(context.Context, *iam.DeleteRolePolicyInput, ...func(*iam.Options)) (*iam.DeleteRolePolicyOutput, error)
	ListAttachedRolePolicies(context.Context, *iam.ListAttachedRolePoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	ListRolePolicies(context.Context, *iam.ListRolePoliciesInput, ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error)
	ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error)

	GetOpenIDConnectProvider(context.Context, *iam.GetOpenIDConnectProviderInput, ...func(*iam.Options)) (*iam.GetOpenIDConnectProviderOutput, error)
	CreateOpenIDConnectProvider(context.Context, *iam.CreateOpenIDConnectProviderInput, ...func(*iam.Options)) (*iam.CreateOpenIDConnectProviderOutput, error)
	DeleteOpenIDConnectProvider(context.Context, *iam.DeleteOpenIDConnectProviderInput, ...func(*iam.Options)) (*iam.DeleteOpenIDConnectProviderOutput, error)
	ListOpenIDConnectProviders(context.Context, *iam.ListOpenIDConnectProvidersInput, ...func(*iam.Options)) (*iam.ListOpenIDConnectProvidersOutput, error)
}

// realIAMClient implements IAMClient against the AWS IAM API.
type realIAMClient struct{ api iamAPI }

// compile-time proof the wrapper satisfies the provider's interface.
var _ IAMClient = (*realIAMClient)(nil)

// credentialResolveTimeout bounds how long the SDK's default chain may spend
// looking for credentials.
//
// The chain ends at EC2 IMDS, and off-EC2 that endpoint is a link-local address
// nothing answers. With the SDK's own retries that took roughly two minutes to
// give up, which a CLI user reads as a hang rather than "no credentials here" —
// including on `setup --dry-run`, which should not need credentials at all.
const credentialResolveTimeout = 10 * time.Second

// NewIAMClient builds an IAMClient from the ambient AWS configuration
// (environment, shared config/credentials, SSO, instance role — whatever the
// SDK's default chain resolves).
//
// Note which identity that is: whatever the ambient chain happens to resolve,
// which on a host with AWS_ACCESS_KEY_ID set is not the instance role. Callers
// that need a specific identity should pass config options rather than relying
// on the default.
func NewIAMClient(ctx context.Context, optFns ...func(*awsconfig.LoadOptions) error) (IAMClient, error) {
	// Bound the credential lookup, but keep the returned client tied to the
	// caller's context for actual API calls.
	loadCtx, cancel := context.WithTimeout(ctx, credentialResolveTimeout)
	defer cancel()

	opts := append([]func(*awsconfig.LoadOptions) error{
		// Cap the IMDS probe rather than waiting out the default retry budget.
		awsconfig.WithEC2IMDSRegion(),
		awsconfig.WithRetryMaxAttempts(2),
	}, optFns...)

	cfg, err := awsconfig.LoadDefaultConfig(loadCtx, opts...)
	if err != nil {
		return nil, fmt.Errorf("aws: loading configuration: %w", err)
	}
	return &realIAMClient{api: iam.NewFromConfig(cfg)}, nil
}

// IsNotFound reports whether an error is IAM's "no such entity". Setup branches
// on this to decide between creating and updating, so it must be distinguishable
// from a permission or network failure.
func IsNotFound(err error) bool {
	var nse *iamtypes.NoSuchEntityException
	return errors.As(err, &nse)
}

func toTags(m map[string]string) []iamtypes.Tag {
	if len(m) == 0 {
		return nil
	}
	tags := make([]iamtypes.Tag, 0, len(m))
	for k, v := range m {
		tags = append(tags, iamtypes.Tag{Key: aws.String(k), Value: aws.String(v)})
	}
	return tags
}

func fromTags(ts []iamtypes.Tag) map[string]string {
	if len(ts) == 0 {
		return nil
	}
	m := make(map[string]string, len(ts))
	for _, t := range ts {
		m[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	return m
}

// ---- roles ----------------------------------------------------------------

func (c *realIAMClient) GetRole(ctx context.Context, roleName string) (*Role, error) {
	out, err := c.api.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(roleName)})
	if err != nil {
		return nil, err
	}
	if out == nil || out.Role == nil {
		return nil, fmt.Errorf("aws: empty GetRole response for %s", roleName)
	}
	r := out.Role

	// IAM returns the assume-role policy percent-encoded; decode it so callers
	// (and the trust-policy validator) get parseable JSON.
	doc := aws.ToString(r.AssumeRolePolicyDocument)
	if decoded, derr := url.QueryUnescape(doc); derr == nil {
		doc = decoded
	}

	return &Role{
		ARN:                      aws.ToString(r.Arn),
		RoleName:                 aws.ToString(r.RoleName),
		AssumeRolePolicyDocument: doc,
		Description:              aws.ToString(r.Description),
		MaxSessionDuration:       int(aws.ToInt32(r.MaxSessionDuration)),
		Tags:                     fromTags(r.Tags),
	}, nil
}

func (c *realIAMClient) CreateRole(ctx context.Context, in *CreateRoleInput) (*Role, error) {
	req := &iam.CreateRoleInput{
		RoleName:                 aws.String(in.RoleName),
		AssumeRolePolicyDocument: aws.String(in.AssumeRolePolicyDocument),
		Tags:                     toTags(in.Tags),
	}
	if in.Description != "" {
		req.Description = aws.String(in.Description)
	}
	if in.MaxSessionDuration > 0 {
		// Reject rather than convert. int -> int32 truncation turns 2^32+3600
		// into 3600: a silently shortened session that still looks valid to
		// every caller. Spec-driven callers are already bounds-checked in
		// core, but CreateRoleInput is exported and this is the last gate.
		if in.MaxSessionDuration < iamMinSessionDuration || in.MaxSessionDuration > iamMaxSessionDuration {
			return nil, fmt.Errorf("aws: MaxSessionDuration %d out of range (%d-%d seconds)",
				in.MaxSessionDuration, iamMinSessionDuration, iamMaxSessionDuration)
		}
		req.MaxSessionDuration = aws.Int32(int32(in.MaxSessionDuration))
	}
	if in.PermissionsBoundary != "" {
		req.PermissionsBoundary = aws.String(in.PermissionsBoundary)
	}

	out, err := c.api.CreateRole(ctx, req)
	if err != nil {
		return nil, err
	}
	if out == nil || out.Role == nil {
		return nil, fmt.Errorf("aws: empty CreateRole response for %s", in.RoleName)
	}
	return &Role{
		ARN:                aws.ToString(out.Role.Arn),
		RoleName:           aws.ToString(out.Role.RoleName),
		Description:        aws.ToString(out.Role.Description),
		MaxSessionDuration: int(aws.ToInt32(out.Role.MaxSessionDuration)),
		Tags:               fromTags(out.Role.Tags),
	}, nil
}

func (c *realIAMClient) UpdateAssumeRolePolicy(ctx context.Context, roleName, policy string) error {
	_, err := c.api.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{
		RoleName:       aws.String(roleName),
		PolicyDocument: aws.String(policy),
	})
	return err
}

func (c *realIAMClient) DeleteRole(ctx context.Context, roleName string) error {
	_, err := c.api.DeleteRole(ctx, &iam.DeleteRoleInput{RoleName: aws.String(roleName)})
	return err
}

func (c *realIAMClient) TagRole(ctx context.Context, roleName string, tags map[string]string) error {
	if len(tags) == 0 {
		return nil
	}
	_, err := c.api.TagRole(ctx, &iam.TagRoleInput{
		RoleName: aws.String(roleName),
		Tags:     toTags(tags),
	})
	return err
}

// ---- policies -------------------------------------------------------------

func (c *realIAMClient) AttachRolePolicy(ctx context.Context, roleName, policyARN string) error {
	_, err := c.api.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{
		RoleName:  aws.String(roleName),
		PolicyArn: aws.String(policyARN),
	})
	return err
}

func (c *realIAMClient) DetachRolePolicy(ctx context.Context, roleName, policyARN string) error {
	_, err := c.api.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{
		RoleName:  aws.String(roleName),
		PolicyArn: aws.String(policyARN),
	})
	return err
}

func (c *realIAMClient) PutRolePolicy(ctx context.Context, roleName, policyName, policyDocument string) error {
	_, err := c.api.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
		RoleName:       aws.String(roleName),
		PolicyName:     aws.String(policyName),
		PolicyDocument: aws.String(policyDocument),
	})
	return err
}

func (c *realIAMClient) DeleteRolePolicy(ctx context.Context, roleName, policyName string) error {
	_, err := c.api.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{
		RoleName:   aws.String(roleName),
		PolicyName: aws.String(policyName),
	})
	return err
}

// ListAttachedRolePolicies walks every page: a truncated first page would make a
// drift check report attached policies as missing.
func (c *realIAMClient) ListAttachedRolePolicies(ctx context.Context, roleName string) ([]string, error) {
	var (
		arns   []string
		marker *string
	)
	for {
		out, err := c.api.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
			RoleName: aws.String(roleName),
			Marker:   marker,
		})
		if err != nil {
			return nil, err
		}
		for _, p := range out.AttachedPolicies {
			arns = append(arns, aws.ToString(p.PolicyArn))
		}
		if !out.IsTruncated || out.Marker == nil {
			return arns, nil
		}
		marker = out.Marker
	}
}

func (c *realIAMClient) ListRolePolicies(ctx context.Context, roleName string) ([]string, error) {
	var (
		names  []string
		marker *string
	)
	for {
		out, err := c.api.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
			RoleName: aws.String(roleName),
			Marker:   marker,
		})
		if err != nil {
			return nil, err
		}
		names = append(names, out.PolicyNames...)
		if !out.IsTruncated || out.Marker == nil {
			return names, nil
		}
		marker = out.Marker
	}
}

// ---- OIDC providers -------------------------------------------------------

func (c *realIAMClient) GetOpenIDConnectProvider(ctx context.Context, arn string) (*OIDCProvider, error) {
	out, err := c.api.GetOpenIDConnectProvider(ctx, &iam.GetOpenIDConnectProviderInput{
		OpenIDConnectProviderArn: aws.String(arn),
	})
	if err != nil {
		return nil, err
	}
	return &OIDCProvider{
		ARN:            arn,
		URL:            aws.ToString(out.Url),
		ClientIDList:   out.ClientIDList,
		ThumbprintList: out.ThumbprintList,
		Tags:           fromTags(out.Tags),
	}, nil
}

func (c *realIAMClient) CreateOpenIDConnectProvider(ctx context.Context, in *CreateOIDCProviderInput) (string, error) {
	out, err := c.api.CreateOpenIDConnectProvider(ctx, &iam.CreateOpenIDConnectProviderInput{
		Url:            aws.String(in.URL),
		ClientIDList:   in.ClientIDList,
		ThumbprintList: in.ThumbprintList,
		Tags:           toTags(in.Tags),
	})
	if err != nil {
		return "", err
	}
	return aws.ToString(out.OpenIDConnectProviderArn), nil
}

func (c *realIAMClient) DeleteOpenIDConnectProvider(ctx context.Context, arn string) error {
	_, err := c.api.DeleteOpenIDConnectProvider(ctx, &iam.DeleteOpenIDConnectProviderInput{
		OpenIDConnectProviderArn: aws.String(arn),
	})
	return err
}

func (c *realIAMClient) ListOpenIDConnectProviders(ctx context.Context) ([]string, error) {
	out, err := c.api.ListOpenIDConnectProviders(ctx, &iam.ListOpenIDConnectProvidersInput{})
	if err != nil {
		return nil, err
	}
	arns := make([]string, 0, len(out.OpenIDConnectProviderList))
	for _, p := range out.OpenIDConnectProviderList {
		arns = append(arns, aws.ToString(p.Arn))
	}
	return arns, nil
}

// ListRoles enumerates every role in the account.
//
// IAM's ListRoles returns each role's AssumeRolePolicyDocument inline, so this
// is one paginated call rather than a GetRole per role — which matters on an
// account with thousands of them, and matters more because IAM's rate limits
// are not generous.
func (c *realIAMClient) ListRoles(ctx context.Context) ([]*Role, error) {
	var out []*Role
	paginator := iam.NewListRolesPaginator(c.api, &iam.ListRolesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("aws: listing roles: %w", err)
		}
		for i := range page.Roles {
			r := page.Roles[i]
			doc := aws.ToString(r.AssumeRolePolicyDocument)
			// ListRoles returns the document URL-encoded, as GetRole does.
			if decoded, derr := url.QueryUnescape(doc); derr == nil {
				doc = decoded
			}
			out = append(out, &Role{
				ARN:                      aws.ToString(r.Arn),
				RoleName:                 aws.ToString(r.RoleName),
				AssumeRolePolicyDocument: doc,
				Description:              aws.ToString(r.Description),
				MaxSessionDuration:       int(aws.ToInt32(r.MaxSessionDuration)),
			})
		}
	}
	return out, nil
}
