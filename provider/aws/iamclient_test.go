package aws

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// fakeIAMAPI stands in for *iam.Client so the wrapper's own logic — URL decoding, pagination, not-found mapping — is testable without AWS.
type fakeIAMAPI struct {
	iamAPI
	getRole      func(context.Context, *iam.GetRoleInput) (*iam.GetRoleOutput, error)
	listAttached func(context.Context, *iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error)
	listInline   func(context.Context, *iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error)
	listOIDC     func(context.Context, *iam.ListOpenIDConnectProvidersInput) (*iam.ListOpenIDConnectProvidersOutput, error)
	createRole   func(context.Context, *iam.CreateRoleInput) (*iam.CreateRoleOutput, error)
}

func (f *fakeIAMAPI) GetRole(ctx context.Context, in *iam.GetRoleInput, _ ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	return f.getRole(ctx, in)
}
func (f *fakeIAMAPI) ListAttachedRolePolicies(ctx context.Context, in *iam.ListAttachedRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	return f.listAttached(ctx, in)
}
func (f *fakeIAMAPI) ListRolePolicies(ctx context.Context, in *iam.ListRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error) {
	return f.listInline(ctx, in)
}
func (f *fakeIAMAPI) ListOpenIDConnectProviders(ctx context.Context, in *iam.ListOpenIDConnectProvidersInput, _ ...func(*iam.Options)) (*iam.ListOpenIDConnectProvidersOutput, error) {
	return f.listOIDC(ctx, in)
}
func (f *fakeIAMAPI) CreateRole(ctx context.Context, in *iam.CreateRoleInput, _ ...func(*iam.Options)) (*iam.CreateRoleOutput, error) {
	return f.createRole(ctx, in)
}

// IAM returns the assume-role policy URL-ENCODED.
func TestGetRoleDecodesURLEncodedPolicy(t *testing.T) {
	const policy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow"}]}`
	c := &realIAMClient{api: &fakeIAMAPI{
		getRole: func(_ context.Context, in *iam.GetRoleInput) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{Role: &iamtypes.Role{
				RoleName:                 in.RoleName,
				Arn:                      aws.String("arn:aws:iam::1:role/r"),
				AssumeRolePolicyDocument: aws.String(url.QueryEscape(policy)),
			}}, nil
		},
	}}

	got, err := c.GetRole(context.Background(), "r")
	if err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	if got.AssumeRolePolicyDocument != policy {
		t.Errorf("policy not decoded:\n got %q\nwant %q", got.AssumeRolePolicyDocument, policy)
	}
	if got.ARN != "arn:aws:iam::1:role/r" {
		t.Errorf("ARN = %q", got.ARN)
	}
}

// A missing role must be reported as "not found" rather than a raw SDK error, because Setup branches on it to decide create-vs-update.
func TestGetRoleNotFoundIsDistinguishable(t *testing.T) {
	c := &realIAMClient{api: &fakeIAMAPI{
		getRole: func(context.Context, *iam.GetRoleInput) (*iam.GetRoleOutput, error) {
			return nil, &iamtypes.NoSuchEntityException{}
		},
	}}
	_, err := c.GetRole(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected an error for a missing role")
	}
	if !IsNotFound(err) {
		t.Errorf("IsNotFound(%v) = false; Setup cannot tell create from update", err)
	}
}

// IAM paginates.
func TestListAttachedRolePoliciesPaginates(t *testing.T) {
	calls := 0
	c := &realIAMClient{api: &fakeIAMAPI{
		listAttached: func(_ context.Context, in *iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
			calls++
			if in.Marker == nil {
				return &iam.ListAttachedRolePoliciesOutput{
					AttachedPolicies: []iamtypes.AttachedPolicy{{PolicyArn: aws.String("arn:p1")}},
					IsTruncated:      true,
					Marker:           aws.String("next"),
				}, nil
			}
			return &iam.ListAttachedRolePoliciesOutput{
				AttachedPolicies: []iamtypes.AttachedPolicy{{PolicyArn: aws.String("arn:p2")}},
			}, nil
		},
	}}
	got, err := c.ListAttachedRolePolicies(context.Background(), "r")
	if err != nil {
		t.Fatalf("ListAttachedRolePolicies: %v", err)
	}
	if len(got) != 2 || got[0] != "arn:p1" || got[1] != "arn:p2" {
		t.Errorf("got %v, want both pages", got)
	}
	if calls != 2 {
		t.Errorf("made %d calls, want 2 (second page not fetched?)", calls)
	}
}

func TestListRolePoliciesPaginates(t *testing.T) {
	c := &realIAMClient{api: &fakeIAMAPI{
		listInline: func(_ context.Context, in *iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error) {
			if in.Marker == nil {
				return &iam.ListRolePoliciesOutput{PolicyNames: []string{"a"}, IsTruncated: true, Marker: aws.String("m")}, nil
			}
			return &iam.ListRolePoliciesOutput{PolicyNames: []string{"b"}}, nil
		},
	}}
	got, err := c.ListRolePolicies(context.Background(), "r")
	if err != nil {
		t.Fatalf("ListRolePolicies: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %v, want both pages", got)
	}
}

func TestCreateRoleMapsTagsAndFields(t *testing.T) {
	var gotIn *iam.CreateRoleInput
	c := &realIAMClient{api: &fakeIAMAPI{
		createRole: func(_ context.Context, in *iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
			gotIn = in
			return &iam.CreateRoleOutput{Role: &iamtypes.Role{
				RoleName: in.RoleName, Arn: aws.String("arn:aws:iam::1:role/new"),
			}}, nil
		},
	}}
	_, err := c.CreateRole(context.Background(), &CreateRoleInput{
		RoleName:                 "new",
		AssumeRolePolicyDocument: `{"x":1}`,
		Description:              "demo",
		MaxSessionDuration:       3600,
		Tags:                     map[string]string{"managed-by": "cloud-auth"},
	})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if aws.ToString(gotIn.RoleName) != "new" || aws.ToString(gotIn.AssumeRolePolicyDocument) != `{"x":1}` {
		t.Errorf("fields not mapped: %+v", gotIn)
	}
	if aws.ToInt32(gotIn.MaxSessionDuration) != 3600 {
		t.Errorf("MaxSessionDuration = %v", gotIn.MaxSessionDuration)
	}
	if len(gotIn.Tags) != 1 || aws.ToString(gotIn.Tags[0].Key) != "managed-by" {
		t.Errorf("tags not mapped: %+v", gotIn.Tags)
	}
}

func TestIsNotFoundIgnoresOtherErrors(t *testing.T) {
	if IsNotFound(errors.New("AccessDenied")) {
		t.Error("IsNotFound must not treat unrelated errors as not-found")
	}
}

// The provider is registered at package init, long before credentials matter, so the client must be built lazily — and an injected fake must always win so tests never touch AWS.
func TestProviderIAMPrefersInjectedClient(t *testing.T) {
	injected := &stubIAM{}
	p := New(WithIAMClient(injected))
	got, err := p.iam(context.Background())
	if err != nil {
		t.Fatalf("iam(): %v", err)
	}
	if got != IAMClient(injected) {
		t.Error("iam() must return the injected client, not build a real one")
	}
}

func TestProviderIAMBuildsLazilyWhenAbsent(t *testing.T) {
	p := New() // how init() registers it: no client
	got, err := p.iam(context.Background())
	if err != nil {
		t.Skipf("no ambient AWS config in this environment: %v", err)
	}
	if got == nil {
		t.Fatal("iam() returned a nil client with no error")
	}
	// Cached: a second call must not rebuild.
	again, _ := p.iam(context.Background())
	if again != got {
		t.Error("iam() should cache the constructed client")
	}
}

// int -> int32 truncation would turn 2^32+3600 into a role that looks like it has a valid 1-hour session and silently does not have what was asked for.
func TestCreateRoleRejectsOutOfRangeSessionDuration(t *testing.T) {
	for _, tc := range []struct {
		name    string
		seconds int
		wantErr bool
	}{
		{"truncates to a valid-looking value", 1<<32 + 3600, true},
		{"above IAM maximum", 43201, true},
		{"below IAM minimum", 3599, true},
		{"at IAM minimum", 3600, false},
		{"at IAM maximum", 43200, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sent *iam.CreateRoleInput
			c := &realIAMClient{api: &fakeIAMAPI{
				createRole: func(_ context.Context, in *iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
					sent = in
					return &iam.CreateRoleOutput{Role: &iamtypes.Role{
						RoleName: in.RoleName,
						Arn:      aws.String("arn:aws:iam::1:role/r"),
					}}, nil
				},
			}}

			_, err := c.CreateRole(context.Background(), &CreateRoleInput{
				RoleName:                 "r",
				AssumeRolePolicyDocument: "{}",
				MaxSessionDuration:       tc.seconds,
			})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("MaxSessionDuration %d: want error, got none (sent %v)",
						tc.seconds, aws.ToInt32(sent.MaxSessionDuration))
				}
				if sent != nil {
					t.Errorf("rejected input still reached IAM")
				}
				return
			}
			if err != nil {
				t.Fatalf("MaxSessionDuration %d: %v", tc.seconds, err)
			}
			if got := aws.ToInt32(sent.MaxSessionDuration); got != int32(tc.seconds) {
				t.Errorf("MaxSessionDuration = %d, want %d", got, tc.seconds)
			}
		})
	}
}
