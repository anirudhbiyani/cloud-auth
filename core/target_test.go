package core

import (
	"strings"
	"testing"
)

// The point of per-cloud types: an impossible combination cannot be written
// down. This test documents what each type requires, and that each rejects an
// incomplete binding before any network call.
func TestTargetValidation(t *testing.T) {
	tests := []struct {
		name    string
		target  Target
		wantErr string
	}{
		{"aws ok", AWSTarget{RoleARN: "arn:aws:iam::123456789012:role/deploy"}, ""},
		{"aws govcloud", AWSTarget{RoleARN: "arn:aws-us-gov:iam::123456789012:role/deploy"}, ""},
		{"aws china", AWSTarget{RoleARN: "arn:aws-cn:iam::123456789012:role/deploy"}, ""},
		{"aws no role", AWSTarget{}, "role ARN is required"},
		{"aws short account", AWSTarget{RoleARN: "arn:aws:iam::1:role/r"}, "invalid AWS role ARN"},
		{"aws not an arn", AWSTarget{RoleARN: "deploy"}, "invalid AWS role ARN"},
		{
			"aws duration too short",
			AWSTarget{RoleARN: "arn:aws:iam::123456789012:role/r", DurationSeconds: 60},
			"between 900 and 43200",
		},

		{
			"gcp ok, full form",
			GCPTarget{WorkloadIdentityPool: "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/x"},
			"",
		},
		{
			"gcp ok, bare form",
			GCPTarget{WorkloadIdentityPool: "projects/1/locations/global/workloadIdentityPools/p/providers/x"},
			"",
		},
		{"gcp no pool", GCPTarget{}, "workload_identity_pool is required"},
		{"gcp nonsense pool", GCPTarget{WorkloadIdentityPool: "my-pool"}, "not a provider resource name"},
		{
			"gcp bad sa",
			GCPTarget{
				WorkloadIdentityPool:      "projects/1/locations/global/workloadIdentityPools/p/providers/x",
				ImpersonateServiceAccount: "not-an-email",
			},
			"invalid GCP service account email",
		},

		{
			"azure ok",
			AzureTarget{
				Tenant:   "11111111-1111-1111-1111-111111111111",
				ClientID: "22222222-2222-2222-2222-222222222222",
				Scope:    "https://storage.azure.com/.default",
			},
			"",
		},
		{
			"azure domain tenant",
			AzureTarget{
				Tenant:   "contoso.onmicrosoft.com",
				ClientID: "22222222-2222-2222-2222-222222222222",
				Scope:    "s",
			},
			"",
		},
		{
			"azure multi-tenant alias",
			AzureTarget{Tenant: "common", ClientID: "22222222-2222-2222-2222-222222222222", Scope: "s"},
			"multi-tenant alias",
		},
		{
			"azure client id not a uuid",
			AzureTarget{Tenant: "11111111-1111-1111-1111-111111111111", ClientID: "app", Scope: "s"},
			"invalid Azure UUID",
		},
		{
			"azure no scope",
			AzureTarget{
				Tenant:   "11111111-1111-1111-1111-111111111111",
				ClientID: "22222222-2222-2222-2222-222222222222",
			},
			"scope is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.target.Validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("want valid, got %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("want an error containing %q, got nil", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("want an error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// Each cloud's audience has one correct value or one conventional one, so
// requiring the caller to restate it adds nothing but a chance to get it wrong.
func TestTargetAudienceDefaults(t *testing.T) {
	if got := (AWSTarget{RoleARN: "r"}).Audience(); got != DefaultAWSAudience {
		t.Errorf("aws audience = %q, want %q", got, DefaultAWSAudience)
	}
	if got := (AzureTarget{}).Audience(); got != DefaultAzureAudience {
		t.Errorf("azure audience = %q, want %q", got, DefaultAzureAudience)
	}

	const bare = "projects/1/locations/global/workloadIdentityPools/p/providers/x"
	const full = "//iam.googleapis.com/" + bare
	if got := (GCPTarget{WorkloadIdentityPool: bare}).Audience(); got != full {
		t.Errorf("gcp audience = %q, want the normalized %q", got, full)
	}
	if got := (GCPTarget{WorkloadIdentityPool: full}).Audience(); got != full {
		t.Errorf("gcp audience = %q, want %q unchanged", got, full)
	}

	// An explicit override always wins.
	if got := (AWSTarget{RoleARN: "r", TokenAudience: "custom"}).Audience(); got != "custom" {
		t.Errorf("explicit audience should win, got %q", got)
	}
}

func TestTargetCloudIsImpliedByType(t *testing.T) {
	cases := map[Target]Cloud{
		AWSTarget{}:   AWS,
		GCPTarget{}:   GCP,
		AzureTarget{}: Azure,
	}
	for target, want := range cases {
		if got := target.Cloud(); got != want {
			t.Errorf("%T.Cloud() = %s, want %s", target, got, want)
		}
	}
}
