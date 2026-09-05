package core

import (
	"strings"
	"testing"
)

func gcpBase() *GCPWorkloadIdentityPoolSpec {
	return &GCPWorkloadIdentityPoolSpec{
		ProjectID:           "my-project",
		ProjectNumber:       "123456789012",
		PoolID:              "gh-pool",
		ProviderID:          "gh",
		ProviderType:        "oidc",
		OIDCIssuerURL:       "https://token.actions.githubusercontent.com",
		ServiceAccountEmail: "deployer@my-project.iam.gserviceaccount.com",
	}
}

// Two independent gates: the pool provider decides who may federate, the IAM binding decides who may then impersonate.
func TestGCPSpecRequiresBothGates(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*GCPWorkloadIdentityPoolSpec)
		wantErr string
	}{
		{"neither gate", func(s *GCPWorkloadIdentityPoolSpec) {}, "attribute_condition is required"},
		{
			"condition but no impersonation scope",
			func(s *GCPWorkloadIdentityPoolSpec) {
				s.AttributeCondition = `assertion.repository == "myorg/myrepo"`
			},
			"subject_scope or attribute_scope is required",
		},
		{
			"both scopes at once",
			func(s *GCPWorkloadIdentityPoolSpec) {
				s.AttributeCondition = `assertion.repository == "myorg/myrepo"`
				s.SubjectScope = "repo:myorg/myrepo:ref:refs/heads/main"
				s.AttributeScope = "repository/myorg/myrepo"
			},
			"mutually exclusive",
		},
		{
			"opt-out without a reason",
			func(s *GCPWorkloadIdentityPoolSpec) { s.AllowWholePoolImpersonation = true },
			"requires unscoped_justification",
		},
		{
			"both gates set",
			func(s *GCPWorkloadIdentityPoolSpec) {
				s.AttributeCondition = `assertion.repository == "myorg/myrepo"`
				s.SubjectScope = "repo:myorg/myrepo:ref:refs/heads/main"
			},
			"",
		},
		{
			"attribute scope is an acceptable alternative",
			func(s *GCPWorkloadIdentityPoolSpec) {
				s.AttributeCondition = `assertion.repository == "myorg/myrepo"`
				s.AttributeScope = "repository/myorg/myrepo"
			},
			"",
		},
		{
			"justified opt-out",
			func(s *GCPWorkloadIdentityPoolSpec) {
				s.AllowWholePoolImpersonation = true
				s.UnscopedJustification = "pool has exactly one provider and one workload"
			},
			"",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := gcpBase()
			tc.mutate(s)
			err := s.Validate()
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

// The IAM member string is what actually grants impersonation.
func TestImpersonationPrincipalIsScoped(t *testing.T) {
	const pool = "projects/123456789012/locations/global/workloadIdentityPools/gh-pool"
	const base = "principalSet://iam.googleapis.com/" + pool

	s := gcpBase()
	s.SubjectScope = "repo:myorg/myrepo:ref:refs/heads/main"
	if got, want := s.ImpersonationPrincipal(pool), base+"/subject/repo:myorg/myrepo:ref:refs/heads/main"; got != want {
		t.Errorf("subject scope:\n got %s\nwant %s", got, want)
	}

	s = gcpBase()
	s.AttributeScope = "repository/myorg/myrepo"
	if got, want := s.ImpersonationPrincipal(pool), base+"/attribute.repository/myorg/myrepo"; got != want {
		t.Errorf("attribute scope:\n got %s\nwant %s", got, want)
	}

	// Only reachable once Validate has demanded a justification.
	s = gcpBase()
	s.AllowWholePoolImpersonation = true
	if got, want := s.ImpersonationPrincipal(pool), base+"/*"; got != want {
		t.Errorf("opt-out:\n got %s\nwant %s", got, want)
	}
}

// Regression: the shared flag parser defaulted audience to sts.amazonaws.com for every mechanism type, so a GCP pool provider was created accepting the one audience every GitHub Actions run can request.
func TestGCPSpecDoesNotInheritTheAWSAudience(t *testing.T) {
	s := gcpBase()
	for _, aud := range s.AllowedAudiences {
		if aud == "sts.amazonaws.com" {
			t.Error("a GCP pool provider must not accept the AWS STS audience by default")
		}
	}
}
