package core

import (
	"strings"
	"testing"
)

func TestAWSSpecRequiresSubjectScope(t *testing.T) {
	base := func() *AWSRoleTrustOIDCSpec {
		return &AWSRoleTrustOIDCSpec{
			RoleName:        "deploy",
			AccountID:       "123456789012",
			OIDCProviderURL: "https://token.actions.githubusercontent.com",
			Audience:        "sts.amazonaws.com",
			Source:          GitHubOIDC,
		}
	}

	tests := []struct {
		name    string
		mutate  func(*AWSRoleTrustOIDCSpec)
		wantErr string
	}{
		{"no subject is rejected", func(s *AWSRoleTrustOIDCSpec) {}, "subject is required"},
		{"blank subject is rejected", func(s *AWSRoleTrustOIDCSpec) { s.Subject = "   " }, "subject is required"},
		{"star subject is rejected", func(s *AWSRoleTrustOIDCSpec) { s.Subject = "*" }, "admits any workload"},
		{"star-colon-star is rejected", func(s *AWSRoleTrustOIDCSpec) { s.Subject = "*:*" }, "admits any workload"},
		{"question-star is rejected", func(s *AWSRoleTrustOIDCSpec) { s.Subject = "?*" }, "admits any workload"},
		{
			"opt-out without a justification is rejected",
			func(s *AWSRoleTrustOIDCSpec) { s.AllowUnscopedSubject = true },
			"requires unscoped_justification",
		},
		{
			"a real subject is accepted",
			func(s *AWSRoleTrustOIDCSpec) { s.Subject = "repo:myorg/myrepo:ref:refs/heads/main" },
			"",
		},
		{
			"a scoped wildcard is accepted",
			func(s *AWSRoleTrustOIDCSpec) {
				s.Subject = "repo:myorg/myrepo:*"
				s.SubjectCondition = "StringLike"
			},
			"",
		},
		{
			"a justified opt-out is accepted",
			func(s *AWSRoleTrustOIDCSpec) {
				s.AllowUnscopedSubject = true
				s.UnscopedJustification = "single-tenant issuer we operate"
			},
			"",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := base()
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
