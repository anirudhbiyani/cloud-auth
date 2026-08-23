package core

import (
	"strings"
	"testing"
)

// These six validators existed, were exported, and were called from nowhere —
// so account_id was never checked to be twelve digits, tenant_id was never a
// UUID, and an http:// issuer was accepted into a trust policy. This test locks
// them to the specs that now use them.
func TestSpecsRejectMalformedIdentifiers(t *testing.T) {
	awsSpec := func(mut func(*AWSRoleTrustOIDCSpec)) error {
		s := &AWSRoleTrustOIDCSpec{
			RoleName: "deploy", AccountID: "123456789012",
			OIDCProviderURL: "https://token.actions.githubusercontent.com",
			Audience:        "sts.amazonaws.com",
			Subject:         "repo:o/r:ref:refs/heads/main",
		}
		mut(s)
		return s.Validate()
	}

	tests := []struct {
		name    string
		mut     func(*AWSRoleTrustOIDCSpec)
		wantErr string
	}{
		{"valid", func(*AWSRoleTrustOIDCSpec) {}, ""},
		{"account id too short", func(s *AWSRoleTrustOIDCSpec) { s.AccountID = "123" }, "invalid AWS account ID"},
		{"account id not numeric", func(s *AWSRoleTrustOIDCSpec) { s.AccountID = "12345678901a" }, "invalid AWS account ID"},
		{
			"http issuer cannot be pinned",
			func(s *AWSRoleTrustOIDCSpec) { s.OIDCProviderURL = "http://token.actions.githubusercontent.com" },
			"must use HTTPS",
		},
		{
			"issuer with no host",
			func(s *AWSRoleTrustOIDCSpec) { s.OIDCProviderURL = "https://" },
			"no host",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := awsSpec(tc.mut)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("want valid, got %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("want an error containing %q, got nil", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("want %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// GovCloud and China role ARNs were rejected outright by an arn:aws:-only regex.
func TestRoleARNCoversEveryPartition(t *testing.T) {
	for _, arn := range []string{
		"arn:aws:iam::123456789012:role/deploy",
		"arn:aws-us-gov:iam::123456789012:role/deploy",
		"arn:aws-cn:iam::123456789012:role/deploy",
		"arn:aws-iso:iam::123456789012:role/path/deploy",
	} {
		if err := ValidateAWSRoleARN(arn); err != nil {
			t.Errorf("ValidateAWSRoleARN(%q) = %v, want nil", arn, err)
		}
	}
	for _, arn := range []string{
		"arn:aws:iam::123:role/deploy",       // account too short
		"arn:aws:s3:::bucket",                // not a role
		"arn:aws:iam::123456789012:user/bob", // not a role
		"deploy",
	} {
		if err := ValidateAWSRoleARN(arn); err == nil {
			t.Errorf("ValidateAWSRoleARN(%q) = nil, want an error", arn)
		}
	}
}

func TestAzureSpecValidatesItsIdentifiers(t *testing.T) {
	base := func() *AzureFederatedCredentialSpec {
		return &AzureFederatedCredentialSpec{
			TenantID:                "11111111-1111-1111-1111-111111111111",
			IdentityType:            "app_registration",
			ApplicationID:           "22222222-2222-2222-2222-222222222222",
			FederatedCredentialName: "cred",
			Issuer:                  "https://token.actions.githubusercontent.com",
			Subject:                 "repo:o/r:ref:refs/heads/main",
		}
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("the valid shape must pass: %v", err)
	}

	s := base()
	s.TenantID = "common"
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "multi-tenant alias") {
		t.Errorf("a multi-tenant alias must be refused, got %v", err)
	}

	s = base()
	s.ApplicationID = "my-app"
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "Azure UUID") {
		t.Errorf("a non-UUID application id must be refused, got %v", err)
	}

	s = base()
	s.Issuer = "http://issuer.example.com"
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("an http issuer must be refused, got %v", err)
	}
}
