package main

import (
	"strings"
	"testing"
)

// The CLI must not be able to express an accidentally-unscoped trust, and must be able to express a deliberate one.
func TestSetupFlagsGovernSubjectScoping(t *testing.T) {
	base := []string{
		"--type", "aws-oidc",
		"--role-name", "deploy",
		"--account-id", "123456789012",
		"--oidc-url", "https://token.actions.githubusercontent.com",
		"--source", "github",
	}

	tests := []struct {
		name    string
		extra   []string
		wantErr string
	}{
		{"no subject", nil, "subject is required"},
		{
			"opt-out without a reason",
			[]string{"--allow-unscoped-subject"},
			"requires unscoped_justification",
		},
		{
			"subject given",
			[]string{"--subject", "repo:myorg/myrepo:ref:refs/heads/main"},
			"",
		},
		{
			"opt-out with a reason",
			[]string{"--allow-unscoped-subject", "--unscoped-justification", "issuer is ours"},
			"",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := parseSetupOpts(append(append([]string{}, base...), tc.extra...))
			if err != nil {
				t.Fatalf("parseSetupOpts: %v", err)
			}
			spec, err := buildSpecFromFlags(opts)
			if err != nil {
				t.Fatalf("buildSpecFromFlags: %v", err)
			}

			err = spec.Validate()
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
