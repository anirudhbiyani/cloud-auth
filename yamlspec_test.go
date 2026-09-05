package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// The help text has always advertised "Spec file (YAML or JSON)".
func TestLoadSpecAcceptsYAMLAndJSON(t *testing.T) {
	dir := t.TempDir()

	yamlSpec := `
type: aws_role_trust_oidc
role_name: deploy
account_id: "123456789012"
oidc_provider_url: https://token.actions.githubusercontent.com
audience: sts.amazonaws.com
subject: repo:myorg/myrepo:ref:refs/heads/main
source: github_oidc
policy_arns:
  - arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
`
	jsonSpec := `{
  "type": "aws_role_trust_oidc",
  "role_name": "deploy",
  "account_id": "123456789012",
  "oidc_provider_url": "https://token.actions.githubusercontent.com",
  "audience": "sts.amazonaws.com",
  "subject": "repo:myorg/myrepo:ref:refs/heads/main",
  "source": "github_oidc",
  "policy_arns": ["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"]
}`

	for name, content := range map[string]string{"spec.yaml": yamlSpec, "spec.json": jsonSpec} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			spec, err := loadSpec(path)
			if err != nil {
				t.Fatalf("loadSpec: %v", err)
			}
			if err := spec.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			aws, ok := spec.(*core.AWSRoleTrustOIDCSpec)
			if !ok {
				t.Fatalf("got %T, want the AWS spec type", spec)
			}
			// Both formats must produce the same spec, including the nested list — a decoder that silently dropped policy_arns would still "work".
			if aws.RoleName != "deploy" || aws.Subject != "repo:myorg/myrepo:ref:refs/heads/main" {
				t.Errorf("scalar fields not decoded: %+v", aws)
			}
			if len(aws.PolicyARNs) != 1 {
				t.Errorf("policy_arns = %v, want one entry", aws.PolicyARNs)
			}
		})
	}
}

// Feeding a federation config to --file used to say "spec must include 'type' field", which describes the symptom rather than the mistake.
func TestLoadSpecRecognisesAFederationConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cloud-auth.yaml")
	cfg := `
version: 1
source:
  detect: auto
targets:
  - name: prod
    cloud: aws
    role: arn:aws:iam::123456789012:role/reader
    audience: sts.amazonaws.com
`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadSpec(path)
	if err == nil {
		t.Fatal("a federation config is not a mechanism spec")
	}
	for _, want := range []string{"federation config", "config-validate"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should point at the right flag (%q): %v", want, err)
		}
	}
}

func TestLoadSpecRejectsAnUnknownType(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spec.yaml")
	if err := os.WriteFile(path, []byte("type: not_a_mechanism\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSpec(path); err == nil {
		t.Fatal("want an error for an unknown mechanism type")
	}
}
