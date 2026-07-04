package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
)

const validYAML = `
version: 1
source:
  detect: auto
targets:
  - name: s3-reader
    cloud: aws
    role: arn:aws:iam::123456789012:role/synapse-reader
    audience: sts.amazonaws.com
  - name: bigquery
    cloud: gcp
    workload_identity_pool: projects/123/locations/global/workloadIdentityPools/cloud-auth/providers/aws
refresh:
  buffer: 5m
`

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cloud-auth.yaml")
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValid(t *testing.T) {
	c, err := Load(writeConfig(t, validYAML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.Targets) != 2 {
		t.Fatalf("targets = %d, want 2", len(c.Targets))
	}
	buf, err := c.RefreshBuffer()
	if err != nil || buf.Minutes() != 5 {
		t.Errorf("refresh buffer = %v (err %v), want 5m", buf, err)
	}
}

func TestValidateRequiresAudience(t *testing.T) {
	// GCP resolves audience from the WIP, but AWS/Azure must set it explicitly.
	body := `
version: 1
targets:
  - name: no-aud
    cloud: aws
    role: arn:aws:iam::123:role/r
`
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("expected fail-closed error for missing audience")
	}
}

func TestValidateUnknownCloud(t *testing.T) {
	body := `
version: 1
targets:
  - name: bad
    cloud: oracle
    audience: x
`
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("expected error for unknown cloud")
	}
}

func TestValidateDuplicateNames(t *testing.T) {
	body := `
version: 1
targets:
  - name: dup
    cloud: aws
    role: r
    audience: a
  - name: dup
    cloud: gcp
    workload_identity_pool: p
`
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("expected error for duplicate target names")
	}
}

func TestResolveTarget(t *testing.T) {
	c, err := Load(writeConfig(t, validYAML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	tgt, err := c.Target("bigquery")
	if err != nil {
		t.Fatalf("Target: %v", err)
	}
	if tgt.Cloud != cloudauth.GCP {
		t.Errorf("cloud = %v", tgt.Cloud)
	}
	// GCP audience defaults to the workload identity pool when unset.
	if tgt.Audience == "" || tgt.Audience != tgt.WorkloadIdentityPool {
		t.Errorf("gcp audience should default to WIP; got %q", tgt.Audience)
	}
	if _, err := c.Target("nope"); err == nil {
		t.Error("expected error for unknown target name")
	}
}

func TestEnvOverridesDetect(t *testing.T) {
	c, err := LoadWithEnv(writeConfig(t, validYAML), func(k string) string {
		if k == "CLOUD_AUTH_SOURCE_DETECT" {
			return "aws-ec2"
		}
		return ""
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Source.Detect != "aws-ec2" {
		t.Errorf("detect = %q, want env override aws-ec2", c.Source.Detect)
	}
}
