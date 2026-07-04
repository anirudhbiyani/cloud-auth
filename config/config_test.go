package config

import (
	"encoding/json"
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

// TestValidateFailClosed enumerates the fail-closed cases as a table. Every case
// must be rejected by Load (invalid or ambiguous config is a hard error).
func TestValidateFailClosed(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{
			name: "unsupported version",
			yaml: `
version: 2
targets:
  - name: t
    cloud: aws
    role: arn:aws:iam::123:role/r
    audience: a
`,
		},
		{
			name: "missing version",
			yaml: `
targets:
  - name: t
    cloud: aws
    role: arn:aws:iam::123:role/r
    audience: a
`,
		},
		{
			name: "target without name",
			yaml: `
version: 1
targets:
  - cloud: aws
    role: r
    audience: a
`,
		},
		{
			name: "aws missing audience",
			yaml: `
version: 1
targets:
  - name: no-aud
    cloud: aws
    role: arn:aws:iam::123:role/r
`,
		},
		{
			name: "azure with only name and cloud",
			yaml: `
version: 1
targets:
  - name: az
    cloud: azure
`,
		},
		{
			name: "unknown cloud",
			yaml: `
version: 1
targets:
  - name: bad
    cloud: oracle
    audience: x
`,
		},
		{
			name: "empty cloud",
			yaml: `
version: 1
targets:
  - name: bad
    cloud: ""
    audience: x
`,
		},
		{
			name: "duplicate target names",
			yaml: `
version: 1
targets:
  - name: dup
    cloud: aws
    role: r
    audience: a
  - name: dup
    cloud: gcp
    workload_identity_pool: p
`,
		},
		{
			name: "aws missing role",
			yaml: `
version: 1
targets:
  - name: aws-no-role
    cloud: aws
    audience: a
`,
		},
		{
			name: "gcp missing workload_identity_pool",
			yaml: `
version: 1
targets:
  - name: gcp-no-pool
    cloud: gcp
    audience: a
`,
		},
		{
			name: "azure missing tenant and client_id",
			yaml: `
version: 1
targets:
  - name: az-no-ids
    cloud: azure
    audience: a
`,
		},
		{
			name: "azure missing client_id",
			yaml: `
version: 1
targets:
  - name: az-no-client
    cloud: azure
    tenant: t
    audience: a
`,
		},
		{
			name: "invalid refresh buffer",
			yaml: `
version: 1
targets:
  - name: t
    cloud: aws
    role: r
    audience: a
refresh:
  buffer: not-a-duration
`,
		},
		{
			name: "malformed yaml",
			yaml: "version: 1\ntargets: [oops",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, tc.yaml)); err == nil {
				t.Fatalf("expected fail-closed error, got nil")
			}
		})
	}
}

// schemaPath is the published JSON schema documenting the config format.
const schemaPath = "cloud-auth.schema.json"

// TestSchemaValidJSON asserts the published schema file parses as JSON.
func TestSchemaValidJSON(t *testing.T) {
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	if doc["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Errorf("schema $schema = %v, want draft 2020-12", doc["$schema"])
	}
}

// TestSchemaMatchesValidator guards drift between the published JSON schema and
// what the Go validator actually enforces. It is intentionally lightweight.
func TestSchemaMatchesValidator(t *testing.T) {
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse schema: %v", err)
	}

	target, ok := dig(doc, "$defs", "target")
	if !ok {
		t.Fatal("schema missing $defs/target")
	}

	// (a) audience must be required on a target.
	req := toStringSet(target.(map[string]any)["required"])
	for _, field := range []string{"name", "cloud", "audience"} {
		if !req[field] {
			t.Errorf("schema target should require %q; required = %v", field, req)
		}
	}

	// (b) the cloud enum must match exactly the clouds the Go validator accepts.
	props, _ := dig(target.(map[string]any), "properties", "cloud")
	enum := toStringSet(props.(map[string]any)["enum"])
	wantClouds := []string{
		string(cloudauth.AWS),
		string(cloudauth.GCP),
		string(cloudauth.Azure),
	}
	for _, c := range wantClouds {
		if !enum[c] {
			t.Errorf("schema cloud enum missing %q; enum = %v", c, enum)
		}
		if _, err := cloudauth.ParseCloud(c); err != nil {
			t.Errorf("validator rejects cloud %q that schema lists: %v", c, err)
		}
	}
	if len(enum) != len(wantClouds) {
		t.Errorf("schema cloud enum has %d entries, want %d (%v)", len(enum), len(wantClouds), wantClouds)
	}
	// Anything the schema does NOT list must be rejected by the validator.
	if _, err := cloudauth.ParseCloud("oracle"); err == nil {
		t.Error("validator accepts a cloud not in the schema enum")
	}
}

func dig(m map[string]any, keys ...string) (any, bool) {
	var cur any = m
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = mm[k]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func toStringSet(v any) map[string]bool {
	out := map[string]bool{}
	if list, ok := v.([]any); ok {
		for _, e := range list {
			if s, ok := e.(string); ok {
				out[s] = true
			}
		}
	}
	return out
}

// FuzzLoad fuzzes the parse+validate path. Properties asserted:
//   - Load never panics on arbitrary input.
//   - When Load returns a nil error, the resulting Config must satisfy every
//     required-field invariant (never nil err AND a missing required field).
func FuzzLoad(f *testing.F) {
	seeds := []string{
		validYAML,
		"",
		"not: [valid",
		"version: 1",
		"version: 2\ntargets: []",
		`version: 1
targets:
  - name: t
    cloud: aws`,
		`version: 1
targets:
  - name: t
    cloud: oracle
    audience: a`,
		`version: 1
targets:
  - name: dup
    cloud: aws
    role: r
    audience: a
  - name: dup
    cloud: gcp
    workload_identity_pool: p`,
		`version: 1
targets:
  - cloud: azure
    audience: a`,
		"version: 1\nrefresh:\n  buffer: bogus",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, body string) {
		p := filepath.Join(t.TempDir(), "cloud-auth.yaml")
		if err := os.WriteFile(p, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		c, err := Load(p) // must never panic
		if err != nil {
			return
		}
		// err == nil: the config MUST honor every fail-closed invariant.
		if c == nil {
			t.Fatal("nil error but nil Config")
		}
		if c.Version != 1 {
			t.Fatalf("accepted unsupported version %d", c.Version)
		}
		seen := map[string]bool{}
		for _, tg := range c.Targets {
			if tg.Name == "" {
				t.Fatal("accepted target with empty name")
			}
			if seen[tg.Name] {
				t.Fatalf("accepted duplicate target name %q", tg.Name)
			}
			seen[tg.Name] = true

			// A resolvable target must exist and carry a non-empty audience.
			rt, rerr := c.Target(tg.Name)
			if rerr != nil {
				t.Fatalf("accepted config but target %q does not resolve: %v", tg.Name, rerr)
			}
			if rt.Audience == "" {
				t.Fatalf("accepted target %q with empty audience", tg.Name)
			}
		}
	})
}
