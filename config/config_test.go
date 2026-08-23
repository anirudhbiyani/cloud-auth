package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
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
	if tgt.Cloud() != core.GCP {
		t.Errorf("cloud = %v", tgt.Cloud())
	}
	// GCP audience defaults to the workload identity pool when unset, in the
	// //iam.googleapis.com/ form the token exchange requires — the config may
	// carry either spelling.
	gcp := tgt.(core.GCPTarget)
	wantAud := gcp.WorkloadIdentityPool
	if !strings.HasPrefix(wantAud, "//iam.googleapis.com/") {
		wantAud = "//iam.googleapis.com/" + wantAud
	}
	if tgt.Audience() != wantAud {
		t.Errorf("gcp audience = %q, want the pool resource name %q", tgt.Audience(), wantAud)
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
		string(core.AWS),
		string(core.GCP),
		string(core.Azure),
	}
	for _, c := range wantClouds {
		if !enum[c] {
			t.Errorf("schema cloud enum missing %q; enum = %v", c, enum)
		}
		if _, err := core.ParseCloud(c); err != nil {
			t.Errorf("validator rejects cloud %q that schema lists: %v", c, err)
		}
	}
	if len(enum) != len(wantClouds) {
		t.Errorf("schema cloud enum has %d entries, want %d (%v)", len(enum), len(wantClouds), wantClouds)
	}
	// Anything the schema does NOT list must be rejected by the validator.
	if _, err := core.ParseCloud("oracle"); err == nil {
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
			if rt.Audience() == "" {
				t.Fatalf("accepted target %q with empty audience", tg.Name)
			}
		}
	})
}

// source.detect was parsed, validated, tested — and read by nothing. An operator
// who pinned it had configured a security control that did not exist. Load must
// now reject a value the enforcement layer cannot honour.
func TestLoadRejectsAnUnusableSourceDetect(t *testing.T) {
	dir := t.TempDir()
	write := func(detect string) string {
		path := filepath.Join(dir, strings.ReplaceAll(detect, "/", "_")+".yaml")
		body := "version: 1\nsource:\n  detect: " + detect + "\ntargets:\n" +
			"  - name: t\n    cloud: aws\n    role: arn:aws:iam::123456789012:role/r\n    audience: a\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	for _, bad := range []string{"aws-ec3", "kubernetes", "aws-"} {
		if _, err := Load(write(bad)); err == nil {
			t.Errorf("Load accepted source.detect %q", bad)
		}
	}
	for _, good := range []string{"auto", "aws", "aws-ec2", "gcp-gke"} {
		if _, err := Load(write(good)); err != nil {
			t.Errorf("Load rejected valid source.detect %q: %v", good, err)
		}
	}
}

// And the parsed value must be reachable, or the enforcement layer has nothing
// to enforce.
func TestSourceSelectorIsExposed(t *testing.T) {
	c := &Config{Version: 1, Source: Source{Detect: "aws-eks-irsa"}}
	sel, err := c.SourceSelector()
	if err != nil {
		t.Fatalf("SourceSelector: %v", err)
	}
	if sel.Cloud != core.AWS || sel.SubRuntime != "eks-irsa" {
		t.Errorf("selector = %+v, want aws/eks-irsa", sel)
	}
}

// A field belonging to another cloud is now a config error rather than a
// silently ignored key. Dropping it is how a target ends up pointing somewhere
// the operator did not intend.
func TestConfigRejectsForeignCloudFields(t *testing.T) {
	dir := t.TempDir()
	load := func(body string) error {
		path := filepath.Join(dir, "c.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Load(path)
		return err
	}

	err := load(`version: 1
targets:
  - name: t
    cloud: aws
    role: arn:aws:iam::123456789012:role/r
    tenant: 11111111-1111-1111-1111-111111111111
`)
	if err == nil || !strings.Contains(err.Error(), "azure setting") {
		t.Errorf("an azure tenant on an aws target must be rejected, got %v", err)
	}

	err = load(`version: 1
targets:
  - name: t
    cloud: gcp
    workload_identity_pool: projects/1/locations/global/workloadIdentityPools/p/providers/x
    role: arn:aws:iam::123456789012:role/r
`)
	if err == nil || !strings.Contains(err.Error(), "aws setting") {
		t.Errorf("an aws role on a gcp target must be rejected, got %v", err)
	}

	// The valid shape still loads.
	if err := load(`version: 1
targets:
  - name: t
    cloud: azure
    tenant: 11111111-1111-1111-1111-111111111111
    client_id: 22222222-2222-2222-2222-222222222222
    scope: https://storage.azure.com/.default
`); err != nil {
		t.Errorf("a valid azure target should load: %v", err)
	}
}
