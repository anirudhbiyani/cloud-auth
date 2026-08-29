// Package config loads and validates cloud-auth's declarative federation config.
//
// Precedence is code > env > file: a file provides the base, environment
// variables (CLOUD_AUTH_*) override it, and programmatic setters override those.
// Validation is strict and fails closed — an invalid or ambiguous config is a
// hard error, never a degraded fallback.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// Config is the top-level federation config (schema version 1).
type Config struct {
	Version int      `yaml:"version"`
	Source  Source   `yaml:"source"`
	Targets []Target `yaml:"targets"`
	Refresh Refresh  `yaml:"refresh"`
}

// Source configures runtime detection.
type Source struct {
	// Detect pins which runtime the workload may authenticate as: "auto" (the
	// default), a cloud ("aws"), or a cloud and sub-runtime ("aws-ec2").
	//
	// A mismatch is a hard error. That is the point: auto-detection picks an
	// identity by probe order, and a host can satisfy more than one probe, so an
	// operator who knows where the workload runs can refuse anything else.
	Detect string `yaml:"detect"`
}

// Refresh configures credential refresh timing.
type Refresh struct {
	Buffer string `yaml:"buffer"` // e.g. "5m"
}

// Target is a named target binding.
type Target struct {
	Name                      string `yaml:"name"`
	Cloud                     string `yaml:"cloud"`
	Audience                  string `yaml:"audience"`
	Role                      string `yaml:"role"`
	WorkloadIdentityPool      string `yaml:"workload_identity_pool"`
	ImpersonateServiceAccount string `yaml:"impersonate_service_account"`
	Tenant                    string `yaml:"tenant"`
	ClientID                  string `yaml:"client_id"`
	Scope                     string `yaml:"scope"`
	SessionName               string `yaml:"session_name"`
}

// Load reads, applies environment overrides, and validates a config file.
func Load(path string) (*Config, error) {
	return LoadWithEnv(path, os.Getenv)
}

// LoadWithEnv is Load with an injectable environment lookup (for tests).
func LoadWithEnv(path string, getenv func(string) string) (*Config, error) {
	// #nosec G304 -- config path is supplied by the operator (--config / default);
	// reading an operator-named file is the documented behaviour.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: reading %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("config: parsing %s: %w", path, err)
	}
	c.applyEnv(getenv)
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// applyEnv overlays CLOUD_AUTH_* environment overrides (env > file).
func (c *Config) applyEnv(getenv func(string) string) {
	if v := getenv("CLOUD_AUTH_SOURCE_DETECT"); v != "" {
		c.Source.Detect = v
	}
	if v := getenv("CLOUD_AUTH_REFRESH_BUFFER"); v != "" {
		c.Refresh.Buffer = v
	}
}

// Validate enforces the fail-closed rules.
func (c *Config) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("config: unsupported version %d (want 1)", c.Version)
	}
	seen := map[string]bool{}
	for i, t := range c.Targets {
		if t.Name == "" {
			return fmt.Errorf("config: target #%d has no name", i)
		}
		if seen[t.Name] {
			return fmt.Errorf("config: duplicate target name %q", t.Name)
		}
		seen[t.Name] = true

		cloud, err := core.ParseFederationTarget(t.Cloud)
		if err != nil {
			return fmt.Errorf("config: target %q: %w", t.Name, err)
		}
		if _, err := t.resolve(cloud); err != nil {
			return fmt.Errorf("config: target %q: %w", t.Name, err)
		}
	}
	if c.Refresh.Buffer != "" {
		if _, err := time.ParseDuration(c.Refresh.Buffer); err != nil {
			return fmt.Errorf("config: refresh.buffer %q: %w", c.Refresh.Buffer, err)
		}
	}
	// Reject an unparseable selector here rather than at first exchange. A typo
	// in a field whose whole purpose is to constrain which identity may be used
	// must fail loudly: silently falling back to auto would leave the operator
	// believing they had pinned something.
	if _, err := c.SourceSelector(); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	return nil
}

// SourceSelector returns the parsed source.detect restriction.
func (c *Config) SourceSelector() (core.Selector, error) {
	return core.ParseSelector(c.Source.Detect)
}

// RefreshBuffer returns the parsed refresh buffer (default 5m).
func (c *Config) RefreshBuffer() (time.Duration, error) {
	if c.Refresh.Buffer == "" {
		return 5 * time.Minute, nil
	}
	return time.ParseDuration(c.Refresh.Buffer)
}

// Target resolves a named target into a core.Target.
func (c *Config) Target(name string) (core.Target, error) {
	for _, t := range c.Targets {
		if t.Name != name {
			continue
		}
		cloud, err := core.ParseFederationTarget(t.Cloud)
		if err != nil {
			return nil, err
		}
		return t.resolve(cloud)
	}
	return nil, fmt.Errorf("config: no target named %q", name)
}

// resolve builds the concrete per-cloud target.
//
// The required-field checks live on each target type's Validate, so the config
// layer no longer restates per-cloud rules — and a field belonging to another
// cloud is now unrepresentable rather than silently ignored.
func (t Target) resolve(cloud core.Cloud) (core.Target, error) {
	var out core.Target
	switch cloud {
	case core.AWS:
		out = core.AWSTarget{
			RoleARN:       t.Role,
			TokenAudience: t.Audience,
			SessionName:   t.SessionName,
		}
	case core.GCP:
		out = core.GCPTarget{
			WorkloadIdentityPool:      t.WorkloadIdentityPool,
			ImpersonateServiceAccount: t.ImpersonateServiceAccount,
			TokenAudience:             t.Audience,
		}
	case core.Azure:
		out = core.AzureTarget{
			Tenant:        t.Tenant,
			ClientID:      t.ClientID,
			TokenAudience: t.Audience,
			Scope:         t.Scope,
		}
	default:
		return nil, fmt.Errorf("unsupported target cloud %q", cloud)
	}

	// Reject fields that belong to another cloud rather than ignoring them: a
	// tenant on an AWS target means the operator has the wrong block, and
	// silently dropping it is how a target ends up pointing somewhere unintended.
	if err := t.rejectForeignFields(cloud); err != nil {
		return nil, err
	}
	if err := out.Validate(); err != nil {
		return nil, err
	}
	return out, nil
}

// rejectForeignFields reports config keys set for a different cloud.
func (t Target) rejectForeignFields(cloud core.Cloud) error {
	type field struct {
		name  string
		value string
		owner core.Cloud
	}
	for _, f := range []field{
		{"role", t.Role, core.AWS},
		{"session_name", t.SessionName, core.AWS},
		{"workload_identity_pool", t.WorkloadIdentityPool, core.GCP},
		{"impersonate_service_account", t.ImpersonateServiceAccount, core.GCP},
		{"tenant", t.Tenant, core.Azure},
		{"client_id", t.ClientID, core.Azure},
		{"scope", t.Scope, core.Azure},
	} {
		if f.value != "" && f.owner != cloud {
			return fmt.Errorf("%q is a %s setting but this target's cloud is %s", f.name, f.owner, cloud)
		}
	}
	return nil
}
