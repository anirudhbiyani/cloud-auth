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

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
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
	Detect string `yaml:"detect"` // "auto" or a forced sub-runtime
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

		cloud, err := cloudauth.ParseCloud(t.Cloud)
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
	return nil
}

// RefreshBuffer returns the parsed refresh buffer (default 5m).
func (c *Config) RefreshBuffer() (time.Duration, error) {
	if c.Refresh.Buffer == "" {
		return 5 * time.Minute, nil
	}
	return time.ParseDuration(c.Refresh.Buffer)
}

// Target resolves a named target into a cloudauth.Target.
func (c *Config) Target(name string) (cloudauth.Target, error) {
	for _, t := range c.Targets {
		if t.Name == name {
			cloud, err := cloudauth.ParseCloud(t.Cloud)
			if err != nil {
				return cloudauth.Target{}, err
			}
			return t.resolve(cloud)
		}
	}
	return cloudauth.Target{}, fmt.Errorf("config: no target named %q", name)
}

// resolve converts a config Target to a cloudauth.Target, applying per-cloud
// defaults and required-field checks. Audience is required everywhere; for GCP
// it defaults to the workload identity pool when unset.
func (t Target) resolve(cloud cloudauth.Cloud) (cloudauth.Target, error) {
	out := cloudauth.Target{
		Cloud:                     cloud,
		Audience:                  t.Audience,
		Role:                      t.Role,
		WorkloadIdentityPool:      t.WorkloadIdentityPool,
		ImpersonateServiceAccount: t.ImpersonateServiceAccount,
		Tenant:                    t.Tenant,
		ClientID:                  t.ClientID,
	}
	switch cloud {
	case cloudauth.AWS:
		if out.Role == "" {
			return out, fmt.Errorf("aws target requires a role ARN")
		}
	case cloudauth.GCP:
		if out.WorkloadIdentityPool == "" {
			return out, fmt.Errorf("gcp target requires workload_identity_pool")
		}
		if out.Audience == "" {
			out.Audience = out.WorkloadIdentityPool
		}
	case cloudauth.Azure:
		if out.Tenant == "" || out.ClientID == "" {
			return out, fmt.Errorf("azure target requires tenant and client_id")
		}
		if out.Audience == "" {
			out.Audience = "api://AzureADTokenExchange"
		}
	}
	if out.Audience == "" {
		return out, fmt.Errorf("audience is required and must be pinned per target")
	}
	return out, nil
}
