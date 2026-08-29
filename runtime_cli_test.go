package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// These tests exist because `cloud-auth doctor` — the tool's most common
// invocation — shipped a segfault. core.Target is an interface, targetFlags
// returned an untyped nil when --to was absent, and cmdDoctor called
// target.Cloud() on it. A nil interface has no method table.
//
// The root package had no test for cmdDoctor, cmdExchange, cmdExec or
// resolveRuntimeConfig at all, which is why nothing caught it. The matrix below
// is the flag/config grid those four functions actually have to survive.

// writeConfig writes a minimal valid federation config and returns its path.
func writeConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cloud-auth.yaml")
	body := `version: 1
targets:
  - name: prod-aws
    cloud: aws
    role: arn:aws:iam::123456789012:role/deploy
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// resolveRuntimeConfig is where the config-driven flow panicked: it reached
// flagTarget.Cloud() holding nil whenever --config was given without --to.
func TestResolveRuntimeConfigMatrix(t *testing.T) {
	cfg := writeConfig(t)
	flagAWS := core.AWSTarget{RoleARN: "arn:aws:iam::999999999999:role/from-flag"}

	for _, tc := range []struct {
		name       string
		flagTarget core.Target
		configPath string
		targetName string
		wantCloud  core.Cloud
		wantErr    string
	}{
		{
			name:       "neither: no target, no error",
			flagTarget: core.NoTarget{},
			wantCloud:  "",
		},
		{
			name:       "--to only: flag target passes through",
			flagTarget: flagAWS,
			wantCloud:  core.AWS,
		},
		{
			name:       "--config only, named target: resolved from file",
			flagTarget: core.NoTarget{},
			configPath: cfg,
			targetName: "prod-aws",
			wantCloud:  core.AWS,
		},
		{
			name:       "--config only, unnamed: refuses, does not panic",
			flagTarget: core.NoTarget{},
			configPath: cfg,
			wantErr:    "--target is required with --config",
		},
		{
			name:       "--config with an unknown target name",
			flagTarget: core.NoTarget{},
			configPath: cfg,
			targetName: "nope",
			wantErr:    "nope",
		},
		{
			name:       "both: the explicit flag wins over the config",
			flagTarget: flagAWS,
			configPath: cfg,
			targetName: "prod-aws",
			wantCloud:  core.AWS,
		},
		{
			name:       "--config pointing at nothing",
			flagTarget: core.NoTarget{},
			configPath: filepath.Join(t.TempDir(), "absent.yaml"),
			wantErr:    "absent.yaml",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target, _, err := resolveRuntimeConfig(tc.flagTarget, tc.configPath, tc.targetName)

			// The contract that stops the panic: a target is returned on every
			// path, including every error path, so the caller can inspect it
			// before deciding whether the error mattered.
			if target == nil {
				t.Fatal("resolveRuntimeConfig returned a nil core.Target; any method call on it panics")
			}
			_ = target.Cloud() // must not panic

			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("want error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %q, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := target.Cloud(); got != tc.wantCloud {
				t.Errorf("Cloud() = %q, want %q", got, tc.wantCloud)
			}
		})
	}
}

// The fix is at the source: targetFlags must never hand back an untyped nil,
// whatever the caller passed. Guarding the consumers instead would leave the
// next consumer to rediscover this.
func TestTargetFlagsNeverReturnsNilTarget(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--to", "aws", "--role", "arn:aws:iam::123456789012:role/r"},
		{"--to", "gcp", "--pool", "projects/1/locations/global/workloadIdentityPools/p/providers/x"},
		{"--to", "azure", "--tenant", "t", "--client-id", "c", "--scope", "s"},
		{"--to", "   "}, // whitespace-only is the "absent" branch
		{"--audience", "sts.amazonaws.com"},
	} {
		t.Run(strings.Join(append([]string{"flags:"}, args...), " "), func(t *testing.T) {
			fs := newTestFlagSet(t)
			getTarget := targetFlags(fs)
			if err := fs.Parse(args); err != nil {
				t.Fatalf("parse: %v", err)
			}
			target, err := getTarget()
			if target == nil {
				t.Fatalf("nil core.Target for args %v (err=%v)", args, err)
			}
			_ = target.Cloud()
			_ = target.Audience()
		})
	}
}

// NoTarget must refuse rather than pretend an unnamed binding is usable.
func TestNoTargetRefusesValidation(t *testing.T) {
	var tgt core.Target = core.NoTarget{}
	if tgt.Cloud() != "" {
		t.Errorf("Cloud() = %q, want empty", tgt.Cloud())
	}
	if tgt.Audience() != "" {
		t.Errorf("Audience() = %q, want empty", tgt.Audience())
	}
	if err := tgt.Validate(); err == nil {
		t.Error("Validate() = nil; an absent target must not validate")
	}
}

// The reported crash, end to end: `cloud-auth doctor` with no arguments. It is a
// detection-only report and must exit cleanly whether or not this machine is on
// a supported cloud.
func TestDoctorWithNoArgumentsDoesNotPanic(t *testing.T) {
	if err := cmdDoctor(context.Background(), nil); err != nil {
		t.Fatalf("cmdDoctor with no arguments: %v", err)
	}
}

// The commands that genuinely require a target must say so, before any network
// call and without dereferencing a nil interface.
func TestRuntimeCommandsRefuseAMissingTarget(t *testing.T) {
	ctx := context.Background()
	cfg := writeConfig(t)

	for _, tc := range []struct {
		name string
		run  func() error
		want string
	}{
		{"exchange, no flags", func() error { return cmdExchange(ctx, nil, "env") }, "--to or --config/--target is required"},
		{"exec, no flags", func() error { return cmdExec(ctx, []string{"--", "true"}) }, "--to or --config/--target is required"},
		{"init, no flags", func() error { return cmdInit(ctx, nil, &bytes.Buffer{}) }, "--to is required"},
		{"credential-process, no flags", func() error { return cmdExchange(ctx, nil, "credential-process") }, "--to or --config/--target is required"},
		{"exchange, --config without --target", func() error {
			return cmdExchange(ctx, []string{"--config", cfg}, "env")
		}, "--target is required with --config"},
		{"exec, --config without --target", func() error {
			return cmdExec(ctx, []string{"--config", cfg, "--", "true"})
		}, "--target is required with --config"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if err == nil {
				t.Fatal("want an error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// One layer down: preflight is a plain struct built by hand, so an unset target
// field must not panic the pure diagnosis path either.
func TestDiagnoseToleratesAnUnsetTarget(t *testing.T) {
	p := preflight{
		runtime:   &core.Runtime{Cloud: core.AWS, SubRuntime: "ec2", Federatable: true},
		detectErr: errors.New("no supported runtime detected"),
	}
	var buf bytes.Buffer
	ds := diagnose(p)           // must not panic
	writeDiagnoses(&buf, p, ds) // must not panic
	if buf.Len() == 0 {
		t.Error("writeDiagnoses produced nothing")
	}
}

// newTestFlagSet returns a flag set that reports parse errors instead of calling
// os.Exit, which the production ExitOnError sets would do inside a test binary.
func newTestFlagSet(t *testing.T) *flag.FlagSet {
	t.Helper()
	fs := flag.NewFlagSet(t.Name(), flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}
