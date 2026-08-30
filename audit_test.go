package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/internal/audit"
)

// audit.Emit had one call site — exchange — so the MUTATING control-plane
// operations, setup and delete, were precisely the ones with no record, along
// with exec, which injects live credentials into a child process.
//
// "Exactly one record per operation" is the property worth testing, and the
// error paths are where it used to break: an operation that returned early
// skipped the record entirely, so failures were the least likely to be logged.

// captureStderr runs fn with os.Stderr redirected and returns what it wrote.
// The audit destination is stderr so it never lands in a command's stdout.
func captureStderr(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	saved := os.Stderr
	os.Stderr = w
	runErr := fn()
	os.Stderr = saved
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, readErr := r.Read(buf)
		sb.Write(buf[:n])
		if readErr != nil {
			break
		}
	}
	return sb.String(), runErr
}

// auditRecords extracts the JSON audit lines from mixed stderr output. Other
// diagnostics share the stream, so anything that is not a well-formed record is
// skipped rather than treated as a parse failure.
func auditRecords(t *testing.T, stderr string) []audit.Event {
	t.Helper()
	var out []audit.Event
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var ev audit.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if ev.Operation != "" {
			out = append(out, ev)
		}
	}
	return out
}

func TestAuditorEmitsExactlyOnce(t *testing.T) {
	for _, tc := range []struct {
		name        string
		err         error
		wantOutcome string
	}{
		{"success", nil, audit.OutcomeSuccess},
		{"failure", errors.New("the exchange was refused"), audit.OutcomeFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			a := newAuditor(audit.OpExchange)
			a.log = audit.New(&buf)

			// Called twice on purpose: finish is deferred at some call sites and
			// also returned explicitly at others, and two records for one
			// operation would double-count in a SIEM.
			_ = a.finish(tc.err)
			_ = a.finish(errors.New("a second, different error"))

			lines := strings.Count(strings.TrimSpace(buf.String()), "\n") + 1
			if buf.Len() == 0 {
				t.Fatal("no record was emitted")
			}
			if lines != 1 {
				t.Fatalf("emitted %d records for one operation:\n%s", lines, buf.String())
			}

			var ev audit.Event
			if err := json.Unmarshal(buf.Bytes(), &ev); err != nil {
				t.Fatalf("record is not valid JSON (%v): %s", err, buf.String())
			}
			if ev.Outcome != tc.wantOutcome {
				t.Errorf("Outcome = %q, want %q", ev.Outcome, tc.wantOutcome)
			}
			if ev.Timestamp.IsZero() {
				t.Error("record has no timestamp")
			}
		})
	}
}

// An operation that dies unexpectedly must record a failure, not a success. The
// default has to be the safe direction for a security record.
func TestAuditorDefaultsToFailure(t *testing.T) {
	a := newAuditor(audit.OpSetup)
	if a.event.Outcome != audit.OutcomeFailure {
		t.Errorf("a pending event's outcome is %q, want %q",
			a.event.Outcome, audit.OutcomeFailure)
	}
}

// The error is redacted before it lands in the audit log — which is the one file
// built for long-term retention, and therefore exactly where a leaked assertion
// would come to rest.
func TestAuditErrorIsRedacted(t *testing.T) {
	const assertion = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZXBvOm9yZy9yZXBvIn0.c2lnbmF0dXJlLW1hdGVyaWFsLXRoYXQtaXMtc2VjcmV0"
	var buf bytes.Buffer
	a := newAuditor(audit.OpExchange)
	a.log = audit.New(&buf)
	_ = a.finish(errors.New("STS rejected assertion " + assertion))

	if strings.Contains(buf.String(), "c2lnbmF0dXJlLW1hdGVyaWFs") {
		t.Errorf("the assertion survived into the audit record: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "STS rejected") {
		t.Errorf("the record is no longer diagnosable: %s", buf.String())
	}
}

// setup mutates trust, so it is audited whatever the outcome. This exercises the
// real command through a dry run, which needs no cloud credentials.
func TestSetupEmitsAnAuditRecord(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state.json")
	stderr, err := captureStderr(t, func() error {
		return cmdSetup(context.Background(), []string{
			"--type", "aws-oidc",
			"--role-name", "audited-role",
			"--account-id", "123456789012",
			"--oidc-url", "https://token.actions.githubusercontent.com",
			"--subject", "repo:myorg/myrepo:ref:refs/heads/main",
			"--source", "github",
			"--dry-run",
			"--state", state,
		})
	})
	if err != nil {
		t.Fatalf("cmdSetup: %v", err)
	}

	records := auditRecords(t, stderr)
	if len(records) != 1 {
		t.Fatalf("got %d audit records, want exactly 1:\n%s", len(records), stderr)
	}
	ev := records[0]
	if ev.Operation != audit.OpSetup {
		t.Errorf("Operation = %q, want %q", ev.Operation, audit.OpSetup)
	}
	if ev.Outcome != audit.OutcomeSuccess {
		t.Errorf("Outcome = %q", ev.Outcome)
	}
	if !ev.DryRun {
		t.Error("DryRun = false; a dry run must be recorded as one")
	}
	if ev.MechanismType == "" {
		t.Error("MechanismType is empty; the record does not say what was set up")
	}
}

// The path that used to be silent: a failing operation returning early.
//
// The failure has to happen INSIDE manager.Setup, after the auditor starts —
// a spec rejected during flag parsing never reaches it and correctly produces
// no record. This case previously used k8s-federation against GCP, which failed
// only because no GCP handler existed; closing that gap made this test pass
// vacuously, so it now uses a refusal that is meant to stay one.
func TestSetupEmitsARecordOnFailure(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state.json")
	stderr, err := captureStderr(t, func() error {
		return cmdSetup(context.Background(), []string{
			"--type", "k8s-federation",
			"--cluster-name", "c",
			"--k8s-namespace", "ns",
			"--k8s-sa-name", "sa",
			"--oidc-url", "https://issuer.example.com",
			// Managed identity needs a resource group and an identity name that
			// azure_config cannot express, so the provider refuses inside Setup.
			"--target-cloud", "azure",
			"--identity-type", "managed-identity",
			"--tenant-id", "11111111-1111-1111-1111-111111111111",
			"--subscription-id", "22222222-2222-2222-2222-222222222222",
			"--dry-run",
			"--state", state,
		})
	})
	if err == nil {
		t.Fatal("expected this setup to fail")
	}

	records := auditRecords(t, stderr)
	if len(records) != 1 {
		t.Fatalf("got %d audit records on the failure path, want exactly 1:\n%s", len(records), stderr)
	}
	if records[0].Outcome != audit.OutcomeFailure {
		t.Errorf("Outcome = %q, want %q", records[0].Outcome, audit.OutcomeFailure)
	}
	if records[0].Error == "" {
		t.Error("the record does not say what failed")
	}
}

// Audit records must not land in stdout, which for several commands is a
// document another program parses.
func TestAuditGoesToStderrNotStdout(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state.json")

	stdout, err := captureStdout(t, func() error {
		return cmdSetup(context.Background(), []string{
			"--type", "aws-oidc",
			"--role-name", "audited-role",
			"--account-id", "123456789012",
			"--oidc-url", "https://token.actions.githubusercontent.com",
			"--subject", "repo:myorg/myrepo:ref:refs/heads/main",
			"--source", "github",
			"--dry-run",
			"--state", state,
		})
	})
	if err != nil {
		t.Fatalf("cmdSetup: %v", err)
	}
	if strings.Contains(stdout, `"operation"`) {
		t.Errorf("an audit record reached stdout:\n%s", stdout)
	}
}
