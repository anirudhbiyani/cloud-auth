package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// `--subject "repo:myorg/myrepo:*"` — the value this project's own README used
// to suggest — passed every gate with no warning, because validateSubjectScope
// tests exact membership in {"*", "?*", "*:*", "**"}.

// setupWith runs a dry-run setup with the given subject and extra flags,
// returning what reached stdout and stderr.
func setupWith(t *testing.T, subject string, extra ...string) (stdout, stderr string, err error) {
	t.Helper()
	state := filepath.Join(t.TempDir(), "state.json")
	args := append([]string{
		"--type", "aws-oidc",
		"--role-name", "r",
		"--account-id", "123456789012",
		"--oidc-url", "https://token.actions.githubusercontent.com",
		"--subject", subject,
		"--source", "github",
		"--dry-run",
		"--state", state,
	}, extra...)

	stderr, _ = captureStderr(t, func() error {
		stdout, err = captureStdout(t, func() error {
			return cmdSetup(context.Background(), args)
		})
		return nil
	})
	return stdout, stderr, err
}

func TestSetupWarnsOnBroadSubjects(t *testing.T) {
	for _, tc := range []struct {
		name        string
		subject     string
		wantErr     bool
		stderrHas   string
		stderrLacks string
	}{
		{
			name:        "an exact subject says nothing",
			subject:     "repo:myorg/myrepo:ref:refs/heads/main",
			stderrLacks: "breadth",
		},
		{
			name:      "a trailing wildcard warns about forks",
			subject:   "repo:myorg/myrepo:*",
			stderrHas: "pull request from a FORK",
		},
		{
			name:      "an org-wide subject names the organisation",
			subject:   "repo:myorg/*",
			stderrHas: `every repository in the "myorg" organisation`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, stderr, err := setupWith(t, tc.subject)
			if err != nil {
				t.Fatalf("setup: %v", err)
			}
			if tc.stderrHas != "" && !strings.Contains(stderr, tc.stderrHas) {
				t.Errorf("stderr does not contain %q:\n%s", tc.stderrHas, stderr)
			}
			if tc.stderrLacks != "" && strings.Contains(stderr, tc.stderrLacks) {
				t.Errorf("stderr should not mention %q:\n%s", tc.stderrLacks, stderr)
			}
		})
	}
}

// Critical breadth is refused, and the refusal has to name the override rather
// than leaving someone to find it.
func TestSetupRefusesCriticalBreadth(t *testing.T) {
	_, _, err := setupWith(t, "repo:*")
	if err == nil {
		t.Fatal("want a refusal for a subject admitting every tenant of the issuer")
	}
	for _, want := range []string{
		"critical breadth",
		"--allow-unscoped-subject",
		"--unscoped-justification",
		"shared-IdP guardrail", // the context that makes this a live problem
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}
}

// The override exists so the decision is recorded, not so it can be waved
// through — but when it is passed, setup must proceed.
func TestSetupAcceptsCriticalBreadthWithAJustification(t *testing.T) {
	_, _, err := setupWith(t, "repo:*",
		"--allow-unscoped-subject",
		"--unscoped-justification", "internal issuer we operate; every token equally trusted")
	if err != nil {
		t.Fatalf("the recorded override should let setup proceed: %v", err)
	}
}

// A wildcard silently upgraded the IAM operator to one that honours it, so the
// same flag both widened the trust and made the widening take effect.
func TestSetupAnnouncesTheStringLikeFlip(t *testing.T) {
	_, stderr, err := setupWith(t, "repo:myorg/myrepo:*")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if !strings.Contains(stderr, "StringLike") {
		t.Errorf("the operator switch was not announced:\n%s", stderr)
	}

	_, stderr, err = setupWith(t, "repo:myorg/myrepo:ref:refs/heads/main")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if strings.Contains(stderr, "StringLike") {
		t.Errorf("no wildcard, so there is no operator switch to announce:\n%s", stderr)
	}
}

// Warnings must not pollute stdout, which is the result.
func TestBreadthWarningsGoToStderr(t *testing.T) {
	stdout, _, err := setupWith(t, "repo:myorg/*")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if strings.Contains(stdout, "breadth") || strings.Contains(stdout, "StringLike") {
		t.Errorf("diagnostics reached stdout:\n%s", stdout)
	}
}

// Only specs carrying a single subject condition are scored. A GCP pool
// provider constrains identities through a CEL attribute condition — a
// different shape, and a string score pretending to analyse one would be worse
// than saying nothing.
func TestOnlySubjectBearingSpecsAreScored(t *testing.T) {
	if _, ok := subjectOf(&core.AWSRoleTrustOIDCSpec{Subject: "repo:o/r:*"}); !ok {
		t.Error("an AWS role trust spec should be scorable")
	}
	if _, ok := subjectOf(&core.AzureFederatedCredentialSpec{Subject: "repo:o/r:*"}); !ok {
		t.Error("an Azure federated credential spec should be scorable")
	}
	if _, ok := subjectOf(&core.GCPWorkloadIdentityPoolSpec{AttributeCondition: "assertion.sub=='x'"}); ok {
		t.Error("a GCP pool spec has no single subject; scoring one would be a pretend analysis")
	}
}
