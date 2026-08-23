package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/test/harness/verifier/verify"
)

// stubExchanger returns a canned outcome for every target.
type stubExchanger struct {
	creds *core.Credentials
	err   error
}

func (s stubExchanger) Exchange(context.Context, core.Target) (*core.Credentials, *core.Runtime, error) {
	return s.creds, &core.Runtime{Cloud: core.GCP, SubRuntime: "gce", Issuer: "https://accounts.google.com"}, s.err
}

const twoCasePlan = `{
  "run_id": "run-42",
  "cases": [
    {"name":"gcp-gce-to-aws","expect":"success","source_runtime":"gcp-gce",
     "target":{"cloud":"aws","role":"arn:aws:iam::123:role/from-gcp","audience":"sts.amazonaws.com"}},
    {"name":"aws-ec2-to-azure-gap","expect":"error","expect_error":"ErrNoFirstClassPath","source_runtime":"aws-ec2",
     "target":{"cloud":"azure","tenant":"t","client_id":"c","audience":"api://AzureADTokenExchange"}}
  ]
}`

func envWith(plan string) func(string) string {
	return func(k string) string {
		if k == verify.EnvTargetsInline {
			return plan
		}
		return ""
	}
}

func TestRunSelectsOnlyThisRuntimesCases(t *testing.T) {
	creds := &core.Credentials{
		Cloud: core.AWS, AccessKeyID: "ASIATESTKEYID0000000",
		SecretAccessKey: "secret-value-not-in-report", SessionToken: "session-token-not-in-report",
		Expiry: time.Now().Add(time.Hour), STSRequestID: "req-9",
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(),
		[]string{"--runtime", "gcp-gce"},
		&stdout, &stderr, envWith(twoCasePlan),
		func() verify.Exchanger { return stubExchanger{creds: creds} })

	if code != verify.ExitOK {
		t.Fatalf("exit = %d, want %d\nstderr:\n%s", code, verify.ExitOK, stderr.String())
	}
	var rep verify.Report
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatalf("stdout is not a JSON report: %v\n%s", err, stdout.String())
	}
	if len(rep.Results) != 1 || rep.Results[0].Name != "gcp-gce-to-aws" {
		t.Fatalf("results = %+v, want only the gcp-gce case", rep.Results)
	}
	if rep.RunID != "run-42" || rep.DetectedKey != verify.RuntimeGCPGCE {
		t.Errorf("report header = %+v", rep)
	}
	for _, secret := range []string{creds.SecretAccessKey, creds.SessionToken, creds.AccessKeyID} {
		if strings.Contains(stdout.String()+stderr.String(), secret) {
			t.Errorf("output leaked %q", secret)
		}
	}
}

func TestRunFailsWhenAnExpectedSuccessFails(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(),
		[]string{"--runtime", "gce"},
		&stdout, &stderr, envWith(twoCasePlan),
		func() verify.Exchanger { return stubExchanger{err: core.ErrTrustMissing} })

	if code != verify.ExitFailure {
		t.Fatalf("exit = %d, want %d", code, verify.ExitFailure)
	}
	if !strings.Contains(stderr.String(), "1 failed") {
		t.Errorf("stderr missing summary:\n%s", stderr.String())
	}
}

func TestRunPassesTheDocumentedGapCase(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(),
		[]string{"--runtime", "aws-ec2"},
		&stdout, &stderr, envWith(twoCasePlan),
		func() verify.Exchanger { return stubExchanger{err: core.ErrNoFirstClassPath} })

	if code != verify.ExitOK {
		t.Fatalf("exit = %d, want %d\n%s", code, verify.ExitOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), "ErrNoFirstClassPath") {
		t.Errorf("report should record the matched sentinel:\n%s", stdout.String())
	}
}

func TestRunUsageErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		env  func(string) string
		want string
	}{
		{"no plan", []string{"--runtime", "gcp-gce", "--targets", "/nonexistent/targets.json"},
			func(string) string { return "" }, "no targets.json"},
		{"bad plan", []string{"--runtime", "gcp-gce"},
			envWith(`{"cases":[{"name":"x","source_runtime":"gcp-gce","expect":"maybe",
				"target":{"cloud":"aws","role":"r","audience":"a"}}]}`), "expect must be"},
		{"unknown runtime override", []string{"--runtime", "ibm"}, envWith(twoCasePlan), "unknown --runtime"},
		{"no cases for runtime", []string{"--runtime", "gcp-gke"}, envWith(twoCasePlan), "no cases for runtime"},
		{"bad flag", []string{"--nope"}, envWith(twoCasePlan), "flag provided but not defined"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), tt.args, &stdout, &stderr, tt.env,
				func() verify.Exchanger { return stubExchanger{} })
			if code != verify.ExitUsage {
				t.Fatalf("exit = %d, want %d\n%s", code, verify.ExitUsage, stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.want) {
				t.Errorf("stderr = %q, want mention of %q", stderr.String(), tt.want)
			}
		})
	}
}

func TestRunAllowEmptyExitsClean(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(),
		[]string{"--runtime", "gcp-gke", "--allow-empty"},
		&stdout, &stderr, envWith(twoCasePlan),
		func() verify.Exchanger { return stubExchanger{} })
	if code != verify.ExitOK {
		t.Fatalf("exit = %d, want %d", code, verify.ExitOK)
	}
}
