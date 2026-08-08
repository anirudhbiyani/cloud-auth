package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
)

func TestScrubberRedactsRegisteredSecrets(t *testing.T) {
	s := NewScrubber()
	s.AddCredentials(awsCreds())

	in := "creds: ASIAEXAMPLEKEYID0000 / wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"
	got := s.Scrub(in)
	for _, secret := range []string{"wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY", "ASIAEXAMPLEKEYID0000"} {
		if strings.Contains(got, secret) {
			t.Errorf("Scrub kept %q: %s", secret, got)
		}
	}
	if !strings.Contains(got, redactedMarker) {
		t.Errorf("Scrub = %q, want a redaction marker", got)
	}
}

func TestScrubberRedactsTokenShapedStrings(t *testing.T) {
	tests := []struct {
		name string
		in   string
		gone string
	}{
		{
			"jwt",
			"rejected assertion eyJhbGciOiJSUzI1NiIsImtpZCI6ImFiYyJ9.eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQifQ.c2lnbmF0dXJlLXZhbHVlLWhlcmU",
			"eyJhbGciOiJSUzI1NiIsImtpZCI6ImFiYyJ9",
		},
		{
			"bearer header",
			"Authorization: Bearer ya29.a0AfH6SMBexampleaccesstokenvalue0123456789",
			"ya29.a0AfH6SMBexampleaccesstokenvalue0123456789",
		},
		{
			"aws session key",
			"used ASIAZZZZZZZZZZZZZZZZ to sign",
			"ASIAZZZZZZZZZZZZZZZZ",
		},
		{
			"long opaque blob",
			"token=AQABAAIAAAAm3UM3aOOOOOOOOOOOOOOOOOOOOOOOOOOOOgAAAAA",
			"AQABAAIAAAAm3UM3aOOOOOOOOOOOOOOOOOOOOOOOOOOOOgAAAAA",
		},
	}
	s := NewScrubber()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.Scrub(tt.in)
			if strings.Contains(got, tt.gone) {
				t.Errorf("Scrub kept token-shaped value: %s", got)
			}
		})
	}
}

func TestScrubberKeepsIdentityMetadata(t *testing.T) {
	// Redaction must not eat the things we rely on for diagnosis.
	keep := []string{
		"arn:aws:iam::123456789012:role/cloud-auth-test-from-gcp",
		"//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/cloud-auth-test/providers/aws-oidc",
		"system:serviceaccount:cloud-auth-test:verifier",
		"https://oidc.eks.us-east-1.amazonaws.com/id/ABC123",
		"api://AzureADTokenExchange",
		"req-1234-5678",
	}
	s := NewScrubber()
	s.AddCredentials(awsCreds())
	for _, k := range keep {
		if got := s.Scrub(k); got != k {
			t.Errorf("Scrub(%q) = %q, want it left intact", k, got)
		}
	}
}

// This is the security guarantee the harness contract demands: a credential
// value must never reach the report, whatever path it takes to get there.
func TestReportNeverContainsCredentialValues(t *testing.T) {
	creds := awsCreds()
	// The error itself leaks the assertion and the secret — a hostile-but-plausible
	// STS error body. Neither may survive into the report.
	leakyErr := fmt.Errorf("STS rejected assertion %s and key %s: %w",
		"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJsZWFrIn0.c2lnbmF0dXJlLXZhbHVlLWhlcmUtMDAw",
		creds.SecretAccessKey, cloudauth.ErrTrustMissing)

	r := testRunner(&fakeExchanger{creds: creds, err: nil})
	r.Probes = map[string]Probe{
		"leaky-probe": func(context.Context, *cloudauth.Credentials, Case) (string, error) {
			return "session token was " + creds.SessionToken, leakyErr
		},
	}
	c := successCase()
	c.Probe = "leaky-probe"

	results := r.Run(context.Background(), []Case{c})
	rep := BuildReport("run-1", RuntimeGCPGCE, &cloudauth.Runtime{Cloud: cloudauth.GCP, SubRuntime: "gce"}, results, time.Now(), 0)

	var buf bytes.Buffer
	if err := rep.WriteJSON(&buf, r.Scrubber); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var human bytes.Buffer
	rep.WriteHuman(&human, r.Scrubber)

	secrets := []string{
		creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken,
		"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJsZWFrIn0.c2lnbmF0dXJlLXZhbHVlLWhlcmUtMDAw",
	}
	for _, out := range []struct {
		name string
		body string
	}{{"json", buf.String()}, {"human", human.String()}} {
		for _, secret := range secrets {
			if strings.Contains(out.body, secret) {
				t.Errorf("%s report leaked %q:\n%s", out.name, secret, out.body)
			}
		}
	}

	// ... and it is still valid JSON with the diagnostic metadata intact.
	var parsed Report
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	if len(parsed.Results) != 1 || parsed.Results[0].Identity.STSRequestID != "req-1234" {
		t.Errorf("parsed report lost its metadata: %+v", parsed)
	}
}

func TestBuildReportSummaryAndExitCode(t *testing.T) {
	results := []CaseResult{
		{Name: "a", Status: StatusPass, Probe: ProbeResult{Status: ProbeOK}},
		{Name: "b", Status: StatusFail, Error: "boom"},
		{Name: "c", Status: StatusSkip},
		{Name: "d", Status: StatusPass, Probe: ProbeResult{Status: ProbeSoftFail}},
		{Name: "e", Status: StatusPass, Probe: ProbeResult{Status: ProbeUnimplemented}},
	}
	rep := BuildReport("run-1", RuntimeAWSEC2, nil, results, time.Now(), 5*time.Millisecond)

	want := Summary{Total: 5, Passed: 3, Failed: 1, Skipped: 1, SoftProbeFailures: 1, ProbesUnimplemented: 1}
	if rep.Summary != want {
		t.Errorf("summary = %+v, want %+v", rep.Summary, want)
	}
	if rep.ExitCode() != ExitFailure {
		t.Errorf("exit code = %d, want %d", rep.ExitCode(), ExitFailure)
	}

	rep.Results = results[:1]
	rep.Summary = summarize(results[:1])
	if rep.ExitCode() != ExitOK {
		t.Errorf("all-pass exit code = %d, want %d", rep.ExitCode(), ExitOK)
	}
}

func TestWriteHumanSummaryMentionsEveryCase(t *testing.T) {
	results := []CaseResult{
		{Name: "gcp-gce-to-aws", TargetCloud: "aws", Status: StatusPass},
		{Name: "aws-ec2-to-azure-gap", TargetCloud: "azure", Status: StatusFail, Error: "boom"},
	}
	rep := BuildReport("run-1", RuntimeGCPGCE, nil, results, time.Now(), time.Second)
	var buf bytes.Buffer
	rep.WriteHuman(&buf, NewScrubber())
	for _, want := range []string{"gcp-gce-to-aws", "aws-ec2-to-azure-gap", "boom", "1 passed", "1 failed"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("human summary missing %q:\n%s", want, buf.String())
		}
	}
}

func TestErrSummaryIsSingleLineAndBounded(t *testing.T) {
	long := strings.Repeat("x", 4000)
	got := errSummary(errors.New("prefix\nsecond line " + long))
	if strings.Contains(got, "\n") {
		t.Errorf("summary contains a newline: %q", got)
	}
	if len(got) > maxErrSummary+len(truncatedMarker) {
		t.Errorf("summary length = %d, want <= %d", len(got), maxErrSummary+len(truncatedMarker))
	}
	if errSummary(nil) != "" {
		t.Errorf("errSummary(nil) = %q, want empty", errSummary(nil))
	}
}
