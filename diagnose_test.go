package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
)

var refNow = time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)

// firstFinding returns the joined messages so tests can assert on substrings.
func joinFindings(ds []diagnosis) string {
	var b strings.Builder
	for _, d := range ds {
		fmt.Fprintln(&b, d.String())
	}
	return b.String()
}

func federatableRT() *core.Runtime {
	return &core.Runtime{Cloud: core.AWS, SubRuntime: "eks-irsa", Federatable: true}
}

func TestDiagnoseDetectionFailed(t *testing.T) {
	p := preflight{detectErr: fmt.Errorf("no supported runtime detected"), now: refNow}
	out := joinFindings(diagnose(p))
	if !strings.Contains(out, "could not detect a source runtime") {
		t.Errorf("want detection-failure message, got:\n%s", out)
	}
}

func TestDiagnoseNonFederatableRuntime(t *testing.T) {
	p := preflight{
		runtime: &core.Runtime{Cloud: core.AWS, SubRuntime: "eks-pod-identity", Federatable: false},
		now:     refNow,
	}
	out := joinFindings(diagnose(p))
	if !strings.Contains(out, "not federatable") || !strings.Contains(out, "eks-pod-identity") {
		t.Errorf("want non-federatable message naming the sub-runtime, got:\n%s", out)
	}
}

func TestDiagnoseMintNonFederatable(t *testing.T) {
	p := preflight{
		runtime: &core.Runtime{Cloud: core.AWS, SubRuntime: "eks-pod-identity", Federatable: true},
		mintErr: fmt.Errorf("mint: %w", core.ErrNonFederatableSource),
		target:  core.GCPTarget{WorkloadIdentityPool: "//iam.googleapis.com/projects/1/x", TokenAudience: "aud"},
		now:     refNow,
	}
	out := joinFindings(diagnose(p))
	if !strings.Contains(out, "cannot produce a federatable token") {
		t.Errorf("want ErrNonFederatableSource message, got:\n%s", out)
	}
}

func TestDiagnoseNoFirstClassPath(t *testing.T) {
	p := preflight{
		runtime: &core.Runtime{Cloud: core.AWS, SubRuntime: "ec2", Federatable: true},
		mintErr: fmt.Errorf("bridge: %w", core.ErrNoFirstClassPath),
		target:  core.AzureTarget{Tenant: "11111111-1111-1111-1111-111111111111", ClientID: "22222222-2222-2222-2222-222222222222", Scope: "https://storage.azure.com/.default", TokenAudience: "api://AzureADTokenExchange"},
		now:     refNow,
	}
	out := joinFindings(diagnose(p))
	if !strings.Contains(out, "no first-class keyless path") {
		t.Errorf("want ErrNoFirstClassPath message, got:\n%s", out)
	}
	// AWS has a first-class remedy now, so the guidance must name it rather than
	// send the operator off to build a bridge.
	if !strings.Contains(out, "outbound identity federation") {
		t.Errorf("want AWS outbound-federation guidance, got:\n%s", out)
	}
	if strings.Contains(out, "OIDC bridge") {
		t.Errorf("AWS guidance should no longer recommend building a bridge, got:\n%s", out)
	}
}

// A source with no first-class remedy still gets the generic bridge guidance.
func TestDiagnoseNoFirstClassPathNonAWS(t *testing.T) {
	p := preflight{
		runtime: &core.Runtime{Cloud: core.GCP, SubRuntime: "gce", Federatable: true},
		mintErr: fmt.Errorf("bridge: %w", core.ErrNoFirstClassPath),
		target:  core.AzureTarget{Tenant: "11111111-1111-1111-1111-111111111111", ClientID: "22222222-2222-2222-2222-222222222222", Scope: "https://storage.azure.com/.default", TokenAudience: "api://AzureADTokenExchange"},
		now:     refNow,
	}
	out := joinFindings(diagnose(p))
	if !strings.Contains(out, "OIDC bridge") {
		t.Errorf("want generic bridge guidance, got:\n%s", out)
	}
}

func TestDiagnoseAudienceMismatch(t *testing.T) {
	p := preflight{
		runtime: federatableRT(),
		token:   &core.SourceToken{Audience: "wrong-aud"},
		target:  core.GCPTarget{WorkloadIdentityPool: "//iam.googleapis.com/projects/1/x", TokenAudience: "right-aud"},
		now:     refNow,
	}
	out := joinFindings(diagnose(p))
	if !strings.Contains(out, "audience mismatch") || !strings.Contains(out, "wrong-aud") || !strings.Contains(out, "right-aud") {
		t.Errorf("want audience-mismatch message with both values, got:\n%s", out)
	}
}

func TestDiagnoseAudienceMissing(t *testing.T) {
	p := preflight{
		runtime: federatableRT(),
		token:   &core.SourceToken{Audience: ""},
		target:  core.GCPTarget{WorkloadIdentityPool: "//iam.googleapis.com/projects/1/x", TokenAudience: "right-aud"},
		now:     refNow,
	}
	out := joinFindings(diagnose(p))
	if !strings.Contains(out, "no audience") {
		t.Errorf("want audience-missing message, got:\n%s", out)
	}
}

func TestDiagnoseExpiredToken(t *testing.T) {
	p := preflight{
		runtime: federatableRT(),
		token:   &core.SourceToken{Audience: "aud", Expiry: refNow.Add(-time.Minute)},
		target:  core.GCPTarget{WorkloadIdentityPool: "//iam.googleapis.com/projects/1/x", TokenAudience: "aud"},
		now:     refNow,
		skew:    30 * time.Second,
	}
	out := joinFindings(diagnose(p))
	if !strings.Contains(out, "expired") || !strings.Contains(out, "clock") {
		t.Errorf("want expiry/clock-skew message, got:\n%s", out)
	}
}

func TestDiagnoseAzureCaseSensitivity(t *testing.T) {
	p := preflight{
		runtime: federatableRT(),
		token:   &core.SourceToken{Audience: "api://AzureADTokenExchange"},
		target:  core.AzureTarget{Tenant: "11111111-1111-1111-1111-111111111111", ClientID: "22222222-2222-2222-2222-222222222222", Scope: "https://storage.azure.com/.default", TokenAudience: "api://azureadtokenexchange"},
		now:     refNow,
	}
	out := joinFindings(diagnose(p))
	if !strings.Contains(out, "Azure case-sensitivity") {
		t.Errorf("want Azure case-sensitivity message, got:\n%s", out)
	}
}

func TestDiagnoseHappyPath(t *testing.T) {
	p := preflight{
		runtime: federatableRT(),
		token:   &core.SourceToken{Audience: "aud", Expiry: refNow.Add(time.Hour)},
		target:  core.AWSTarget{RoleARN: "arn:aws:iam::123456789012:role/x", TokenAudience: "aud"},
		now:     refNow,
		skew:    30 * time.Second,
	}
	ds := diagnose(p)
	out := joinFindings(ds)
	if strings.Contains(out, "✗") {
		t.Errorf("happy path should have no failures, got:\n%s", out)
	}
	if !strings.Contains(out, "minted successfully") || !strings.Contains(out, "audience matches") {
		t.Errorf("want success findings, got:\n%s", out)
	}
	// The proof kind decides which target-side trust applies, so "it minted" on
	// its own is not enough for an operator to act on.
	if !strings.Contains(out, "kind ") {
		t.Errorf("want the minted proof kind reported, got:\n%s", out)
	}
}

func TestExchangeAdvisoryPerCloud(t *testing.T) {
	cases := []struct {
		target core.Target
		want   string
	}{
		{core.AWSTarget{RoleARN: "arn:aws:iam::123456789012:role/x"}, "AssumeRoleWithWebIdentity"},
		{core.GCPTarget{WorkloadIdentityPool: "//iam.googleapis.com/projects/1/p"}, "workload identity pool"},
		{core.AzureTarget{Tenant: "11111111-1111-1111-1111-111111111111", ClientID: "22222222-2222-2222-2222-222222222222", Scope: "s"}, "federated identity credential"},
	}
	for _, c := range cases {
		got := exchangeAdvisory(c.target)
		if !strings.Contains(got, c.want) {
			t.Errorf("%s advisory missing %q, got:\n%s", c.target.Cloud(), c.want, got)
		}
	}
}

func TestWriteDiagnosesAdvisoryOnlyWhenMintOK(t *testing.T) {
	// Mint failed => no exchange advisory should be printed.
	var b strings.Builder
	p := preflight{
		runtime: federatableRT(),
		mintErr: fmt.Errorf("boom"),
		target:  core.AWSTarget{RoleARN: "arn:aws:iam::123456789012:role/r", TokenAudience: "aud"},
		now:     refNow,
	}
	writeDiagnoses(&b, p, diagnose(p))
	if strings.Contains(b.String(), "AssumeRoleWithWebIdentity") {
		t.Errorf("advisory must not appear when mint failed, got:\n%s", b.String())
	}
}
