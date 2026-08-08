package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
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

func federatableRT() *cloudauth.Runtime {
	return &cloudauth.Runtime{Cloud: cloudauth.AWS, SubRuntime: "eks-irsa", Federatable: true}
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
		runtime: &cloudauth.Runtime{Cloud: cloudauth.AWS, SubRuntime: "eks-pod-identity", Federatable: false},
		now:     refNow,
	}
	out := joinFindings(diagnose(p))
	if !strings.Contains(out, "not federatable") || !strings.Contains(out, "eks-pod-identity") {
		t.Errorf("want non-federatable message naming the sub-runtime, got:\n%s", out)
	}
}

func TestDiagnoseMintNonFederatable(t *testing.T) {
	p := preflight{
		runtime: &cloudauth.Runtime{Cloud: cloudauth.AWS, SubRuntime: "eks-pod-identity", Federatable: true},
		mintErr: fmt.Errorf("mint: %w", cloudauth.ErrNonFederatableSource),
		target:  cloudauth.Target{Cloud: cloudauth.GCP, Audience: "aud"},
		now:     refNow,
	}
	out := joinFindings(diagnose(p))
	if !strings.Contains(out, "cannot produce a federatable token") {
		t.Errorf("want ErrNonFederatableSource message, got:\n%s", out)
	}
}

func TestDiagnoseNoFirstClassPath(t *testing.T) {
	p := preflight{
		runtime: &cloudauth.Runtime{Cloud: cloudauth.AWS, SubRuntime: "ec2", Federatable: true},
		mintErr: fmt.Errorf("bridge: %w", cloudauth.ErrNoFirstClassPath),
		target:  cloudauth.Target{Cloud: cloudauth.Azure, Audience: "api://AzureADTokenExchange"},
		now:     refNow,
	}
	out := joinFindings(diagnose(p))
	if !strings.Contains(out, "no first-class keyless path") {
		t.Errorf("want ErrNoFirstClassPath message, got:\n%s", out)
	}
	if !strings.Contains(out, "OIDC bridge") {
		t.Errorf("want bridge guidance, got:\n%s", out)
	}
}

func TestDiagnoseAudienceMismatch(t *testing.T) {
	p := preflight{
		runtime: federatableRT(),
		token:   &cloudauth.SourceToken{Audience: "wrong-aud"},
		target:  cloudauth.Target{Cloud: cloudauth.GCP, Audience: "right-aud"},
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
		token:   &cloudauth.SourceToken{Audience: ""},
		target:  cloudauth.Target{Cloud: cloudauth.GCP, Audience: "right-aud"},
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
		token:   &cloudauth.SourceToken{Audience: "aud", Expiry: refNow.Add(-time.Minute)},
		target:  cloudauth.Target{Cloud: cloudauth.GCP, Audience: "aud"},
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
		token:   &cloudauth.SourceToken{Audience: "api://AzureADTokenExchange"},
		target:  cloudauth.Target{Cloud: cloudauth.Azure, Audience: "api://azureadtokenexchange"},
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
		token:   &cloudauth.SourceToken{Audience: "aud", Expiry: refNow.Add(time.Hour)},
		target:  cloudauth.Target{Cloud: cloudauth.AWS, Audience: "aud", Role: "arn:aws:iam::1:role/x"},
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
}

func TestExchangeAdvisoryPerCloud(t *testing.T) {
	cases := []struct {
		target cloudauth.Target
		want   string
	}{
		{cloudauth.Target{Cloud: cloudauth.AWS, Role: "arn:aws:iam::1:role/x"}, "AssumeRoleWithWebIdentity"},
		{cloudauth.Target{Cloud: cloudauth.GCP, WorkloadIdentityPool: "projects/p"}, "workload identity pool"},
		{cloudauth.Target{Cloud: cloudauth.Azure, Tenant: "t", ClientID: "c"}, "federated identity credential"},
	}
	for _, c := range cases {
		got := exchangeAdvisory(c.target)
		if !strings.Contains(got, c.want) {
			t.Errorf("%s advisory missing %q, got:\n%s", c.target.Cloud, c.want, got)
		}
	}
}

func TestWriteDiagnosesAdvisoryOnlyWhenMintOK(t *testing.T) {
	// Mint failed => no exchange advisory should be printed.
	var b strings.Builder
	p := preflight{
		runtime: federatableRT(),
		mintErr: fmt.Errorf("boom"),
		target:  cloudauth.Target{Cloud: cloudauth.AWS, Audience: "aud", Role: "r"},
		now:     refNow,
	}
	writeDiagnoses(&b, p, diagnose(p))
	if strings.Contains(b.String(), "AssumeRoleWithWebIdentity") {
		t.Errorf("advisory must not appear when mint failed, got:\n%s", b.String())
	}
}
