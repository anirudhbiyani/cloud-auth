package verify

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// fakeExchanger stands in for *broker.Broker: same method shape, no cloud.
type fakeExchanger struct {
	creds *core.Credentials
	rt    *core.Runtime
	err   error
	calls []core.Target
}

func (f *fakeExchanger) Exchange(ctx context.Context, t core.Target) (*core.Credentials, *core.Runtime, error) {
	f.calls = append(f.calls, t)
	return f.creds, f.rt, f.err
}

var testNow = time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)

func testRunner(ex Exchanger) *Runner {
	return &Runner{
		Exchanger: ex,
		Scrubber:  NewScrubber(),
		Now:       func() time.Time { return testNow },
		Skew:      30 * time.Second,
		Timeout:   time.Minute,
	}
}

func awsCreds() *core.Credentials {
	return &core.Credentials{
		Cloud:           core.AWS,
		AccessKeyID:     "ASIAEXAMPLEKEYID0000",
		SecretAccessKey: "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
		SessionToken:    "FwoGZXIvYXdzEExampleSessionTokenValue0000000000",
		Expiry:          testNow.Add(time.Hour),
		STSRequestID:    "req-1234",
	}
}

func successCase() Case {
	return Case{
		Name: "gcp-gce-to-aws", Expect: ExpectSuccess, SourceRuntime: RuntimeGCPGCE,
		Target: TargetSpec{Cloud: "aws", Role: "arn:aws:iam::123:role/x", Audience: "sts.amazonaws.com"},
	}
}

func TestRunCaseSuccess(t *testing.T) {
	ex := &fakeExchanger{
		creds: awsCreds(),
		rt:    &core.Runtime{Cloud: core.GCP, SubRuntime: "gce", Issuer: "https://accounts.google.com", Subject: "1098765"},
	}
	res := testRunner(ex).RunCase(context.Background(), successCase())

	if res.Status != StatusPass {
		t.Fatalf("status = %s (%s), want pass", res.Status, res.Error)
	}
	if res.TargetCloud != "aws" || res.Name != "gcp-gce-to-aws" {
		t.Errorf("result = %+v", res)
	}
	if res.Identity.Issuer != "https://accounts.google.com" || res.Identity.Subject != "1098765" {
		t.Errorf("identity = %+v, want issuer/subject recorded", res.Identity)
	}
	if res.Identity.STSRequestID != "req-1234" {
		t.Errorf("sts request id = %q, want it recorded for correlation", res.Identity.STSRequestID)
	}
	if res.Identity.Role != "arn:aws:iam::123:role/x" {
		t.Errorf("role = %q, want the target role recorded", res.Identity.Role)
	}
	if len(ex.calls) != 1 || ex.calls[0].Audience() != "sts.amazonaws.com" {
		t.Errorf("exchange calls = %+v", ex.calls)
	}
	if res.Probe.Status != ProbeNotRequested {
		t.Errorf("probe = %+v, want not-requested", res.Probe)
	}
}

func TestRunCaseSuccessFailures(t *testing.T) {
	expiredCreds := awsCreds()
	expiredCreds.Expiry = testNow.Add(10 * time.Second) // inside the 30s skew

	emptyCreds := &core.Credentials{Cloud: core.AWS, Expiry: testNow.Add(time.Hour)}

	gcpNoToken := &core.Credentials{Cloud: core.GCP, Expiry: testNow.Add(time.Hour)}

	tests := []struct {
		name    string
		ex      *fakeExchanger
		c       Case
		wantMsg string
	}{
		{
			"exchange error", &fakeExchanger{err: errors.New("sts said no")}, successCase(),
			"sts said no",
		},
		{
			"nil credentials", &fakeExchanger{}, successCase(),
			"no credentials",
		},
		{
			"expired credentials", &fakeExchanger{creds: expiredCreds}, successCase(),
			"expired",
		},
		{
			"empty aws credentials", &fakeExchanger{creds: emptyCreds}, successCase(),
			"access key",
		},
		{
			"empty gcp access token", &fakeExchanger{creds: gcpNoToken},
			Case{Name: "x", Expect: ExpectSuccess, SourceRuntime: RuntimeAWSEKSIRSA,
				Target: TargetSpec{Cloud: "gcp", Pool: "//iam/p", Audience: "//iam/p"}},
			"access token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := testRunner(tt.ex).RunCase(context.Background(), tt.c)
			if res.Status != StatusFail {
				t.Fatalf("status = %s, want fail", res.Status)
			}
			if !strings.Contains(strings.ToLower(res.Error), tt.wantMsg) {
				t.Errorf("error = %q, want mention of %q", res.Error, tt.wantMsg)
			}
		})
	}
}

func gapCase() Case {
	return Case{
		Name: "aws-ec2-to-azure-gap", Expect: ExpectError, ExpectError: "ErrNoFirstClassPath",
		SourceRuntime: RuntimeAWSEC2,
		Target:        TargetSpec{Cloud: "azure", Tenant: "t", ClientID: "c", Audience: "api://AzureADTokenExchange"},
	}
}

func TestRunCaseExpectedSentinelError(t *testing.T) {
	// The documented AWS-EC2 -> Azure gap: it must fail, with this error.
	wrapped := fmt.Errorf("cloud-auth: exchange: %w: SigV4 proof is not RS256 OIDC", core.ErrNoFirstClassPath)
	res := testRunner(&fakeExchanger{err: wrapped}).RunCase(context.Background(), gapCase())

	if res.Status != StatusPass {
		t.Fatalf("status = %s (%s), want pass: the documented gap failing with its sentinel IS the pass condition", res.Status, res.Error)
	}
	if res.MatchedSentinel != "ErrNoFirstClassPath" {
		t.Errorf("matched sentinel = %q", res.MatchedSentinel)
	}
}

func TestRunCaseExpectedErrorMismatches(t *testing.T) {
	tests := []struct {
		name    string
		ex      *fakeExchanger
		wantMsg string
	}{
		{
			"wrong sentinel",
			&fakeExchanger{err: fmt.Errorf("nope: %w", core.ErrTrustMissing)},
			"want ErrNoFirstClassPath",
		},
		{
			"unrelated error",
			&fakeExchanger{err: errors.New("connection refused")},
			"want ErrNoFirstClassPath",
		},
		{
			"unexpected success",
			&fakeExchanger{creds: &core.Credentials{Cloud: core.Azure, AccessToken: "tok", Expiry: testNow.Add(time.Hour)}},
			"succeeded",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := testRunner(tt.ex).RunCase(context.Background(), gapCase())
			if res.Status != StatusFail {
				t.Fatalf("status = %s, want fail", res.Status)
			}
			if !strings.Contains(res.Error, tt.wantMsg) {
				t.Errorf("error = %q, want mention of %q", res.Error, tt.wantMsg)
			}
		})
	}
}

func TestRunCaseUnknownSentinelNameFails(t *testing.T) {
	c := gapCase()
	c.ExpectError = "ErrMadeUp"
	res := testRunner(&fakeExchanger{err: core.ErrNoFirstClassPath}).RunCase(context.Background(), c)
	if res.Status != StatusFail || !strings.Contains(res.Error, "unknown sentinel") {
		t.Errorf("result = %+v, want fail mentioning unknown sentinel", res)
	}
}

func TestRunCaseProbeOutcomesAreSoft(t *testing.T) {
	tests := []struct {
		name       string
		probe      string
		probes     map[string]Probe
		strict     bool
		wantStatus Status
		wantProbe  ProbeStatus
	}{
		{
			"probe ok", "ok-probe",
			map[string]Probe{"ok-probe": func(context.Context, *core.Credentials, Case) (string, error) {
				return "arn:aws:sts::123:assumed-role/x/y", nil
			}},
			false, StatusPass, ProbeOK,
		},
		{
			"probe fails but case still passes", "bad-probe",
			map[string]Probe{"bad-probe": func(context.Context, *core.Credentials, Case) (string, error) {
				return "", errors.New("403 from sts")
			}},
			false, StatusPass, ProbeSoftFail,
		},
		{
			"probe fails under -probe-strict", "bad-probe",
			map[string]Probe{"bad-probe": func(context.Context, *core.Credentials, Case) (string, error) {
				return "", errors.New("403 from sts")
			}},
			true, StatusFail, ProbeSoftFail,
		},
		{
			"unimplemented probe is soft", "no-such-probe", nil,
			false, StatusPass, ProbeUnimplemented,
		},
		{
			"panicking probe does not crash the run", "panic-probe",
			map[string]Probe{"panic-probe": func(context.Context, *core.Credentials, Case) (string, error) {
				panic("probe exploded")
			}},
			false, StatusPass, ProbeSoftFail,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := testRunner(&fakeExchanger{creds: awsCreds()})
			r.Probes = tt.probes
			r.StrictProbe = tt.strict
			c := successCase()
			c.Probe = tt.probe

			res := r.RunCase(context.Background(), c)
			if res.Status != tt.wantStatus {
				t.Errorf("status = %s (%s), want %s", res.Status, res.Error, tt.wantStatus)
			}
			if res.Probe.Status != tt.wantProbe {
				t.Errorf("probe status = %s, want %s", res.Probe.Status, tt.wantProbe)
			}
			if res.Probe.Name != tt.probe {
				t.Errorf("probe name = %q, want %q", res.Probe.Name, tt.probe)
			}
		})
	}
}

func TestRunAllCasesRecordsDurations(t *testing.T) {
	r := testRunner(&fakeExchanger{creds: awsCreds()})
	results := r.Run(context.Background(), []Case{successCase()})
	if len(results) != 1 {
		t.Fatalf("results = %d", len(results))
	}
	if results[0].DurationMS < 0 {
		t.Errorf("duration = %d", results[0].DurationMS)
	}
}
