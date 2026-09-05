package main

import (
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// IAM role ARNs may carry a path, and GetRole takes the name only.
func TestRoleNameFromARN(t *testing.T) {
	for _, tc := range []struct {
		name    string
		arn     string
		want    string
		wantErr bool
	}{
		{"plain role", "arn:aws:iam::123456789012:role/deploy", "deploy", false},
		{"role with a path", "arn:aws:iam::123456789012:role/team/payments/deploy", "deploy", false},
		{"gov partition", "arn:aws-us-gov:iam::123456789012:role/deploy", "deploy", false},
		{"china partition", "arn:aws-cn:iam::123456789012:role/deploy", "deploy", false},
		{"not a role ARN", "arn:aws:iam::123456789012:user/someone", "", true},
		{"empty role name", "arn:aws:iam::123456789012:role/", "", true},
		{"not an ARN at all", "deploy", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := roleNameFromARN(tc.arn)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// A trust read that FAILED must never render as "no problems found" — the same distinction validate draws between skipped and passed.
func TestExplanationDistinguishesUnreadFromClean(t *testing.T) {
	var sb strings.Builder
	writeExplanation(&sb, nil, nil, errRead{})
	out := sb.String()

	if strings.Contains(out, "✓") {
		t.Errorf("a failed trust read rendered as a pass:\n%s", out)
	}
	if !strings.Contains(out, "nothing below was") {
		t.Errorf("the output does not say the comparison did not happen:\n%s", out)
	}

	sb.Reset()
	writeExplanation(&sb, &core.TrustPolicy{
		Issuer:     "https://token.actions.githubusercontent.com",
		Conditions: []core.TrustCondition{{Operator: "StringEquals", Claim: "sub", Value: "repo:o/r:ref:refs/heads/main"}},
	}, nil, nil)
	if !strings.Contains(sb.String(), "✓") {
		t.Errorf("a clean comparison should say so:\n%s", sb.String())
	}
}

type errRead struct{}

func (errRead) Error() string { return "no credentials" }

// A trust with no conditions at all admits every identity its issuer serves, and an empty section would read as though there were simply nothing to show.
func TestExplanationCallsOutAnUnconditionedTrust(t *testing.T) {
	var sb strings.Builder
	writeExplanation(&sb, &core.TrustPolicy{Issuer: "https://issuer.example.com"}, nil, nil)
	if !strings.Contains(sb.String(), "admits every identity") {
		t.Errorf("an unconditioned trust was not called out:\n%s", sb.String())
	}
}

// The fix text is long by design — a remediation that fits on one line usually is not one — so it wraps rather than running off the terminal.
func TestFixTextWraps(t *testing.T) {
	long := strings.Repeat("word ", 40)
	got := wrapFix(long, 40, "    ")
	for _, line := range strings.Split(got, "\n") {
		trimmed := strings.TrimLeft(line, " ")
		if len(trimmed) > 40 {
			t.Errorf("line is %d characters, over the 40 limit: %q", len(trimmed), trimmed)
		}
	}
	// Wrapping must not lose or duplicate words.
	if len(strings.Fields(got)) != len(strings.Fields(long)) {
		t.Errorf("word count changed: %d -> %d", len(strings.Fields(long)), len(strings.Fields(got)))
	}
}

// Azure trust cannot be resolved from a runtime target, and saying so beats reporting no findings as though the trust were fine.
func TestAzureExplainRefusesClearly(t *testing.T) {
	_, err := trustForTarget(t.Context(), core.AzureTarget{
		Tenant:   "11111111-1111-1111-1111-111111111111",
		ClientID: "22222222-2222-2222-2222-222222222222",
		Scope:    "https://management.azure.com/.default",
	})
	if err == nil {
		t.Fatal("want a refusal")
	}
	// It must name the actual obstacle — object id vs client id — not just "unsupported".
	if !strings.Contains(err.Error(), "object id") {
		t.Errorf("the refusal does not explain why: %v", err)
	}
	if !strings.Contains(err.Error(), "validate --ref") {
		t.Errorf("the refusal offers nowhere to go: %v", err)
	}
}

// A GCP pool without the /providers/ segment names a pool, not a provider, and the trust lives on the provider.
func TestGCPExplainRequiresTheProviderResource(t *testing.T) {
	_, err := trustForTarget(t.Context(), core.GCPTarget{
		WorkloadIdentityPool: "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p",
	})
	if err == nil {
		t.Fatal("want an error for a pool name with no provider segment")
	}
	if !strings.Contains(err.Error(), "providers/") {
		t.Errorf("the error does not say what shape is needed: %v", err)
	}
}
