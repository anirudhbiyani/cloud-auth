package verify

import (
	"errors"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// contractPlan is the example from test/harness/CONTRACT.md, verbatim.
const contractPlan = `{
  "run_id": "20260705-abc123",
  "cases": [
    {
      "name": "gcp-gce-to-aws",
      "expect": "success",
      "source_runtime": "gcp-gce",
      "target": { "cloud": "aws", "role": "arn:aws:iam::123:role/x", "audience": "sts.amazonaws.com" },
      "probe": "sts-get-caller-identity"
    },
    {
      "name": "aws-ec2-to-azure-gap",
      "expect": "error",
      "expect_error": "ErrNoFirstClassPath",
      "source_runtime": "aws-ec2",
      "target": { "cloud": "azure", "tenant": "t", "client_id": "c", "audience": "api://AzureADTokenExchange" }
    }
  ]
}`

func TestLoadPlanParsesContractExample(t *testing.T) {
	p, err := LoadPlan([]byte(contractPlan))
	if err != nil {
		t.Fatalf("LoadPlan: %v", err)
	}
	if p.RunID != "20260705-abc123" {
		t.Errorf("run_id = %q", p.RunID)
	}
	if len(p.Cases) != 2 {
		t.Fatalf("cases = %d, want 2", len(p.Cases))
	}
	c0 := p.Cases[0]
	if c0.Name != "gcp-gce-to-aws" || c0.Expect != ExpectSuccess ||
		c0.SourceRuntime != RuntimeGCPGCE || c0.Probe != "sts-get-caller-identity" {
		t.Errorf("case[0] = %+v", c0)
	}
	c1 := p.Cases[1]
	if c1.Expect != ExpectError || c1.ExpectError != "ErrNoFirstClassPath" ||
		c1.SourceRuntime != RuntimeAWSEC2 {
		t.Errorf("case[1] = %+v", c1)
	}
}

func TestLoadPlanRejectsMalformedCases(t *testing.T) {
	tests := []struct {
		name string
		json string
		want string
	}{
		{"not json", `{`, "parsing"},
		{"no cases", `{"run_id":"r","cases":[]}`, "no cases"},
		{"missing name", `{"cases":[{"expect":"success","source_runtime":"gcp-gce",
			"target":{"cloud":"aws","audience":"a","role":"r"}}]}`, "name"},
		{"duplicate name", `{"cases":[
			{"name":"d","expect":"success","source_runtime":"gcp-gce","target":{"cloud":"aws","audience":"a","role":"r"}},
			{"name":"d","expect":"success","source_runtime":"gcp-gce","target":{"cloud":"aws","audience":"a","role":"r"}}]}`, "duplicate"},
		{"bad expect", `{"cases":[{"name":"c","expect":"maybe","source_runtime":"gcp-gce",
			"target":{"cloud":"aws","audience":"a","role":"r"}}]}`, "expect"},
		{"error without expect_error", `{"cases":[{"name":"c","expect":"error","source_runtime":"aws-ec2",
			"target":{"cloud":"azure","audience":"a","tenant":"t","client_id":"c"}}]}`, "expect_error"},
		{"unknown sentinel", `{"cases":[{"name":"c","expect":"error","expect_error":"ErrNope",
			"source_runtime":"aws-ec2","target":{"cloud":"azure","audience":"a","tenant":"t","client_id":"c"}}]}`, "unknown sentinel"},
		{"unknown runtime", `{"cases":[{"name":"c","expect":"success","source_runtime":"ibm-cloud",
			"target":{"cloud":"aws","audience":"a","role":"r"}}]}`, "source_runtime"},
		{"unknown cloud", `{"cases":[{"name":"c","expect":"success","source_runtime":"gcp-gce",
			"target":{"cloud":"oracle","audience":"a"}}]}`, "cloud"},
		{"missing audience", `{"cases":[{"name":"c","expect":"success","source_runtime":"gcp-gce",
			"target":{"cloud":"aws","role":"r"}}]}`, "audience"},
		{"aws target without role", `{"cases":[{"name":"c","expect":"success","source_runtime":"gcp-gce",
			"target":{"cloud":"aws","audience":"a"}}]}`, "role"},
		{"gcp target without pool", `{"cases":[{"name":"c","expect":"success","source_runtime":"aws-eks-irsa",
			"target":{"cloud":"gcp","audience":"a"}}]}`, "pool"},
		{"azure target without client id", `{"cases":[{"name":"c","expect":"success","source_runtime":"gcp-gce",
			"target":{"cloud":"azure","audience":"a","tenant":"t"}}]}`, "client_id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadPlan([]byte(tt.json))
			if err == nil {
				t.Fatalf("LoadPlan(%s) = nil error, want one mentioning %q", tt.name, tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want mention of %q", err, tt.want)
			}
		})
	}
}

func TestCanonicalRuntime(t *testing.T) {
	tests := []struct{ in, want string }{
		{"gcp-gce", RuntimeGCPGCE},
		{"GCP-GCE", RuntimeGCPGCE},
		{" gce ", RuntimeGCPGCE},
		{"gcp_gce", RuntimeGCPGCE},
		{"aws-ec2", RuntimeAWSEC2},
		{"ec2", RuntimeAWSEC2},
		{"aws-eks-irsa", RuntimeAWSEKSIRSA},
		{"eks-irsa", RuntimeAWSEKSIRSA},
		{"aws-eks", RuntimeAWSEKSIRSA},
		{"azure-aks-workload-identity", RuntimeAzureAKSWI},
		{"azure-aks-wi", RuntimeAzureAKSWI},
		{"aks-wi", RuntimeAzureAKSWI},
		{"azure-aks", RuntimeAzureAKSWI},
		{"ibm-cloud", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := CanonicalRuntime(tt.in); got != tt.want {
			t.Errorf("CanonicalRuntime(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestRuntimeKeyFromDetection(t *testing.T) {
	tests := []struct {
		name string
		rt   *core.Runtime
		want string
	}{
		{"eks irsa", &core.Runtime{Cloud: core.AWS, SubRuntime: "eks-irsa"}, RuntimeAWSEKSIRSA},
		{"ec2", &core.Runtime{Cloud: core.AWS, SubRuntime: "ec2"}, RuntimeAWSEC2},
		{"gce", &core.Runtime{Cloud: core.GCP, SubRuntime: "gce"}, RuntimeGCPGCE},
		{"aks wi", &core.Runtime{Cloud: core.Azure, SubRuntime: "aks-workload-identity"}, RuntimeAzureAKSWI},
		{"nil", nil, ""},
		{"unknown sub", &core.Runtime{Cloud: core.AWS, SubRuntime: "outposts"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RuntimeKey(tt.rt); got != tt.want {
				t.Errorf("RuntimeKey(%+v) = %q, want %q", tt.rt, got, tt.want)
			}
		})
	}
}

func TestSelectCasesPicksOnlyThisRuntime(t *testing.T) {
	p, err := LoadPlan([]byte(contractPlan))
	if err != nil {
		t.Fatalf("LoadPlan: %v", err)
	}
	tests := []struct {
		runtime string
		want    []string
	}{
		{RuntimeGCPGCE, []string{"gcp-gce-to-aws"}},
		{"gce", []string{"gcp-gce-to-aws"}},
		{RuntimeAWSEC2, []string{"aws-ec2-to-azure-gap"}},
		{RuntimeAWSEKSIRSA, nil},
		{"", nil},
	}
	for _, tt := range tests {
		t.Run(tt.runtime, func(t *testing.T) {
			got := SelectCases(p.Cases, tt.runtime)
			if len(got) != len(tt.want) {
				t.Fatalf("selected %d cases, want %d", len(got), len(tt.want))
			}
			for i, c := range got {
				if c.Name != tt.want[i] {
					t.Errorf("case[%d] = %q, want %q", i, c.Name, tt.want[i])
				}
			}
		})
	}
}

func TestSentinelFor(t *testing.T) {
	tests := []struct {
		in   string
		want error
		ok   bool
	}{
		{"ErrNoFirstClassPath", core.ErrNoFirstClassPath, true},
		{"errnofirstclasspath", core.ErrNoFirstClassPath, true},
		{"ErrTrustMissing", core.ErrTrustMissing, true},
		{"ErrNonFederatableSource", core.ErrNonFederatableSource, true},
		{"ErrNotThisRuntime", core.ErrNotThisRuntime, true},
		{"ErrSomethingElse", nil, false},
		{"", nil, false},
	}
	for _, tt := range tests {
		got, ok := SentinelFor(tt.in)
		if ok != tt.ok {
			t.Errorf("SentinelFor(%q) ok = %v, want %v", tt.in, ok, tt.ok)
		}
		if ok && !errors.Is(got, tt.want) {
			t.Errorf("SentinelFor(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestTargetSpecToTarget(t *testing.T) {
	tests := []struct {
		name string
		spec TargetSpec
		want core.Target
	}{
		{
			"aws",
			TargetSpec{Cloud: "aws", Role: "arn:aws:iam::123456789012:role/x"},
			core.AWSTarget{RoleARN: "arn:aws:iam::123456789012:role/x"},
		},
		{
			"gcp pool key",
			TargetSpec{Cloud: "gcp", Pool: "//iam.googleapis.com/projects/1/p1"},
			core.GCPTarget{WorkloadIdentityPool: "//iam.googleapis.com/projects/1/p1"},
		},
		{
			"gcp provider alias",
			TargetSpec{Cloud: "gcp", Provider: "//iam.googleapis.com/projects/1/p2", Audience: "a", Impersonate: "sa@p.iam.gserviceaccount.com"},
			core.GCPTarget{WorkloadIdentityPool: "//iam.googleapis.com/projects/1/p2", TokenAudience: "a", ImpersonateServiceAccount: "sa@p.iam.gserviceaccount.com"},
		},
		{
			"azure",
			TargetSpec{Cloud: "azure", Tenant: "11111111-1111-1111-1111-111111111111", ClientID: "22222222-2222-2222-2222-222222222222", Scope: "https://storage.azure.com/.default"},
			core.AzureTarget{Tenant: "11111111-1111-1111-1111-111111111111", ClientID: "22222222-2222-2222-2222-222222222222", Scope: "https://storage.azure.com/.default"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.spec.Target()
			if err != nil {
				t.Fatalf("Target: %v", err)
			}
			if got != tt.want {
				t.Errorf("Target() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestResolvePlanReportsMissingInput(t *testing.T) {
	env := func(string) string { return "" }
	_, _, err := ResolvePlan(env, "/nonexistent/targets.json")
	if !errors.Is(err, ErrPlanNotFound) {
		t.Fatalf("err = %v, want ErrPlanNotFound", err)
	}
}

func TestResolvePlanPrefersInlineEnv(t *testing.T) {
	env := func(k string) string {
		if k == EnvTargetsInline {
			return contractPlan
		}
		return ""
	}
	p, origin, err := ResolvePlan(env, "/nonexistent/targets.json")
	if err != nil {
		t.Fatalf("ResolvePlan: %v", err)
	}
	if len(p.Cases) != 2 {
		t.Errorf("cases = %d", len(p.Cases))
	}
	if !strings.Contains(origin, EnvTargetsInline) {
		t.Errorf("origin = %q, want mention of %s", origin, EnvTargetsInline)
	}
}
