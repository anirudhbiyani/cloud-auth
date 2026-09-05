package core

import (
	"errors"
	"strings"
	"testing"
)

func TestParseSelector(t *testing.T) {
	valid := map[string]Selector{
		"":                     {},
		"auto":                 {},
		"  AUTO  ":             {},
		"aws":                  {Cloud: AWS},
		"gcp":                  {Cloud: GCP},
		"azure":                {Cloud: Azure},
		"aws-ec2":              {Cloud: AWS, SubRuntime: "ec2"},
		"aws-eks-irsa":         {Cloud: AWS, SubRuntime: "eks-irsa"},
		"gcp:gke":              {Cloud: GCP, SubRuntime: "gke"},
		"azure/container-apps": {Cloud: Azure, SubRuntime: "container-apps"},
		"AWS-EC2":              {Cloud: AWS, SubRuntime: "ec2"},
	}
	for in, want := range valid {
		got, err := ParseSelector(in)
		if err != nil {
			t.Errorf("ParseSelector(%q) = %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseSelector(%q) = %+v, want %+v", in, got, want)
		}
	}

	// A typo must fail loudly.
	invalid := []string{"aws-ec3", "gcp-gek", "azure-vmm", "kubernetes", "amazon", "aws-", "-ec2"}
	for _, in := range invalid {
		if got, err := ParseSelector(in); err == nil {
			t.Errorf("ParseSelector(%q) = %+v, want an error", in, got)
		}
	}
}

func TestSelectorRoundTripsThroughString(t *testing.T) {
	for _, in := range []string{"auto", "aws", "gcp-gke", "azure-aks-workload-identity"} {
		sel, err := ParseSelector(in)
		if err != nil {
			t.Fatalf("ParseSelector(%q): %v", in, err)
		}
		if got := sel.String(); got != in {
			t.Errorf("String() = %q, want %q", got, in)
		}
	}
}

func TestSelectorMatch(t *testing.T) {
	ec2 := &Runtime{Cloud: AWS, SubRuntime: "ec2"}

	if err := (Selector{}).Match(ec2); err != nil {
		t.Errorf("auto must match anything: %v", err)
	}
	if err := (Selector{Cloud: AWS}).Match(ec2); err != nil {
		t.Errorf("cloud match: %v", err)
	}
	if err := (Selector{Cloud: AWS, SubRuntime: "ec2"}).Match(ec2); err != nil {
		t.Errorf("exact match: %v", err)
	}

	// The cases that matter: detection succeeded, but produced an identity the operator forbade.
	wrongCloud := (Selector{Cloud: GCP}).Match(ec2)
	if !errors.Is(wrongCloud, ErrRuntimeMismatch) {
		t.Errorf("want ErrRuntimeMismatch for a different cloud, got %v", wrongCloud)
	}
	if !strings.Contains(wrongCloud.Error(), "aws/ec2") {
		t.Errorf("the error must name what was detected: %v", wrongCloud)
	}

	wrongSub := (Selector{Cloud: AWS, SubRuntime: "eks-irsa"}).Match(ec2)
	if !errors.Is(wrongSub, ErrRuntimeMismatch) {
		t.Errorf("want ErrRuntimeMismatch for a different sub-runtime, got %v", wrongSub)
	}
}
