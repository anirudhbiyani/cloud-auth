package core

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Selector pins which runtime a workload is allowed to authenticate as.
//
// Auto-detection is convenient and, for a credential source, a little dangerous:
// the probe order decides the identity, and a host can satisfy more than one
// probe — an EC2 instance with AWS_* variables in its environment, a pod whose
// projected token sits beside an instance profile. An operator who knows where
// the workload runs can say so, and then a mismatch is an error instead of a
// silent switch to a different identity.
//
// The zero Selector matches anything, which is the auto-detect default.
type Selector struct {
	// Cloud restricts detection to one provider. Empty matches any.
	Cloud Cloud
	// SubRuntime additionally requires a named sub-runtime ("ec2", "eks-irsa",
	// "gke", "aks-workload-identity", …). Empty matches any.
	SubRuntime string
}

// IsAuto reports whether the selector imposes no restriction.
func (s Selector) IsAuto() bool { return s.Cloud == "" && s.SubRuntime == "" }

// String renders the selector in the form ParseSelector accepts.
func (s Selector) String() string {
	switch {
	case s.IsAuto():
		return "auto"
	case s.SubRuntime == "":
		return string(s.Cloud)
	default:
		return string(s.Cloud) + "-" + s.SubRuntime
	}
}

// ParseSelector reads the config's `source.detect` value.
//
// Accepted forms:
//
//	auto                      no restriction (the default)
//	aws | gcp | azure         require that cloud
//	aws-ec2, gcp-gke, …       require that cloud and sub-runtime
//
// Anything else is an error rather than a silent fallback to auto. A typo in a
// field whose purpose is to constrain which identity may be used has to fail
// loudly, or it constrains nothing and reads as though it does.
func ParseSelector(s string) (Selector, error) {
	trimmed := strings.ToLower(strings.TrimSpace(s))
	if trimmed == "" || trimmed == "auto" {
		return Selector{}, nil
	}

	cloudPart, subPart := trimmed, ""
	if i := strings.IndexAny(trimmed, "-:/"); i >= 0 {
		cloudPart, subPart = trimmed[:i], trimmed[i+1:]
		// "aws-" is malformed, not a synonym for "aws". Quietly repairing it would
		// be the wrong instinct for a field whose job is to constrain identity:
		// the operator meant to name a sub-runtime and something dropped it.
		if cloudPart == "" || subPart == "" {
			return Selector{}, fmt.Errorf("source.detect %q: malformed; use auto, a cloud "+
				"(aws), or a cloud and sub-runtime (aws-ec2)", s)
		}
	}

	cloud, err := ParseFederationTarget(cloudPart)
	if err != nil {
		return Selector{}, fmt.Errorf("source.detect %q: %w (want auto, or a cloud such as "+
			"aws/gcp/azure, optionally with a sub-runtime such as aws-ec2)", s, err)
	}

	sel := Selector{Cloud: cloud, SubRuntime: subPart}
	if subPart != "" && !knownSubRuntimes[cloud][subPart] {
		return Selector{}, fmt.Errorf("source.detect %q: %s has no sub-runtime %q (known: %s)",
			s, cloud, subPart, strings.Join(subRuntimeNames(cloud), ", "))
	}
	return sel, nil
}

// knownSubRuntimes is what the detectors in this package can actually report.
// Validating against it turns a typo into an error at config load rather than a
// mismatch at first exchange.
var knownSubRuntimes = map[Cloud]map[string]bool{
	AWS: {
		"ec2": true, "ecs": true, "lambda": true,
		"eks-irsa": true, "eks-pod-identity": true,
	},
	GCP: {
		"gce": true, "gke": true, "cloud-run": true, "cloud-functions": true,
	},
	Azure: {
		"vm": true, "aks-workload-identity": true,
		"app-service": true, "container-apps": true,
	},
}

func subRuntimeNames(c Cloud) []string {
	names := make([]string, 0, len(knownSubRuntimes[c]))
	for n := range knownSubRuntimes[c] {
		names = append(names, n)
	}
	// Sorted so the error message is stable and diffable.
	slices.Sort(names)
	return names
}

// ErrRuntimeMismatch means detection succeeded but produced a runtime the
// configuration does not permit.
//
// Deliberately distinct from ErrNotThisRuntime: that one means "keep looking",
// this one means "stop". An operator who pinned source.detect wants a hard
// failure, not a fallback to whatever the next probe finds.
var ErrRuntimeMismatch = errors.New("cloud-auth: detected runtime does not match source.detect")

// Match reports whether rt satisfies the selector, and explains why not.
func (s Selector) Match(rt *Runtime) error {
	if s.IsAuto() || rt == nil {
		return nil
	}
	if s.Cloud != "" && rt.Cloud != s.Cloud {
		return fmt.Errorf("%w: detected %s/%s but source.detect requires %s; refusing to "+
			"authenticate as an identity the configuration did not permit",
			ErrRuntimeMismatch, rt.Cloud, rt.SubRuntime, s)
	}
	if s.SubRuntime != "" && rt.SubRuntime != s.SubRuntime {
		return fmt.Errorf("%w: detected %s/%s but source.detect requires %s; refusing to "+
			"authenticate as an identity the configuration did not permit",
			ErrRuntimeMismatch, rt.Cloud, rt.SubRuntime, s)
	}
	return nil
}
