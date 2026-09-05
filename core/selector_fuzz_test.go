package core

import (
	"strings"
	"testing"
)

// source.detect restricts which identity a workload may use, so a value that parses must mean exactly what it says: no silent widening, no fallback to auto, and every accepted value must round-trip.
func FuzzParseSelector(f *testing.F) {
	f.Add("auto")
	f.Add("aws")
	f.Add("aws-ec2")
	f.Add("gcp:gke")
	f.Add("azure/container-apps")
	f.Add("")
	f.Add("aws-")
	f.Add("kubernetes")

	f.Fuzz(func(t *testing.T, in string) {
		sel, err := ParseSelector(in)
		if err != nil {
			// A rejected value must not have produced a restriction.
			if !sel.IsAuto() {
				t.Fatalf("error path returned a restriction: %+v", sel)
			}
			return
		}
		// Anything that parsed must round-trip, or String and ParseSelector disagree about what was configured.
		round, rerr := ParseSelector(sel.String())
		if rerr != nil || round != sel {
			t.Fatalf("%q parsed to %+v, which does not round-trip (%+v, %v)", in, sel, round, rerr)
		}
		// A restriction must never be silently empty for a non-auto input.
		trimmed := strings.ToLower(strings.TrimSpace(in))
		if trimmed != "" && trimmed != "auto" && sel.IsAuto() {
			t.Fatalf("input %q accepted but imposes no restriction", in)
		}
	})
}

// A trust policy's subject arrives from IAM.
func FuzzIsUnscoped(f *testing.F) {
	f.Add("*")
	f.Add("repo:org/repo:*")
	f.Add("")
	f.Add("*:*:*")
	f.Add("?*")

	f.Fuzz(func(t *testing.T, pattern string) {
		got := isUnscoped(pattern)
		if got != isUnscoped("  "+pattern+"  ") {
			t.Fatalf("isUnscoped(%q) depends on surrounding whitespace", pattern)
		}
		// Anything that pins a real character is scoped.
		meaningful := strings.Trim(strings.ReplaceAll(strings.TrimSpace(pattern), ":", ""), "*?")
		if got && meaningful != "" {
			t.Fatalf("isUnscoped(%q) = true but it pins real characters (%q)", pattern, meaningful)
		}
	})
}
