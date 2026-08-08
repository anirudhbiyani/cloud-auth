//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/anirudhbiyani/cloud-auth/broker"
	"github.com/anirudhbiyani/cloud-auth/source"
	"github.com/anirudhbiyani/cloud-auth/test/harness/verifier/verify"
)

// defaultTargetsPath is where the driver merges the stage-2 outputs. Tests run
// with their package directory as the working directory.
const defaultTargetsPath = "../harness/state/targets.json"

// detectTimeout bounds runtime detection. Off-cloud, every metadata probe has
// to fail before we can skip, so this is also the worst-case skip latency.
const detectTimeout = 10 * time.Second

// caseTimeout bounds a single exchange.
const caseTimeout = 60 * time.Second

// loadPlan resolves the merged targets.json, skipping the whole test when the
// harness has not been stood up. A malformed plan is a real failure: the file
// exists, so something is wrong with it.
func loadPlan(t *testing.T) *verify.Plan {
	t.Helper()
	plan, origin, err := verify.ResolvePlan(os.Getenv, defaultTargetsPath)
	switch {
	case errors.Is(err, verify.ErrPlanNotFound):
		t.Skipf("no harness state: %v\n"+
			"  stand the harness up first (test/harness/scripts/up.sh), or point $%s at a merged targets.json",
			err, verify.EnvTargetsFile)
	case err != nil:
		t.Fatalf("targets plan at %s is unusable: %v", origin, err)
	}
	t.Logf("plan %s: run %s, %d cases", origin, plan.RunID, len(plan.Cases))
	return plan
}

// detectRuntime resolves the runtime this test process is running on, skipping
// when it is not one of the harness source runtimes (i.e. a laptop).
func detectRuntime(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), detectTimeout)
	defer cancel()

	_, rt, err := source.Default().Detect(ctx)
	if err != nil {
		t.Skipf("not running inside a harness source runtime (%v);\n"+
			"  these tests execute in-cloud — run them from the verifier Job/instance, not a laptop", err)
	}
	key := verify.RuntimeKey(rt)
	if key == "" {
		t.Skipf("detected %s/%s, which is not a source runtime in the pair matrix", rt.Cloud, rt.SubRuntime)
	}
	t.Logf("detected runtime %s (federatable=%t)", key, rt.Federatable)
	return key
}

// TestPairMatrix runs one subtest per case in the merged plan, named after the
// case. Cases belonging to another source runtime skip: the matrix is executed
// by running this same suite in every source runtime, and each run owns its
// slice of it.
func TestPairMatrix(t *testing.T) {
	plan := loadPlan(t)
	key := detectRuntime(t)

	runner := &verify.Runner{
		Exchanger: broker.New(),
		Probes:    verify.DefaultProbes(),
		Scrubber:  verify.NewScrubber(),
		Timeout:   caseTimeout,
	}

	for _, c := range plan.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if verify.CanonicalRuntime(c.SourceRuntime) != key {
				t.Skipf("case runs on %s; this host is %s", c.SourceRuntime, key)
			}
			res := runner.RunCase(context.Background(), c)
			logResult(t, runner.Scrubber, res)

			if res.Status != verify.StatusPass {
				t.Fatalf("case %q failed: %s", c.Name, res.Error)
			}
			if c.Expect == verify.ExpectError {
				t.Logf("documented gap held: failed with %s", res.MatchedSentinel)
			}
		})
	}
}

// TestPlanCoversTheDocumentedGap guards the negative row of the matrix: the
// harness must assert that AWS-EC2 → Azure fails with ErrNoFirstClassPath. A
// plan without it would go green while the guard silently rotted away.
func TestPlanCoversTheDocumentedGap(t *testing.T) {
	plan := loadPlan(t)

	var gaps int
	for _, c := range plan.Cases {
		if c.Expect == verify.ExpectError && c.ExpectError == "ErrNoFirstClassPath" {
			gaps++
			t.Logf("negative case %q: %s → %s", c.Name, c.SourceRuntime, c.Target.Cloud)
		}
	}
	if gaps == 0 {
		t.Errorf("plan has no expect=error/ErrNoFirstClassPath case; " +
			"CONTRACT.md requires the AWS-EC2 → Azure gap to be asserted")
	}
}

// TestPlanRuntimeCoverage reports which source runtimes the plan expects, so a
// harness run that never scheduled one of them is visible in the logs rather
// than silently passing with everything skipped.
func TestPlanRuntimeCoverage(t *testing.T) {
	plan := loadPlan(t)

	counts := map[string]int{}
	for _, c := range plan.Cases {
		counts[verify.CanonicalRuntime(c.SourceRuntime)]++
	}
	for rt, n := range counts {
		t.Logf("%-30s %d case(s)", rt, n)
	}
	if len(counts) == 0 {
		t.Fatal("plan selects no runtimes")
	}
}

// logResult prints the scrubbed JSON result for the case. It goes through the
// same report writer as the verifier, so the no-credentials guarantee holds
// here too.
func logResult(t *testing.T, s *verify.Scrubber, res verify.CaseResult) {
	t.Helper()
	b, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		t.Logf("result: %+v", res)
		return
	}
	var buf bytes.Buffer
	buf.Write(s.ScrubBytes(b))
	t.Logf("result: %s", buf.String())
}
