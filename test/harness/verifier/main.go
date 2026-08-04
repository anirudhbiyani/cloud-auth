// Command verifier is the in-cloud half of the cloud-auth integration harness.
//
// The same static binary is deployed to every source runtime in the matrix (an
// EKS-IRSA pod, an AKS workload-identity pod, an EC2 instance, a GCE instance).
// On start it asks cloud-auth's own detector where it is, selects only the
// targets.json cases whose source_runtime matches, and runs each one through
// the broker (detect→mint→exchange). It writes a JSON report to stdout, a human
// summary to stderr, and exits non-zero if any case failed.
//
// It never prints credentials, tokens, or assertions — see verify.Scrubber.
//
// Usage:
//
//	verifier [--targets ./targets.json] [--runtime <key>] [--timeout 60s]
//	         [--skew 60s] [--probe-strict] [--allow-empty] [--out -]
//
// Environment:
//
//	CLOUD_AUTH_TARGETS_JSON  targets.json inline (ConfigMap / user-data delivery)
//	CLOUD_AUTH_TARGETS_FILE  path to targets.json (overrides --targets)
//
// Exit codes: 0 all selected cases passed; 1 at least one case failed;
// 2 the verifier could not run (no plan, undetectable runtime, bad flags).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/anirudhbiyani/cloud-auth/broker"
	"github.com/anirudhbiyani/cloud-auth/cloudauth"
	"github.com/anirudhbiyani/cloud-auth/source"
	"github.com/anirudhbiyani/cloud-auth/test/harness/verifier/verify"
)

// detectTimeout bounds runtime detection: every detector probes a metadata
// endpoint, and a black-holed IMDS must not hang the Job forever.
const detectTimeout = 15 * time.Second

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, os.Getenv, func() verify.Exchanger { return broker.New() }))
}

// options are the parsed flags.
type options struct {
	targets     string
	runtime     string
	timeout     time.Duration
	skew        time.Duration
	probeStrict bool
	allowEmpty  bool
	out         string
}

// run is main's testable body: everything cloud-touching arrives through
// newExchanger and the detector, everything else is plain data.
func run(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string, newExchanger func() verify.Exchanger) int {
	opts, err := parseFlags(args, stderr)
	if err != nil {
		return verify.ExitUsage
	}

	plan, origin, err := verify.ResolvePlan(getenv, opts.targets)
	if err != nil {
		fmt.Fprintf(stderr, "verifier: %v\n", err)
		if errors.Is(err, verify.ErrPlanNotFound) {
			fmt.Fprintf(stderr, "  deliver targets.json via --targets, $%s, or $%s\n",
				verify.EnvTargetsFile, verify.EnvTargetsInline)
		}
		return verify.ExitUsage
	}
	fmt.Fprintf(stderr, "verifier: plan %s (%d cases, run %s)\n", origin, len(plan.Cases), plan.RunID)

	rt, runtimeKey, err := resolveRuntime(ctx, opts.runtime)
	if err != nil {
		fmt.Fprintf(stderr, "verifier: %v\n", err)
		return verify.ExitUsage
	}

	selected := verify.SelectCases(plan.Cases, runtimeKey)
	if len(selected) == 0 {
		// Every runtime in the matrix owns at least one case, so an empty
		// selection normally means the plan and the deployment disagree.
		fmt.Fprintf(stderr, "verifier: no cases for runtime %q (plan covers %v)\n", runtimeKey, planRuntimes(plan))
		if !opts.allowEmpty {
			return verify.ExitUsage
		}
	}

	runner := &verify.Runner{
		Exchanger:   newExchanger(),
		Probes:      verify.DefaultProbes(),
		Scrubber:    verify.NewScrubber(),
		Skew:        opts.skew,
		Timeout:     opts.timeout,
		StrictProbe: opts.probeStrict,
	}

	started := time.Now()
	results := runner.Run(ctx, selected)
	report := verify.BuildReport(plan.RunID, runtimeKey, rt, results, started, time.Since(started))

	sink, closeSink, err := openOut(opts.out, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "verifier: %v\n", err)
		return verify.ExitUsage
	}
	defer closeSink()
	if err := report.WriteJSON(sink, runner.Scrubber); err != nil {
		fmt.Fprintf(stderr, "verifier: writing report: %v\n", err)
		return verify.ExitUsage
	}
	report.WriteHuman(stderr, runner.Scrubber)
	return report.ExitCode()
}

func parseFlags(args []string, stderr io.Writer) (options, error) {
	var o options
	fs := flag.NewFlagSet("verifier", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.targets, "targets", "./targets.json", "path to the merged targets.json")
	fs.StringVar(&o.runtime, "runtime", "", "override the detected source runtime key (e.g. aws-eks-irsa); detection is used when empty")
	fs.DurationVar(&o.timeout, "timeout", verify.DefaultCaseTimeout, "per-case timeout")
	fs.DurationVar(&o.skew, "skew", verify.DefaultSkew, "clock-skew tolerance for credential expiry")
	fs.BoolVar(&o.probeStrict, "probe-strict", false, "treat a failed or unimplemented probe as a case failure")
	fs.BoolVar(&o.allowEmpty, "allow-empty", false, "exit 0 when no case matches this runtime instead of failing")
	fs.StringVar(&o.out, "out", "-", `where to write the JSON report ("-" is stdout)`)
	return o, fs.Parse(args)
}

// resolveRuntime returns the detected runtime and its canonical key. An
// explicit override skips detection (useful when driving the binary by hand);
// an unrecognized runtime is fatal rather than silently selecting nothing.
func resolveRuntime(ctx context.Context, override string) (*cloudauth.Runtime, string, error) {
	if override != "" {
		key := verify.CanonicalRuntime(override)
		if key == "" {
			return nil, "", fmt.Errorf("unknown --runtime %q", override)
		}
		return nil, key, nil
	}
	dctx, cancel := context.WithTimeout(ctx, detectTimeout)
	defer cancel()

	_, rt, err := source.Default().Detect(dctx)
	if err != nil {
		return nil, "", fmt.Errorf("detecting source runtime: %w (this binary must run inside a harness source runtime; use --runtime to override)", err)
	}
	key := verify.RuntimeKey(rt)
	if key == "" {
		return rt, "", fmt.Errorf("detected %s/%s, which is not a runtime this harness covers", rt.Cloud, rt.SubRuntime)
	}
	return rt, key, nil
}

// planRuntimes lists the distinct runtimes a plan covers, for the "nothing to
// do here" diagnostic.
func planRuntimes(p *verify.Plan) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range p.Cases {
		k := verify.CanonicalRuntime(c.SourceRuntime)
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}

// openOut resolves --out to a writer. Writing the report to a file as well as
// exiting non-zero lets a Job's artifacts survive a failed run.
func openOut(path string, stdout io.Writer) (io.Writer, func(), error) {
	if path == "" || path == "-" {
		return stdout, func() {}, nil
	}
	// #nosec G304 -- report path is supplied by the operator (--out).
	f, err := os.Create(path)
	if err != nil {
		return nil, func() {}, fmt.Errorf("opening --out %s: %w", path, err)
	}
	return f, func() { _ = f.Close() }, nil
}
