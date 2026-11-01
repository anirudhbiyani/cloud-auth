// Command verifier is the in-cloud half of the cloud-auth integration harness.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/anirudhbiyani/cloud-auth/broker"
	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/source"
	"github.com/anirudhbiyani/cloud-auth/test/harness/verifier/verify"
)

// detectTimeout bounds runtime detection: every detector probes a metadata endpoint, and a black-holed IMDS must not hang the Job forever.
const detectTimeout = 15 * time.Second

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if api := os.Getenv("AWS_LAMBDA_RUNTIME_API"); api != "" {
		os.Exit(lambdaLoop(ctx, "http://"+api+"/2018-06-01/runtime/invocation/", []string{"--allow-empty"}))
	}
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, os.Getenv, func() verify.Exchanger { return broker.New() }))
}

// lambdaLoop serves the Lambda custom-runtime API: each event is a targets.json document, each response the JSON report. The binary is the function's `bootstrap`, so one static build covers every runtime.
// ponytail: hand-rolled runtime loop instead of aws-lambda-go; it is three HTTP calls and saves a dependency.
func lambdaLoop(ctx context.Context, api string, args []string) int {
	for {
		resp, err := http.Get(api + "next") // #nosec G107 -- the runtime API host comes from Lambda itself.
		if err != nil {
			fmt.Fprintf(os.Stderr, "verifier: lambda runtime api: %v\n", err)
			return 1
		}
		id := resp.Header.Get("Lambda-Runtime-Aws-Request-Id")
		event, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || id == "" {
			fmt.Fprintf(os.Stderr, "verifier: lambda runtime api: /next answered %d\n", resp.StatusCode)
			return 1
		}

		var out, log bytes.Buffer
		getenv := func(k string) string {
			if k == verify.EnvTargetsInline {
				return string(event)
			}
			return os.Getenv(k)
		}
		code := run(ctx, args, &out, &log, getenv, func() verify.Exchanger { return broker.New() })
		_, _ = os.Stderr.Write(log.Bytes()) // CloudWatch
		body := out.Bytes()
		if len(body) == 0 {
			body = fmt.Appendf(nil, `{"error":"verifier exited %d before writing a report","log":%q}`, code, log.String())
		}
		post, err := http.Post(api+id+"/response", "application/json", bytes.NewReader(body)) // #nosec G107
		if err != nil {
			fmt.Fprintf(os.Stderr, "verifier: posting response: %v\n", err)
			return 1
		}
		_ = post.Body.Close()
	}
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

// run is main's testable body: everything cloud-touching arrives through newExchanger and the detector, everything else is plain data.
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
		// Every runtime in the matrix owns at least one case, so an empty selection normally means the plan and the deployment disagree.
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

// resolveRuntime returns the detected runtime and its canonical key.
func resolveRuntime(ctx context.Context, override string) (*core.Runtime, string, error) {
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

// planRuntimes lists the distinct runtimes a plan covers, for the "nothing to do here" diagnostic.
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

// openOut resolves --out to a writer.
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
