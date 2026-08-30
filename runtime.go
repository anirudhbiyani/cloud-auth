// This file holds the runtime (data-plane) subcommands: obtaining short-lived
// credentials for one cloud from a workload running in another, with zero
// static secrets. They are dispatched from run() in controlplane.go.

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/anirudhbiyani/cloud-auth/broker"
	"github.com/anirudhbiyani/cloud-auth/config"
	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/internal/audit"
	"github.com/anirudhbiyani/cloud-auth/source"
)

// targetFlags builds a core.Target from a flag set.
//
// It returns an error rather than swallowing one: --to used to discard the parse
// failure, so a typo became the empty cloud and surfaced as "--to is required".
func targetFlags(fs *flag.FlagSet) func() (core.Target, error) {
	to := fs.String("to", "", "target cloud: aws|gcp|azure")
	role := fs.String("role", "", "AWS role ARN")
	sessionName := fs.String("session-name", "", "AWS sts:RoleSessionName (default: the proof's subject)")
	pool := fs.String("pool", "", "GCP workload identity pool provider resource name")
	impersonate := fs.String("impersonate", "", "GCP service account to impersonate (optional)")
	tenant := fs.String("tenant", "", "Azure tenant id (GUID or verified domain)")
	clientID := fs.String("client-id", "", "Azure app/UAMI client id")
	scope := fs.String("scope", "", "Azure resource scope (required for azure)")
	audience := fs.String("audience", "", "token audience (defaults per cloud)")

	return func() (core.Target, error) {
		if strings.TrimSpace(*to) == "" {
			// A typed zero, not nil: core.Target is an interface, and every
			// consumer calls a method on this before it can decide anything.
			return core.NoTarget{}, nil // the caller may resolve a target from --config
		}
		cloud, err := core.ParseCloud(*to)
		if err != nil {
			return nil, err
		}
		switch cloud {
		case core.AWS:
			return core.AWSTarget{
				RoleARN: *role, TokenAudience: *audience, SessionName: *sessionName,
			}, nil
		case core.GCP:
			return core.GCPTarget{
				WorkloadIdentityPool:      *pool,
				ImpersonateServiceAccount: *impersonate,
				TokenAudience:             *audience,
			}, nil
		case core.Azure:
			return core.AzureTarget{
				Tenant: *tenant, ClientID: *clientID, TokenAudience: *audience, Scope: *scope,
			}, nil
		default:
			return nil, fmt.Errorf("unsupported target cloud %q", cloud)
		}
	}
}

// defaultClockSkew is the tolerance applied to token expiry checks in doctor.
const defaultClockSkew = 60 * time.Second

// configFlags adds --config/--target to a command.
//
// Every data-plane command takes these now, not just doctor. The config file
// carries source.detect, and a restriction on which identity may be used is
// worthless if only the diagnostic command honours it.
func configFlags(fs *flag.FlagSet) (path, target *string) {
	return fs.String("config", "", "config file supplying the target and source restriction"),
		fs.String("target", "", "named target from --config")
}

// resolveRuntimeConfig merges flags with an optional config file and returns the
// target plus the source restriction to enforce.
//
// Explicit flags win: --to names a target directly, and a config file is only
// consulted for the target when no --to was given. source.detect always applies
// when a config is loaded, because it constrains the identity rather than
// selecting a destination.
func resolveRuntimeConfig(flagTarget core.Target, configPath, targetName string) (core.Target, core.Selector, error) {
	if configPath == "" {
		return flagTarget, core.Selector{}, nil
	}

	c, err := config.Load(configPath)
	if err != nil {
		return flagTarget, core.Selector{}, err
	}
	sel, err := c.SourceSelector()
	if err != nil {
		return flagTarget, core.Selector{}, err
	}

	target := flagTarget
	if target.Cloud() == "" {
		if targetName == "" {
			return target, sel, fmt.Errorf("--target is required with --config (or pass --to)")
		}
		if target, err = c.Target(targetName); err != nil {
			return target, sel, err
		}
	}
	return target, sel, nil
}

// auditRole records which identity was requested, for the audit line. Only AWS
// has a role; the others are identified by pool or client id.
func auditRole(t core.Target) string {
	switch v := t.(type) {
	case core.AWSTarget:
		return v.RoleARN
	case core.GCPTarget:
		if v.ImpersonateServiceAccount != "" {
			return v.ImpersonateServiceAccount
		}
		return v.WorkloadIdentityPool
	case core.AzureTarget:
		return v.ClientID
	default:
		return ""
	}
}

// brokerFor builds a broker whose detection is restricted to sel.
func brokerFor(sel core.Selector) *broker.Broker {
	if sel.IsAuto() {
		return broker.New()
	}
	return broker.New(broker.WithRegistry(source.DefaultRestricted(sel)))
}

func cmdDoctor(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	getTarget := targetFlags(fs)
	configPath := fs.String("config", "", "config file to resolve a named target (optional)")
	targetName := fs.String("target", "", "named target from --config to preflight")
	explain := fs.Bool("explain", false,
		"read the target's live trust and diff it against the presented assertion "+
			"(needs target-side read credentials)")
	format := fs.String("format", "text", "output format: text|json")
	fs.Parse(args)

	prov, rt, detectErr := source.Default().Detect(ctx)

	// Print what was detected, degrading gracefully off-cloud — but NOT in json
	// mode, where stdout carries one document and a human preamble in front of
	// it is exactly the bug `list --output json` had.
	if *format != "json" {
		printRuntime(os.Stdout, rt, detectErr)
	}

	flagTarget, err := getTarget()
	if err != nil {
		return err
	}
	target, sel, err := resolveRuntimeConfig(flagTarget, *configPath, *targetName)
	if err != nil {
		return err
	}
	// Report a restriction violation as the finding it is: detection may have
	// succeeded while producing an identity the config forbids.
	if detectErr == nil {
		if mErr := sel.Match(rt); mErr != nil {
			if *format != "json" {
				fmt.Fprintf(os.Stdout, "\n✗ %v\n", mErr)
			}
			return mErr
		}
	}
	if target.Cloud() == "" {
		// Detection-only. In json mode that is still a report — a consumer
		// asked for a document and must get one.
		if *format == "json" {
			return writeDoctorJSON(os.Stdout,
				preflight{runtime: rt, detectErr: detectErr}, nil, nil, nil, nil)
		}
		return nil
	}
	if target.Audience() == "" {
		return fmt.Errorf("doctor: --audience is required to preflight a target")
	}

	p := preflight{
		runtime:   rt,
		detectErr: detectErr,
		target:    target,
		now:       time.Now(),
		skew:      defaultClockSkew,
	}
	// Only attempt a mint if detection succeeded and the runtime can federate.
	if detectErr == nil && rt != nil && rt.Federatable && prov != nil {
		p.token, p.mintErr = prov.Mint(ctx, target.Audience())
	}

	diagnoses := diagnose(p)

	// --explain performs the one piece of I/O diagnose() must never do, and
	// does it HERE so diagnose() stays pure: the trust policy is fetched by the
	// caller and compared as data.
	var (
		trust    *core.TrustPolicy
		findings []core.Finding
		trustErr error
	)
	if *explain {
		trust, trustErr = trustForTarget(ctx, target)
		if trustErr == nil {
			findings = core.Explain(core.ExplainInput{
				Trust: trust, Token: p.token, Target: target,
				SourceCloud: runtimeCloud(rt),
			})
		}
	}

	if *format == "json" {
		return writeDoctorJSON(os.Stdout, p, diagnoses, trust, findings, trustErr)
	}

	writeDiagnoses(os.Stdout, p, diagnoses)
	if *explain {
		writeExplanation(os.Stdout, trust, findings, trustErr)
	}

	// A critical finding means this exchange will not work. Exiting 0 on that
	// would make --explain useless in a pipeline, which is half its point.
	for _, f := range findings {
		if f.Severity == core.FindingCritical {
			return errValidationFailed(fmt.Errorf(
				"%d trust finding(s), the most severe critical: %s", len(findings), f.Summary))
		}
	}
	return nil
}

// runtimeCloud returns the detected cloud, or empty.
func runtimeCloud(rt *core.Runtime) core.Cloud {
	if rt == nil {
		return ""
	}
	return rt.Cloud
}

// printRuntime writes the detected-runtime summary, degrading gracefully when
// detection failed (e.g. not running on a real cloud).
func printRuntime(w io.Writer, rt *core.Runtime, detectErr error) {
	if detectErr != nil || rt == nil {
		fmt.Fprintf(w, "Detected runtime:\n  (none) — %v\n", detectErr)
		return
	}
	fmt.Fprintf(w, "Detected runtime:\n  cloud:       %s\n  sub-runtime: %s\n  federatable: %t\n",
		rt.Cloud, rt.SubRuntime, rt.Federatable)
	if rt.Subject != "" {
		fmt.Fprintf(w, "  subject:     %s\n", rt.Subject)
	}
	if rt.Issuer != "" {
		fmt.Fprintf(w, "  issuer:      %s\n", rt.Issuer)
	}
	if !rt.Federatable {
		fmt.Fprintln(w, "\n⚠  This runtime cannot produce a federatable token. Use an OIDC-native source (e.g. EKS IRSA).")
	}
}

func cmdExchange(ctx context.Context, args []string, defaultFormat string) error {
	fs := flag.NewFlagSet("exchange", flag.ExitOnError)
	getTarget := targetFlags(fs)
	configPath, targetName := configFlags(fs)
	format := fs.String("format", defaultFormat, "output format: env|json|credential-process")
	fs.Parse(args)

	flagTarget, err := getTarget()
	if err != nil {
		return err
	}
	target, sel, err := resolveRuntimeConfig(flagTarget, *configPath, *targetName)
	if err != nil {
		return err
	}
	if target.Cloud() == "" {
		return fmt.Errorf("--to or --config/--target is required")
	}
	if target.Audience() == "" {
		return fmt.Errorf("--audience is required (pinned per target)")
	}

	// credential-process is the same operation as exchange wearing a different
	// output contract, but a SIEM should be able to tell them apart: one is a
	// person or a script, the other is an SDK refreshing on its own schedule.
	op := audit.OpExchange
	if *format == "credential-process" {
		op = audit.OpCredentialProcess
	}
	aud := newAuditor(op).with(func(e *audit.Event) {
		e.TargetCloud = string(target.Cloud())
		e.Role = auditRole(target)
	})

	creds, rt, err := brokerFor(sel).Exchange(ctx, target)
	if rt != nil {
		aud.with(func(e *audit.Event) { e.SourceIdentity = rt.Subject })
	}
	if err != nil {
		return aud.finish(err)
	}
	aud.with(func(e *audit.Event) { e.STSRequestID = creds.STSRequestID })
	_ = aud.finish(nil)

	switch *format {
	case "json", "credential-process":
		out, err := credentialProcessJSON(creds)
		if err != nil {
			return err
		}
		fmt.Println(string(out))
	default:
		fmt.Print(formatEnv(creds))
	}
	return nil
}

func cmdConfigValidate(args []string) error {
	fs := flag.NewFlagSet("config-validate", flag.ExitOnError)
	path := fs.String("config", "cloud-auth.yaml", "path to the federation config")
	fs.Parse(args)

	c, err := config.Load(*path)
	if err != nil {
		return err
	}
	fmt.Printf("✓ config %s is valid (%d targets)\n", *path, len(c.Targets))
	for _, t := range c.Targets {
		fmt.Printf("  - %s → %s\n", t.Name, t.Cloud)
	}
	return nil
}
