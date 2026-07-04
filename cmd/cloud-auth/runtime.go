// This file holds the runtime (data-plane) subcommands of the cloud-auth CLI:
// obtaining short-lived credentials for one cloud from a workload running in
// another, with zero static secrets. These are dispatched from run() in
// controlplane.go, which is the single entry point.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/anirudhbiyani/cloud-auth/broker"
	"github.com/anirudhbiyani/cloud-auth/cloudauth"
	"github.com/anirudhbiyani/cloud-auth/config"
	"github.com/anirudhbiyani/cloud-auth/internal/audit"
	"github.com/anirudhbiyani/cloud-auth/source"
)

// targetFlags builds a cloudauth.Target from a flag set.
func targetFlags(fs *flag.FlagSet) func() cloudauth.Target {
	to := fs.String("to", "", "target cloud: aws|gcp|azure")
	role := fs.String("role", "", "AWS role ARN")
	pool := fs.String("pool", "", "GCP workload identity pool")
	impersonate := fs.String("impersonate", "", "GCP service account to impersonate (optional)")
	tenant := fs.String("tenant", "", "Azure tenant id")
	clientID := fs.String("client-id", "", "Azure app/UAMI client id")
	audience := fs.String("audience", "", "token audience (required, pinned per target)")
	return func() cloudauth.Target {
		cloud, _ := cloudauth.ParseCloud(*to)
		return cloudauth.Target{
			Cloud: cloud, Role: *role, WorkloadIdentityPool: *pool,
			ImpersonateServiceAccount: *impersonate, Tenant: *tenant,
			ClientID: *clientID, Audience: *audience,
		}
	}
}

// defaultClockSkew is the tolerance applied to token expiry checks in doctor.
const defaultClockSkew = 60 * time.Second

func cmdDoctor(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	getTarget := targetFlags(fs)
	configPath := fs.String("config", "", "config file to resolve a named target (optional)")
	targetName := fs.String("target", "", "named target from --config to preflight")
	fs.Parse(args)

	prov, rt, detectErr := source.Default().Detect(ctx)

	// Always print what was detected (degrade gracefully off-cloud).
	printRuntime(os.Stdout, rt, detectErr)

	target := getTarget()
	// A named config target takes precedence when no explicit --to was given.
	if target.Cloud == "" && *configPath != "" && *targetName != "" {
		c, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		t, err := c.Target(*targetName)
		if err != nil {
			return err
		}
		target = t
	}
	if target.Cloud == "" {
		return nil // detection-only
	}
	if target.Audience == "" {
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
		p.token, p.mintErr = prov.Mint(ctx, target.Audience)
	}

	writeDiagnoses(os.Stdout, p, diagnose(p))
	return nil
}

// printRuntime writes the detected-runtime summary, degrading gracefully when
// detection failed (e.g. not running on a real cloud).
func printRuntime(w io.Writer, rt *cloudauth.Runtime, detectErr error) {
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
	format := fs.String("format", defaultFormat, "output format: env|json|credential-process")
	fs.Parse(args)

	target := getTarget()
	if target.Cloud == "" {
		return fmt.Errorf("--to is required")
	}
	if target.Audience == "" {
		return fmt.Errorf("--audience is required (pinned per target)")
	}

	auditLog := audit.New(os.Stderr)
	start := time.Now()
	creds, rt, err := broker.New().Exchange(ctx, target)
	ev := audit.Event{
		Timestamp: start.UTC(), TargetCloud: string(target.Cloud), Role: target.Role,
		LatencyMS: time.Since(start).Milliseconds(),
	}
	if rt != nil {
		ev.SourceIdentity = rt.Subject
	}
	if err != nil {
		ev.Outcome, ev.Error = "failure", err.Error()
		auditLog.Emit(ev)
		return err
	}
	ev.Outcome, ev.STSRequestID = "success", creds.STSRequestID
	auditLog.Emit(ev)

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
