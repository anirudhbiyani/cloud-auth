// Command cloud-auth is the cloud-auth CLI: obtain short-lived credentials for one
// cloud from a workload running in another, with zero static secrets.
//
//	cloud-auth doctor                         detect runtime + print source identity
//	cloud-auth exchange --to aws --role ...   perform an exchange, print/export creds
//	cloud-auth credential-process --to aws    emit the AWS credential_process JSON
//	cloud-auth validate --config cloud-auth.yaml   lint the federation config
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/anirudhbiyani/cloud-auth/broker"
	"github.com/anirudhbiyani/cloud-auth/cloudauth"
	"github.com/anirudhbiyani/cloud-auth/config"
	"github.com/anirudhbiyani/cloud-auth/internal/audit"
	"github.com/anirudhbiyani/cloud-auth/source"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	ctx := context.Background()
	var err error
	switch os.Args[1] {
	case "doctor":
		err = cmdDoctor(ctx, os.Args[2:])
	case "exchange":
		err = cmdExchange(ctx, os.Args[2:], "env")
	case "credential-process":
		err = cmdExchange(ctx, os.Args[2:], "credential-process")
	case "validate":
		err = cmdValidate(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "cloud-auth: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "cloud-auth: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `cloud-auth — cross-cloud workload identity federation

Usage:
  cloud-auth doctor [--to CLOUD --role ARN --audience AUD]
  cloud-auth exchange --to CLOUD [--role ARN] [--pool WIP] [--tenant T --client-id C] --audience AUD [--format env|json]
  cloud-auth credential-process --to aws --role ARN --audience AUD
  cloud-auth validate --config cloud-auth.yaml
`)
}

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

func cmdDoctor(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	getTarget := targetFlags(fs)
	fs.Parse(args)

	prov, rt, err := source.Default().Detect(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Detected runtime:\n  cloud:       %s\n  sub-runtime: %s\n  federatable: %t\n",
		rt.Cloud, rt.SubRuntime, rt.Federatable)
	if rt.Subject != "" {
		fmt.Printf("  subject:     %s\n", rt.Subject)
	}
	if rt.Issuer != "" {
		fmt.Printf("  issuer:      %s\n", rt.Issuer)
	}
	if !rt.Federatable {
		fmt.Println("\n⚠  This runtime cannot produce a federatable token. Use an OIDC-native source (e.g. EKS IRSA).")
	}

	target := getTarget()
	if target.Cloud == "" {
		return nil // detection-only
	}
	if target.Audience == "" {
		return fmt.Errorf("doctor: --audience is required to preflight a target")
	}
	fmt.Printf("\nPreflight target %s (audience %s):\n", target.Cloud, target.Audience)
	if _, err := prov.Mint(ctx, target.Audience); err != nil {
		fmt.Printf("  ✗ minting source proof failed: %v\n", err)
		return nil
	}
	fmt.Println("  ✓ source proof minted successfully")
	return nil
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

func cmdValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
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
