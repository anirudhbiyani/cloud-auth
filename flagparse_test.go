package main

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// Characterisation tests for the four option parsers.
//
// These were written to pin the behaviour that exists, not the behaviour that
// ought to exist, so that the parsers can be re-implemented without guessing.
// parseValidateOpts and parseDeleteOpts had no coverage at all; parseSetupOpts
// had 35.7%, which is what made a rewrite of it a rewrite of untested code.
//
// Where current behaviour is arguably wrong, the test records it as-is and says
// so in a comment rather than asserting the preferred behaviour.

// Every long flag setup accepts, with the field it must land in. Kept exhaustive
// on purpose: a flag dropped in a rewrite is silently ignored input, and silent
// is the failure mode that reaches production.
func TestParseSetupOptsBindsEveryStringFlag(t *testing.T) {
	for flag, field := range map[string]string{
		"--file": "specFile", "--state": "statePath", "--type": "mechType",
		"--source": "source", "--audience": "audience", "--subject": "subject",
		"--issuer": "issuer", "--unscoped-justification": "unscopedJustification",
		"--attribute-condition": "attributeCondition", "--subject-scope": "subjectScope",
		"--attribute-scope": "attributeScope", "--role-name": "roleName",
		"--account-id": "accountID", "--oidc-url": "oidcURL", "--policy-arns": "policyARNs",
		"--project-id": "projectID", "--project-number": "projectNumber",
		"--pool-id": "poolID", "--provider-id": "providerID", "--provider-type": "providerType",
		"--aws-account-id": "awsAccountID", "--service-account": "serviceAccount",
		"--tenant-id": "tenantID", "--identity-type": "identityType", "--app-name": "appName",
		"--app-id": "appID", "--identity-name": "identityName", "--resource-group": "resourceGroup",
		"--subscription-id": "subscriptionID", "--credential-name": "credentialName",
		"--cluster-name": "clusterName", "--k8s-namespace": "k8sNamespace",
		"--k8s-sa-name": "k8sSAName", "--target-cloud": "targetCloud",
	} {
		t.Run(flag, func(t *testing.T) {
			args := []string{flag, "sentinel"}
			// --file and --type are mutually exclusive, and one is required.
			if flag != "--file" && flag != "--type" {
				args = append(args, "--type", "aws-oidc")
			}
			opts, err := parseSetupOpts(args)
			if err != nil {
				t.Fatalf("parseSetupOpts(%v): %v", args, err)
			}
			got := reflect.ValueOf(*opts).FieldByName(field).String()
			if got != "sentinel" {
				t.Errorf("%s landed in %s = %q, want %q", flag, field, got, "sentinel")
			}
		})
	}
}

func TestParseSetupOptsBindsEveryBoolFlag(t *testing.T) {
	for flag, field := range map[string]string{
		"--dry-run": "dryRun", "--force": "force", "--verbose": "verbose",
		"--require-idp-authorized-role":    "requireIdPAuthorizedRole",
		"--allow-unscoped-subject":         "allowUnscopedSubject",
		"--allow-whole-pool-impersonation": "allowWholePoolImpersonation",
		"--create-k8s-sa":                  "createK8sSA",
	} {
		t.Run(flag, func(t *testing.T) {
			opts, err := parseSetupOpts([]string{"--type", "aws-oidc", flag})
			if err != nil {
				t.Fatalf("parseSetupOpts: %v", err)
			}
			if !reflect.ValueOf(*opts).FieldByName(field).Bool() {
				t.Errorf("%s did not set %s", flag, field)
			}
			// And it must stay false when absent, rather than defaulting on.
			base, err := parseSetupOpts([]string{"--type", "aws-oidc"})
			if err != nil {
				t.Fatal(err)
			}
			if reflect.ValueOf(*base).FieldByName(field).Bool() {
				t.Errorf("%s defaults to true", field)
			}
		})
	}
}

func TestParseSetupOptsShortAliases(t *testing.T) {
	opts, err := parseSetupOpts([]string{"-f", "spec.yaml", "-v"})
	if err != nil {
		t.Fatalf("parseSetupOpts: %v", err)
	}
	if opts.specFile != "spec.yaml" || !opts.verbose {
		t.Errorf("-f/-v did not bind: %+v", opts)
	}
}

func TestParseSetupOptsDefaults(t *testing.T) {
	opts, err := parseSetupOpts([]string{"--type", "aws-oidc"})
	if err != nil {
		t.Fatalf("parseSetupOpts: %v", err)
	}
	if opts.statePath != core.DefaultStateStorePath() {
		t.Errorf("statePath = %q, want the default store path", opts.statePath)
	}
	// No audience default: this parser is shared by every mechanism type and
	// sts.amazonaws.com is only ever right for AWS. Per-type defaults belong to
	// the build*Spec functions.
	if opts.audience != "" {
		t.Errorf("audience = %q, want empty — defaulting it here mis-scopes GCP", opts.audience)
	}
}

func TestParseSetupOptsInputModeRules(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"neither":       {[]string{}, "either --file or --type is required"},
		"both":          {[]string{"--file", "s.yaml", "--type", "aws-oidc"}, "mutually exclusive"},
		"unknown":       {[]string{"--type", "aws-oidc", "--nope"}, "flag provided but not defined"},
		"missing value": {[]string{"--type"}, "flag needs an argument"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseSetupOpts(tc.args)
			if err == nil {
				t.Fatalf("want an error for %v", tc.args)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// The equals form. The hand-rolled parsers compared each argument to the flag
// name exactly, so `--type=aws-oidc` was rejected as an unknown option while
// `exec` and `doctor` — already on flag.FlagSet — accepted `--to=aws`. The same
// binary answered differently depending on the subcommand. Both forms now work
// everywhere, and a bare word is still refused, since these subcommands take
// options only.
func TestParseSetupOptsAcceptsBothFlagForms(t *testing.T) {
	for _, args := range [][]string{
		{"--type=aws-oidc"},
		{"--type", "aws-oidc"},
		{"-type=aws-oidc"},
	} {
		opts, err := parseSetupOpts(args)
		if err != nil {
			t.Fatalf("parseSetupOpts(%v): %v", args, err)
		}
		if opts.mechType != "aws-oidc" {
			t.Errorf("parseSetupOpts(%v): mechType = %q", args, opts.mechType)
		}
	}

	if _, err := parseSetupOpts([]string{"--type", "aws-oidc", "stray"}); err == nil ||
		!strings.Contains(err.Error(), "unexpected argument: stray") {
		t.Errorf("error = %v, want a positional argument refused", err)
	}
}

func TestParseValidateOpts(t *testing.T) {
	t.Run("full", func(t *testing.T) {
		opts, err := parseValidateOpts([]string{
			"--ref", "r-1", "--include-token-test", "--timeout", "90s",
			"--state", "/tmp/s.json", "-v",
		})
		if err != nil {
			t.Fatalf("parseValidateOpts: %v", err)
		}
		want := validateOpts{refID: "r-1", includeTokenTest: true,
			timeout: 90 * time.Second, statePath: "/tmp/s.json", verbose: true}
		if *opts != want {
			t.Errorf("got %+v, want %+v", *opts, want)
		}
	})

	t.Run("defaults", func(t *testing.T) {
		opts, err := parseValidateOpts([]string{"--ref", "r-1"})
		if err != nil {
			t.Fatalf("parseValidateOpts: %v", err)
		}
		if opts.timeout != 30*time.Second {
			t.Errorf("timeout = %v, want 30s", opts.timeout)
		}
		if opts.statePath != core.DefaultStateStorePath() {
			t.Errorf("statePath = %q", opts.statePath)
		}
	})

	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"ref required":    {[]string{}, "--ref is required"},
		"bad duration":    {[]string{"--ref", "r", "--timeout", "soon"}, "invalid timeout duration"},
		"missing ref arg": {[]string{"--ref"}, "flag needs an argument"},
		"unknown":         {[]string{"--ref", "r", "--x"}, "flag provided but not defined"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseValidateOpts(tc.args); err == nil ||
				!strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestParseDeleteOpts(t *testing.T) {
	opts, err := parseDeleteOpts([]string{
		"--ref", "r-1", "--dry-run", "--force", "-y", "--state", "/tmp/s.json", "-v",
	})
	if err != nil {
		t.Fatalf("parseDeleteOpts: %v", err)
	}
	want := deleteOpts{refID: "r-1", dryRun: true, force: true, yes: true,
		statePath: "/tmp/s.json", verbose: true}
	if *opts != want {
		t.Errorf("got %+v, want %+v", *opts, want)
	}

	// --yes and -y are the same flag; the long form must work too.
	long, err := parseDeleteOpts([]string{"--ref", "r", "--yes"})
	if err != nil || !long.yes {
		t.Errorf("--yes did not bind: %+v %v", long, err)
	}

	if _, err := parseDeleteOpts([]string{}); err == nil ||
		!strings.Contains(err.Error(), "--ref is required") {
		t.Errorf("error = %v, want --ref required", err)
	}
}

func TestParseListOpts(t *testing.T) {
	opts, err := parseListOpts([]string{
		"--type", "aws-oidc", "--provider", "aws", "-o", "json", "--state", "/tmp/s.json",
	})
	if err != nil {
		t.Fatalf("parseListOpts: %v", err)
	}
	want := listOpts{mechType: "aws-oidc", provider: "aws",
		output: "json", statePath: "/tmp/s.json"}
	if *opts != want {
		t.Errorf("got %+v, want %+v", *opts, want)
	}

	def, err := parseListOpts(nil)
	if err != nil {
		t.Fatalf("parseListOpts(nil): %v", err)
	}
	if def.output != "table" {
		t.Errorf("output default = %q, want table", def.output)
	}

	long, err := parseListOpts([]string{"--output", "json"})
	if err != nil || long.output != "json" {
		t.Errorf("--output did not bind: %+v %v", long, err)
	}
}
