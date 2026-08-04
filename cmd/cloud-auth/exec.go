package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/anirudhbiyani/cloud-auth/broker"
	"github.com/anirudhbiyani/cloud-auth/cloudauth"
)

// splitExecArgs splits an argv into the flags before "--" and the command
// (plus its args) after it. It returns an error if no "--" separator or no
// command is present.
func splitExecArgs(args []string) (flags []string, command []string, err error) {
	for i, a := range args {
		if a == "--" {
			flags = args[:i]
			command = args[i+1:]
			if len(command) == 0 {
				return nil, nil, errors.New("exec: no command after '--'")
			}
			return flags, command, nil
		}
	}
	return nil, nil, errors.New("exec: missing '--' separator before the command")
}

// credentialEnv returns the environment-variable assignments (KEY=VALUE) that
// inject the given credentials, consistent with formatEnv's variable choices.
// It returns AWS_* for AWS and the generic bearer variable otherwise.
func credentialEnv(c *cloudauth.Credentials) []string {
	switch c.Cloud {
	case cloudauth.AWS:
		return []string{
			"AWS_ACCESS_KEY_ID=" + c.AccessKeyID,
			"AWS_SECRET_ACCESS_KEY=" + c.SecretAccessKey,
			"AWS_SESSION_TOKEN=" + c.SessionToken,
		}
	default:
		return []string{"CLOUD_AUTH_ACCESS_TOKEN=" + c.AccessToken}
	}
}

// execEnviron composes the child process environment: the inherited base env
// with the credential variables appended (later entries win in os/exec).
func execEnviron(base []string, c *cloudauth.Credentials) []string {
	out := make([]string, 0, len(base)+3)
	out = append(out, base...)
	out = append(out, credentialEnv(c)...)
	return out
}

func cmdExec(ctx context.Context, args []string) error {
	flags, command, err := splitExecArgs(args)
	if err != nil {
		return err
	}

	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	getTarget := targetFlags(fs)
	fs.Parse(flags)

	target := getTarget()
	if target.Cloud == "" {
		return fmt.Errorf("--to is required")
	}
	if target.Audience == "" {
		return fmt.Errorf("--audience is required (pinned per target)")
	}

	creds, _, err := broker.New().Exchange(ctx, target)
	if err != nil {
		return err
	}

	// Running an operator-supplied command IS this subcommand's purpose — the
	// same contract as `env`, `aws-vault exec`, or `kubectl exec`. The argv comes
	// from this process's own command line after `--`, not from any remote or
	// untrusted source, and it is passed straight to execve: no shell is
	// interposed, so there is no metacharacter interpretation to inject through.
	// #nosec G204,G702 -- operator-supplied argv, executed without a shell
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Env = execEnviron(os.Environ(), creds)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		// Propagate the child's exit code.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("exec %s: %w", command[0], err)
	}
	return nil
}
