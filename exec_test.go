package main

import (
	"reflect"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

func TestSplitExecArgs(t *testing.T) {
	flags, cmd, err := splitExecArgs([]string{"--to", "aws", "--role", "r", "--", "aws", "s3", "ls"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(flags, []string{"--to", "aws", "--role", "r"}) {
		t.Errorf("flags = %v", flags)
	}
	if !reflect.DeepEqual(cmd, []string{"aws", "s3", "ls"}) {
		t.Errorf("cmd = %v", cmd)
	}
}

func TestSplitExecArgsMissingSeparator(t *testing.T) {
	if _, _, err := splitExecArgs([]string{"--to", "aws", "aws", "s3"}); err == nil {
		t.Error("want error when '--' is missing")
	}
}

func TestSplitExecArgsNoCommand(t *testing.T) {
	if _, _, err := splitExecArgs([]string{"--to", "aws", "--"}); err == nil {
		t.Error("want error when no command follows '--'")
	}
}

func TestCredentialEnvAWS(t *testing.T) {
	c := &core.Credentials{Cloud: core.AWS, AccessKeyID: "AKIA", SecretAccessKey: "sk", SessionToken: "st"}
	got := credentialEnv(c)
	want := []string{
		"AWS_ACCESS_KEY_ID=AKIA",
		"AWS_SECRET_ACCESS_KEY=sk",
		"AWS_SESSION_TOKEN=st",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("credentialEnv = %v, want %v", got, want)
	}
}

func TestCredentialEnvBearer(t *testing.T) {
	c := &core.Credentials{Cloud: core.GCP, AccessToken: "tok"}
	got := credentialEnv(c)
	want := []string{"CLOUD_AUTH_ACCESS_TOKEN=tok"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("credentialEnv = %v, want %v", got, want)
	}
}

func TestExecEnvironAppendsAfterBase(t *testing.T) {
	base := []string{"PATH=/usr/bin", "HOME=/home/x"}
	c := &core.Credentials{Cloud: core.AWS, AccessKeyID: "AKIA", SecretAccessKey: "sk", SessionToken: "st"}
	got := execEnviron(base, c)
	if len(got) != 5 {
		t.Fatalf("want 5 env entries, got %d: %v", len(got), got)
	}
	// Base preserved, credentials appended last so they win.
	if got[0] != "PATH=/usr/bin" || got[1] != "HOME=/home/x" {
		t.Errorf("base env not preserved: %v", got)
	}
	if got[2] != "AWS_ACCESS_KEY_ID=AKIA" {
		t.Errorf("credentials not appended: %v", got)
	}
}
