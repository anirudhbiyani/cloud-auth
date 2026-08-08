package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
)

func TestCredentialProcessJSON(t *testing.T) {
	exp := time.Date(2026, 7, 4, 13, 0, 0, 0, time.UTC)
	creds := &cloudauth.Credentials{
		Cloud: cloudauth.AWS, AccessKeyID: "AKIA", SecretAccessKey: "sk", SessionToken: "st", Expiry: exp,
	}
	out, err := credentialProcessJSON(creds)
	if err != nil {
		t.Fatalf("credentialProcessJSON: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if got["Version"] != float64(1) {
		t.Errorf("Version = %v, want 1", got["Version"])
	}
	if got["AccessKeyId"] != "AKIA" || got["SecretAccessKey"] != "sk" || got["SessionToken"] != "st" {
		t.Errorf("fields wrong: %v", got)
	}
	if got["Expiration"] != "2026-07-04T13:00:00Z" {
		t.Errorf("Expiration = %v, want RFC3339 UTC", got["Expiration"])
	}
}

func TestFormatEnvAWS(t *testing.T) {
	creds := &cloudauth.Credentials{Cloud: cloudauth.AWS, AccessKeyID: "AKIA", SecretAccessKey: "sk", SessionToken: "st"}
	out := formatEnv(creds)
	for _, want := range []string{
		"export AWS_ACCESS_KEY_ID=AKIA",
		"export AWS_SECRET_ACCESS_KEY=sk",
		"export AWS_SESSION_TOKEN=st",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("env output missing %q; got:\n%s", want, out)
		}
	}
}

func TestFormatEnvBearer(t *testing.T) {
	creds := &cloudauth.Credentials{Cloud: cloudauth.GCP, AccessToken: "tok"}
	out := formatEnv(creds)
	if !strings.Contains(out, "tok") {
		t.Errorf("bearer env missing token; got:\n%s", out)
	}
}
