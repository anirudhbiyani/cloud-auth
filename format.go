package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// credentialProcessJSON emits the AWS credential_process contract so an existing AWS SDK config can invoke cloud-auth transparently.
func credentialProcessJSON(c *core.Credentials) ([]byte, error) {
	// This contract exists to hand plaintext credentials to an AWS SDK, so Reveal is the point rather than a leak.
	plain := c.Reveal()
	out := map[string]any{
		"Version":         1,
		"AccessKeyId":     plain.AccessKeyID,
		"SecretAccessKey": plain.SecretAccessKey,
		"SessionToken":    plain.SessionToken,
	}
	if !c.Expiry.IsZero() {
		out["Expiration"] = c.Expiry.UTC().Format(time.RFC3339)
	}
	return json.Marshal(out)
}

// formatEnv renders shell export lines for the credentials.
func formatEnv(c *core.Credentials) string {
	plain := c.Reveal()
	var b strings.Builder
	switch c.Cloud {
	case core.AWS:
		fmt.Fprintf(&b, "export AWS_ACCESS_KEY_ID=%s\n", plain.AccessKeyID)
		fmt.Fprintf(&b, "export AWS_SECRET_ACCESS_KEY=%s\n", plain.SecretAccessKey)
		fmt.Fprintf(&b, "export AWS_SESSION_TOKEN=%s\n", plain.SessionToken)
	default:
		// GCP/Azure bearer token: no universal env var, expose a generic one.
		fmt.Fprintf(&b, "export CLOUD_AUTH_ACCESS_TOKEN=%s\n", plain.AccessToken)
	}
	return b.String()
}
