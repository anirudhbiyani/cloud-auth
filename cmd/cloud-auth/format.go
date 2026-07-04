package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
)

// credentialProcessJSON emits the AWS credential_process contract so an
// existing AWS SDK config can invoke cloud-auth transparently.
func credentialProcessJSON(c *cloudauth.Credentials) ([]byte, error) {
	out := map[string]any{
		"Version":         1,
		"AccessKeyId":     c.AccessKeyID,
		"SecretAccessKey": c.SecretAccessKey,
		"SessionToken":    c.SessionToken,
	}
	if !c.Expiry.IsZero() {
		out["Expiration"] = c.Expiry.UTC().Format(time.RFC3339)
	}
	return json.Marshal(out)
}

// formatEnv renders shell export lines for the credentials.
func formatEnv(c *cloudauth.Credentials) string {
	var b strings.Builder
	switch c.Cloud {
	case cloudauth.AWS:
		fmt.Fprintf(&b, "export AWS_ACCESS_KEY_ID=%s\n", c.AccessKeyID)
		fmt.Fprintf(&b, "export AWS_SECRET_ACCESS_KEY=%s\n", c.SecretAccessKey)
		fmt.Fprintf(&b, "export AWS_SESSION_TOKEN=%s\n", c.SessionToken)
	default:
		// GCP/Azure bearer token: no universal env var, expose a generic one.
		fmt.Fprintf(&b, "export CLOUD_AUTH_ACCESS_TOKEN=%s\n", c.AccessToken)
	}
	return b.String()
}
