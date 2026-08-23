package core

import (
	"strings"
	"testing"
)

// ParseCloud used to reject five of this package's own Cloud constants, because
// it conflated "a cloud we know" with "a cloud we can obtain credentials for".
// Those are different questions and now have different functions.
func TestParseCloudAcceptsEveryDeclaredCloud(t *testing.T) {
	for _, in := range []string{
		"aws", "gcp", "azure",
		"cloudflare", "vault", "okta", "github_oidc", "kubernetes",
		"AWS", "  Azure  ",
	} {
		if _, err := ParseCloud(in); err != nil {
			t.Errorf("ParseCloud(%q) = %v, want nil", in, err)
		}
	}
	for _, in := range []string{"", "amazon", "gcloud", "aws2"} {
		if got, err := ParseCloud(in); err == nil {
			t.Errorf("ParseCloud(%q) = %q, want an error", in, got)
		}
	}
}

// A trust peer is a real cloud but not somewhere a workload can get credentials.
// Saying that is more useful than calling it unknown.
func TestParseFederationTargetRejectsTrustPeers(t *testing.T) {
	for _, in := range []string{"aws", "gcp", "azure"} {
		if _, err := ParseFederationTarget(in); err != nil {
			t.Errorf("ParseFederationTarget(%q) = %v, want nil", in, err)
		}
	}
	for _, in := range []string{"cloudflare", "vault", "okta", "github_oidc", "kubernetes"} {
		_, err := ParseFederationTarget(in)
		if err == nil {
			t.Errorf("ParseFederationTarget(%q) should be refused", in)
			continue
		}
		if !strings.Contains(err.Error(), "trust peer") {
			t.Errorf("error for %q should explain why, got %v", in, err)
		}
	}
}
