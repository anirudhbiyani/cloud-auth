package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Two checks that need nothing but the issuer URL: is the OIDC provider the trust names actually serving keys, and does this machine's clock agree with the internet.

// DefaultValidationHTTPClient is used by the discovery and clock-skew validators when no client is given. Tests point it at a fake or an offline transport. Plain stdlib so core stays a leaf package.
var DefaultValidationHTTPClient = &http.Client{Timeout: 10 * time.Second}

// DiscoveryURL is the OIDC discovery document for an issuer.
func DiscoveryURL(issuer string) string {
	return strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
}

// OIDCDiscoveryValidator fetches the issuer's discovery document and its JWKS: a trust that names an issuer nobody can fetch keys from fails every exchange, and nothing else in `validate` would notice.
type OIDCDiscoveryValidator struct {
	issuer string
	client *http.Client
}

// NewOIDCDiscoveryValidator checks the issuer recorded for a mechanism; an empty issuer (a SigV4-style trust) is reported as skipped, not failed.
func NewOIDCDiscoveryValidator(issuer string, client *http.Client) *OIDCDiscoveryValidator {
	if client == nil {
		client = DefaultValidationHTTPClient
	}
	return &OIDCDiscoveryValidator{issuer: issuer, client: client}
}

func (v *OIDCDiscoveryValidator) ID() string   { return "oidc_discovery" }
func (v *OIDCDiscoveryValidator) Name() string { return "OIDC provider configuration" }
func (v *OIDCDiscoveryValidator) Description() string {
	return "Fetches the issuer's .well-known/openid-configuration, confirms its issuer field matches the trust, and fetches the JWKS it points at."
}

// Validate implements Validator.
func (v *OIDCDiscoveryValidator) Validate(ctx context.Context, _ MechanismRef) ValidationCheck {
	check := NewCheck(v, SeverityError)
	start := time.Now()
	defer func() { check.Duration = time.Since(start) }()

	if v.issuer == "" {
		check.Status = CheckStatusSkipped
		check.Message = "this mechanism records no OIDC issuer (a SigV4 or non-OIDC trust), so there is no discovery document to check"
		return check
	}
	url := DiscoveryURL(v.issuer)
	check.Evidence["discovery_url"] = url

	var disc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := v.getJSON(ctx, url, &disc); err != nil {
		check.Status = CheckStatusFailed
		check.Message = fmt.Sprintf("discovery document unreachable: %v", err)
		check.Remediation = "Every target cloud fetches this URL to verify tokens. Confirm the issuer URL in the trust is exactly what the provider publishes (scheme, host, path, trailing slash) and that it is publicly reachable on port 443."
		return check
	}
	check.Evidence["issuer_field"] = disc.Issuer
	check.Evidence["jwks_uri"] = disc.JWKSURI

	// Targets compare iss byte-for-byte; a trailing slash is the classic mismatch, so it is called out rather than tolerated.
	if disc.Issuer != v.issuer {
		check.Status = CheckStatusFailed
		check.Message = fmt.Sprintf("discovery document says issuer %q but the trust names %q", disc.Issuer, v.issuer)
		check.Remediation = "Re-create the trust with the issuer exactly as the discovery document states it; tokens carry that value in `iss`, and the target compares it character for character."
		return check
	}
	if !strings.HasPrefix(disc.JWKSURI, "https://") {
		check.Status = CheckStatusFailed
		check.Message = fmt.Sprintf("jwks_uri %q is missing or not https", disc.JWKSURI)
		check.Remediation = "The identity provider must publish its signing keys over HTTPS; this is a provider-side problem."
		return check
	}

	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := v.getJSON(ctx, disc.JWKSURI, &jwks); err != nil {
		check.Status = CheckStatusFailed
		check.Message = fmt.Sprintf("JWKS unreachable: %v", err)
		check.Remediation = "The discovery document is fine but the key set is not; check the provider's status page, and that nothing on your network rewrites the jwks_uri host."
		return check
	}
	check.Evidence["key_count"] = len(jwks.Keys)
	if len(jwks.Keys) == 0 {
		check.Status = CheckStatusFailed
		check.Message = "the JWKS contains no keys; no token from this issuer can be verified"
		check.Remediation = "Wait for the provider to publish keys, or fix the jwks_uri if it points at the wrong document."
		return check
	}
	withoutKid := 0
	for _, k := range jwks.Keys {
		if k.Kid == "" {
			withoutKid++
		}
	}
	check.Status = CheckStatusPassed
	check.Message = fmt.Sprintf("issuer matches; %d signing key(s) published", len(jwks.Keys))
	if withoutKid > 0 {
		check.Evidence["keys_without_kid"] = withoutKid
		check.Message += fmt.Sprintf("; %d lack a kid, which some targets (Anthropic) require", withoutKid)
	}
	return check
}

func (v *OIDCDiscoveryValidator) getJSON(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("not JSON: %w", err)
	}
	return nil
}

// ClockSkewValidator compares the local clock with the Date header of a remote HTTPS response: tokens are time-bounded, and a skewed workload clock fails exchanges with errors that say nothing about time.
type ClockSkewValidator struct {
	url       string
	tolerance time.Duration
	client    *http.Client
	now       func() time.Time
}

// NewClockSkewValidator uses url as the remote time source (the issuer's discovery URL is the natural choice) and fails when the skew exceeds tolerance, which should be what the target accepts: 30s for Anthropic, about 5 minutes for the clouds.
func NewClockSkewValidator(url string, tolerance time.Duration, client *http.Client) *ClockSkewValidator {
	if client == nil {
		client = DefaultValidationHTTPClient
	}
	return &ClockSkewValidator{url: url, tolerance: tolerance, client: client, now: time.Now}
}

func (v *ClockSkewValidator) ID() string   { return "clock_skew" }
func (v *ClockSkewValidator) Name() string { return "Clock skew" }
func (v *ClockSkewValidator) Description() string {
	return "Compares the local clock with the Date header of a remote HTTPS response and fails when the difference exceeds what the target tolerates."
}

// Validate implements Validator.
func (v *ClockSkewValidator) Validate(ctx context.Context, _ MechanismRef) ValidationCheck {
	check := NewCheck(v, SeverityError)
	start := time.Now()
	defer func() { check.Duration = time.Since(start) }()

	if v.url == "" {
		check.Status = CheckStatusSkipped
		check.Message = "no remote time source: the mechanism records no issuer URL to ask"
		return check
	}
	check.Evidence["time_source"] = v.url
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, v.url, nil)
	if err != nil {
		check.Status = CheckStatusSkipped
		check.Message = err.Error()
		return check
	}
	sent := v.now()
	resp, err := v.client.Do(req)
	if err != nil {
		check.Status = CheckStatusSkipped
		check.Message = fmt.Sprintf("remote time source unreachable, skew not measured: %v", err)
		return check
	}
	_ = resp.Body.Close()
	received := v.now()
	remote, err := http.ParseTime(resp.Header.Get("Date"))
	if err != nil {
		check.Status = CheckStatusSkipped
		check.Message = "the remote answered without a usable Date header, so skew was not measured"
		return check
	}
	// The Date header has one-second resolution and was stamped mid-request; the midpoint of the request is the fairest local comparison.
	local := sent.Add(received.Sub(sent) / 2)
	skew := local.Sub(remote)
	if skew < 0 {
		skew = -skew
	}
	check.Evidence["skew_seconds"] = int(skew / time.Second)
	check.Evidence["tolerance_seconds"] = int(v.tolerance / time.Second)
	if skew > v.tolerance {
		check.Status = CheckStatusFailed
		check.Message = fmt.Sprintf("local clock is %s off the remote; the target tolerates %s", skew.Round(time.Second), v.tolerance)
		check.Remediation = "Sync the clock (chrony or systemd-timesyncd on Linux, the metadata time server on cloud VMs). Token exp/iat checks at the target will reject a skewed workload with an opaque authentication error."
		return check
	}
	check.Status = CheckStatusPassed
	check.Message = fmt.Sprintf("local clock within %s of the remote (tolerance %s)", skew.Round(time.Second), v.tolerance)
	return check
}
