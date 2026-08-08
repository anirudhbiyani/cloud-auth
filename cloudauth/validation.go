package cloudauth

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Validator performs validation checks on mechanisms.
type Validator interface {
	// ID returns the unique identifier for this validator.
	ID() string

	// Name returns a human-readable name.
	Name() string

	// Description returns what this validator checks.
	Description() string

	// Validate performs the validation check.
	Validate(ctx context.Context, ref MechanismRef) ValidationCheck
}

// ValidatorRegistry holds registered validators.
type ValidatorRegistry struct {
	validators map[string]Validator
	byType     map[MechanismType][]string
}

// NewValidatorRegistry creates a new validator registry.
func NewValidatorRegistry() *ValidatorRegistry {
	return &ValidatorRegistry{
		validators: make(map[string]Validator),
		byType:     make(map[MechanismType][]string),
	}
}

// Register adds a validator to the registry.
func (r *ValidatorRegistry) Register(v Validator, types ...MechanismType) {
	r.validators[v.ID()] = v
	for _, t := range types {
		r.byType[t] = append(r.byType[t], v.ID())
	}
}

// Get retrieves a validator by ID.
func (r *ValidatorRegistry) Get(id string) (Validator, bool) {
	v, ok := r.validators[id]
	return v, ok
}

// GetForType returns validators applicable to a mechanism type.
func (r *ValidatorRegistry) GetForType(t MechanismType) []Validator {
	ids := r.byType[t]
	validators := make([]Validator, 0, len(ids))
	for _, id := range ids {
		if v, ok := r.validators[id]; ok {
			validators = append(validators, v)
		}
	}
	return validators
}

// DefaultValidators is the global validator registry.
var DefaultValidators = NewValidatorRegistry()

// Common validator implementations

// OIDCIssuerReachableValidator checks if an OIDC issuer is reachable.
type OIDCIssuerReachableValidator struct {
	issuerURL string
	client    *http.Client
}

// NewOIDCIssuerReachableValidator creates a new OIDC issuer validator.
func NewOIDCIssuerReachableValidator(issuerURL string) *OIDCIssuerReachableValidator {
	return &OIDCIssuerReachableValidator{
		issuerURL: issuerURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (v *OIDCIssuerReachableValidator) ID() string {
	return "oidc_issuer_reachable"
}

func (v *OIDCIssuerReachableValidator) Name() string {
	return "OIDC Issuer Reachable"
}

func (v *OIDCIssuerReachableValidator) Description() string {
	return "Checks if the OIDC issuer endpoint is reachable and returns valid metadata"
}

func (v *OIDCIssuerReachableValidator) Validate(ctx context.Context, ref MechanismRef) ValidationCheck {
	start := time.Now()
	check := ValidationCheck{
		ID:          v.ID(),
		Name:        v.Name(),
		Description: v.Description(),
		Severity:    SeverityError,
		Evidence:    make(map[string]interface{}),
	}

	wellKnownURL := v.issuerURL + "/.well-known/openid-configuration"
	check.Evidence["url"] = wellKnownURL

	req, err := http.NewRequestWithContext(ctx, "GET", wellKnownURL, nil)
	if err != nil {
		check.Status = CheckStatusFailed
		check.Evidence["error"] = err.Error()
		check.Remediation = "Check the OIDC issuer URL format"
		check.Duration = time.Since(start)
		return check
	}

	resp, err := v.client.Do(req)
	if err != nil {
		check.Status = CheckStatusFailed
		check.Evidence["error"] = err.Error()
		check.Remediation = "Ensure the OIDC issuer is accessible from this network"
		check.Duration = time.Since(start)
		return check
	}
	defer resp.Body.Close()

	check.Evidence["status_code"] = resp.StatusCode

	if resp.StatusCode != http.StatusOK {
		check.Status = CheckStatusFailed
		check.Remediation = fmt.Sprintf("OIDC issuer returned status %d, expected 200", resp.StatusCode)
		check.Duration = time.Since(start)
		return check
	}

	check.Status = CheckStatusPassed
	check.Duration = time.Since(start)
	return check
}

// TrustPolicyMatchValidator checks if a trust policy matches expected values.
type TrustPolicyMatchValidator struct {
	expectedIssuer   string
	expectedAudience string
	expectedSubject  string
}

// NewTrustPolicyMatchValidator creates a new trust policy validator.
func NewTrustPolicyMatchValidator(issuer, audience, subject string) *TrustPolicyMatchValidator {
	return &TrustPolicyMatchValidator{
		expectedIssuer:   issuer,
		expectedAudience: audience,
		expectedSubject:  subject,
	}
}

func (v *TrustPolicyMatchValidator) ID() string {
	return "trust_policy_match"
}

func (v *TrustPolicyMatchValidator) Name() string {
	return "Trust Policy Match"
}

func (v *TrustPolicyMatchValidator) Description() string {
	return "Checks if the trust policy matches expected issuer, audience, and subject"
}

func (v *TrustPolicyMatchValidator) Validate(ctx context.Context, ref MechanismRef) ValidationCheck {
	start := time.Now()
	check := ValidationCheck{
		ID:          v.ID(),
		Name:        v.Name(),
		Description: v.Description(),
		Severity:    SeverityError,
		Evidence:    make(map[string]interface{}),
	}

	// NOT IMPLEMENTED: fetching and diffing the live trust policy needs a
	// provider-specific API call. Reported as Skipped (never Passed) so the
	// report cannot imply the policy was checked — ValidationReport.IsComplete
	// surfaces this to callers.
	check.Evidence["expected_issuer"] = v.expectedIssuer
	check.Evidence["expected_audience"] = v.expectedAudience
	check.Evidence["expected_subject"] = v.expectedSubject

	check.Status = CheckStatusSkipped
	check.Message = "trust policy was NOT verified"
	check.Remediation = "Not yet automated. Manually confirm the target trust policy pins " +
		"issuer, audience and subject to the values in Evidence — an unpinned trust is a " +
		"confused-deputy risk."
	check.Duration = time.Since(start)
	return check
}

// PermissionsValidator checks if required permissions are present.
type PermissionsValidator struct {
	requiredPermissions []string
}

// NewPermissionsValidator creates a new permissions validator.
func NewPermissionsValidator(permissions []string) *PermissionsValidator {
	return &PermissionsValidator{
		requiredPermissions: permissions,
	}
}

func (v *PermissionsValidator) ID() string {
	return "permissions_check"
}

func (v *PermissionsValidator) Name() string {
	return "Permissions Check"
}

func (v *PermissionsValidator) Description() string {
	return "Checks if required permissions are present on the identity"
}

func (v *PermissionsValidator) Validate(ctx context.Context, ref MechanismRef) ValidationCheck {
	start := time.Now()
	check := ValidationCheck{
		ID:          v.ID(),
		Name:        v.Name(),
		Description: v.Description(),
		Severity:    SeverityError,
		Evidence:    make(map[string]interface{}),
	}

	// NOT IMPLEMENTED: needs a provider-specific policy-simulation call.
	// Skipped, never Passed — see TrustPolicyMatchValidator for the rationale.
	check.Evidence["required_permissions"] = v.requiredPermissions

	check.Status = CheckStatusSkipped
	check.Message = "permissions were NOT verified"
	check.Remediation = "Not yet automated. Manually confirm the target identity grants " +
		"the permissions listed in Evidence, and no more."
	check.Duration = time.Since(start)
	return check
}

// RemoteTimeFunc returns the current time according to an external authority.
// The usual implementation reads the Date header of an HTTPS response from the
// identity provider — the peer whose token expiry actually matters.
type RemoteTimeFunc func(ctx context.Context) (time.Time, error)

// ClockSkewValidator compares the local clock against a remote time source.
//
// Clock skew is a real federation failure mode: if the local clock drifts, a
// minted token's nbf/exp is evaluated against a different "now" at the target
// STS and the exchange is refused for reasons that look nothing like a clock
// problem. Comparing against a remote authority is the only way to detect it —
// reading the local clock alone proves nothing, so without a time source this
// check reports Skipped rather than a meaningless pass.
type ClockSkewValidator struct {
	maxSkew    time.Duration
	now        func() time.Time
	remoteTime RemoteTimeFunc
}

// ClockSkewOption configures a ClockSkewValidator.
type ClockSkewOption func(*ClockSkewValidator)

// WithRemoteTime supplies the external time authority to compare against.
// Without it the check cannot run and reports Skipped.
func WithRemoteTime(f RemoteTimeFunc) ClockSkewOption {
	return func(v *ClockSkewValidator) { v.remoteTime = f }
}

// WithClockSkewNow overrides the local clock (for tests).
func WithClockSkewNow(f func() time.Time) ClockSkewOption {
	return func(v *ClockSkewValidator) { v.now = f }
}

// NewClockSkewValidator creates a new clock skew validator.
func NewClockSkewValidator(maxSkew time.Duration, opts ...ClockSkewOption) *ClockSkewValidator {
	v := &ClockSkewValidator{maxSkew: maxSkew, now: time.Now}
	for _, o := range opts {
		o(v)
	}
	return v
}

// RemoteTimeFromHTTP builds a RemoteTimeFunc that reads the Date header of a
// HEAD request to url — a dependency-free way to learn a peer's clock.
func RemoteTimeFromHTTP(client *http.Client, url string) RemoteTimeFunc {
	return func(ctx context.Context) (time.Time, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
		if err != nil {
			return time.Time{}, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return time.Time{}, err
		}
		defer func() { _ = resp.Body.Close() }()
		raw := resp.Header.Get("Date")
		if raw == "" {
			return time.Time{}, fmt.Errorf("no Date header from %s", url)
		}
		return http.ParseTime(raw)
	}
}

func (v *ClockSkewValidator) ID() string {
	return "clock_skew"
}

func (v *ClockSkewValidator) Name() string {
	return "Clock Skew Check"
}

func (v *ClockSkewValidator) Description() string {
	return "Checks if system clock is within acceptable range"
}

func (v *ClockSkewValidator) Validate(ctx context.Context, ref MechanismRef) ValidationCheck {
	start := time.Now()
	check := ValidationCheck{
		ID:          v.ID(),
		Name:        v.Name(),
		Description: v.Description(),
		Severity:    SeverityWarning,
		Evidence:    make(map[string]interface{}),
	}

	now := v.now()
	check.Evidence["local_time"] = now.Format(time.RFC3339)
	check.Evidence["max_skew"] = v.maxSkew.String()

	// No authority to compare against means we cannot detect drift. Say so,
	// rather than reporting a pass that verified nothing.
	if v.remoteTime == nil {
		check.Status = CheckStatusSkipped
		check.Remediation = "Configure a remote time source (see WithRemoteTime / RemoteTimeFromHTTP) " +
			"to detect clock drift; the local clock alone cannot reveal skew."
		check.Duration = time.Since(start)
		return check
	}

	remote, err := v.remoteTime(ctx)
	if err != nil {
		check.Status = CheckStatusFailed
		check.Message = fmt.Sprintf("could not read remote time: %v", err)
		check.Remediation = "Verify the time source is reachable from this host."
		check.Duration = time.Since(start)
		return check
	}

	// Absolute: drift in either direction breaks nbf/exp evaluation.
	skew := now.Sub(remote)
	if skew < 0 {
		skew = -skew
	}
	check.Evidence["remote_time"] = remote.Format(time.RFC3339)
	check.Evidence["observed_skew"] = skew.String()

	if skew > v.maxSkew {
		check.Status = CheckStatusFailed
		check.Message = fmt.Sprintf("clock skew %s exceeds the %s tolerance", skew, v.maxSkew)
		check.Remediation = "Sync this host's clock (NTP/chrony); token nbf/exp will be " +
			"evaluated against the peer's clock and may be rejected."
	} else {
		check.Status = CheckStatusPassed
	}
	check.Duration = time.Since(start)
	return check
}

// TokenAcquisitionValidator attempts actual token acquisition.
type TokenAcquisitionValidator struct {
	tokenProvider TokenProvider
	request       TokenRequest
}

// NewTokenAcquisitionValidator creates a new token acquisition validator.
func NewTokenAcquisitionValidator(tp TokenProvider, req TokenRequest) *TokenAcquisitionValidator {
	return &TokenAcquisitionValidator{
		tokenProvider: tp,
		request:       req,
	}
}

func (v *TokenAcquisitionValidator) ID() string {
	return "token_acquisition"
}

func (v *TokenAcquisitionValidator) Name() string {
	return "Token Acquisition Test"
}

func (v *TokenAcquisitionValidator) Description() string {
	return "Attempts to acquire a token using the configured mechanism"
}

func (v *TokenAcquisitionValidator) Validate(ctx context.Context, ref MechanismRef) ValidationCheck {
	start := time.Now()
	check := ValidationCheck{
		ID:          v.ID(),
		Name:        v.Name(),
		Description: v.Description(),
		Severity:    SeverityCritical,
		Evidence:    make(map[string]interface{}),
	}

	resp, err := v.tokenProvider.Token(ctx, v.request)
	if err != nil {
		check.Status = CheckStatusFailed
		check.Evidence["error"] = err.Error()
		check.Remediation = "Check trust relationship configuration and permissions"
		check.Duration = time.Since(start)
		return check
	}

	check.Status = CheckStatusPassed
	check.Evidence["token_type"] = resp.TokenType
	check.Evidence["expires_at"] = resp.ExpiresAt
	check.Evidence["scopes"] = resp.Scopes
	// Don't include the actual token!
	check.Duration = time.Since(start)
	return check
}

// RunValidation executes a set of validators and returns a report.
func RunValidation(ctx context.Context, ref MechanismRef, validators []Validator) *ValidationReport {
	report := &ValidationReport{
		Ref:         ref,
		Checks:      make([]ValidationCheck, 0, len(validators)),
		ValidatedAt: time.Now(),
	}

	for _, v := range validators {
		check := v.Validate(ctx, ref)
		report.Checks = append(report.Checks, check)

		switch check.Status {
		case CheckStatusPassed:
			report.Summary.PassedChecks++
		case CheckStatusFailed:
			report.Summary.FailedChecks++
		case CheckStatusSkipped:
			report.Summary.SkippedChecks++
		}
		report.Summary.TotalChecks++
	}

	report.Summary.IsValid = report.IsValid()
	return report
}

// StandardValidatorsFor returns standard validators for a mechanism type.
func StandardValidatorsFor(t MechanismType) []Validator {
	return DefaultValidators.GetForType(t)
}
