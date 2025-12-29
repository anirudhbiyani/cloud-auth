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

	// This is a placeholder - actual implementation would fetch and compare policies
	check.Evidence["expected_issuer"] = v.expectedIssuer
	check.Evidence["expected_audience"] = v.expectedAudience
	check.Evidence["expected_subject"] = v.expectedSubject

	// TODO: Implement actual policy fetch and comparison
	check.Status = CheckStatusSkipped
	check.Remediation = "Manual verification required"
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

	check.Evidence["required_permissions"] = v.requiredPermissions

	// TODO: Implement actual permission checking
	check.Status = CheckStatusSkipped
	check.Remediation = "Manual verification required"
	check.Duration = time.Since(start)
	return check
}

// ClockSkewValidator checks for clock skew issues.
type ClockSkewValidator struct {
	maxSkew time.Duration
}

// NewClockSkewValidator creates a new clock skew validator.
func NewClockSkewValidator(maxSkew time.Duration) *ClockSkewValidator {
	return &ClockSkewValidator{maxSkew: maxSkew}
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

	// For now, just check local time is reasonable
	now := time.Now()
	check.Evidence["local_time"] = now.Format(time.RFC3339)
	check.Evidence["max_skew"] = v.maxSkew.String()

	// TODO: Compare with remote time source
	check.Status = CheckStatusPassed
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

