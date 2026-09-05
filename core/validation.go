package core

import (
	"context"
	"fmt"
	"strings"
	"sync"
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
	mu         sync.RWMutex
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

// Register adds a validator to the registry, returning an error if the ID is already taken.
func (r *ValidatorRegistry) Register(v Validator, types ...MechanismType) error {
	if v == nil {
		return fmt.Errorf("cloud-auth: cannot register a nil validator")
	}
	id := v.ID()
	if id == "" {
		return fmt.Errorf("cloud-auth: validator has no ID")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.validators[id]; exists {
		return fmt.Errorf("cloud-auth: validator already registered: %s", id)
	}
	r.validators[id] = v
	for _, t := range types {
		r.byType[t] = append(r.byType[t], id)
	}
	return nil
}

// Get retrieves a validator by ID.
func (r *ValidatorRegistry) Get(id string) (Validator, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	v, ok := r.validators[id]
	return v, ok
}

// GetForType returns validators applicable to a mechanism type.
func (r *ValidatorRegistry) GetForType(t MechanismType) []Validator {
	r.mu.RLock()
	defer r.mu.RUnlock()

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

// TrustCondition is one condition a trust policy places on a claim, with the operator that evaluates it.
type TrustCondition struct {
	// Operator is the provider's condition operator, verbatim: "StringEquals", "StringLike", "ForAllValues:StringEquals", and so on.
	Operator string
	// Claim is the normalized claim name: "sub", "aud", or "oaud".
	Claim string
	// Value is the pattern or literal the operator compares against.
	Value string
}

// IsPattern reports whether Value contains wildcard characters.
func (c TrustCondition) IsPattern() bool {
	return strings.ContainsAny(c.Value, "*?")
}

// HonoursWildcards reports whether Operator actually expands a wildcard.
func (c TrustCondition) HonoursWildcards() bool {
	op := c.Operator
	if i := strings.LastIndex(op, ":"); i >= 0 {
		op = op[i+1:] // strip a ForAllValues:/ForAnyValue: qualifier
	}
	return strings.HasSuffix(op, "Like") || strings.HasSuffix(op, "LikeIfExists")
}

// TrustPolicy is the live, provider-neutral trust configuration of a mechanism: who is trusted to assume it, for which audience, and scoped to which subjects.
type TrustPolicy struct {
	// Issuer is the trusted OIDC issuer (or federated principal).
	Issuer string
	// Audiences are the accepted `aud` values.
	Audiences []string
	// Subjects are the accepted `sub` values or patterns.
	Subjects []string
	// Conditions retains every condition with its operator.
	Conditions []TrustCondition
	// Raw is the provider's original policy document, for evidence.
	Raw string
}

// SubjectConditions returns the conditions constraining the `sub` claim.
func (p *TrustPolicy) SubjectConditions() []TrustCondition {
	return p.conditionsFor("sub")
}

// AudienceConditions returns the conditions constraining `aud` or `oaud`.
func (p *TrustPolicy) AudienceConditions() []TrustCondition {
	return append(p.conditionsFor("aud"), p.conditionsFor("oaud")...)
}

func (p *TrustPolicy) conditionsFor(claim string) []TrustCondition {
	if p == nil {
		return nil
	}
	var out []TrustCondition
	for _, c := range p.Conditions {
		if c.Claim == claim {
			out = append(out, c)
		}
	}
	return out
}

// TrustPolicySource supplies the live trust policy for a mechanism.
type TrustPolicySource interface {
	TrustPolicy(ctx context.Context, ref MechanismRef) (*TrustPolicy, error)
}

// TrustPolicyMatchValidator checks the live trust policy against expectations.
type TrustPolicyMatchValidator struct {
	expectedIssuer   string
	expectedAudience string
	expectedSubject  string
	source           TrustPolicySource
}

// TrustPolicyOption configures a TrustPolicyMatchValidator.
type TrustPolicyOption func(*TrustPolicyMatchValidator)

// WithTrustPolicySource supplies the live policy to compare against.
func WithTrustPolicySource(s TrustPolicySource) TrustPolicyOption {
	return func(v *TrustPolicyMatchValidator) { v.source = s }
}

// NewTrustPolicyMatchValidator creates a new trust policy validator.
func NewTrustPolicyMatchValidator(issuer, audience, subject string, opts ...TrustPolicyOption) *TrustPolicyMatchValidator {
	v := &TrustPolicyMatchValidator{
		expectedIssuer:   issuer,
		expectedAudience: audience,
		expectedSubject:  subject,
	}
	for _, o := range opts {
		o(v)
	}
	return v
}

// wildcardMatch reports whether s matches an IAM StringLike pattern, in which `*` matches any run of characters and `?` any single one.
func wildcardMatch(pattern, s string) bool {
	if pattern == s {
		return true
	}
	if !strings.ContainsAny(pattern, "*?") {
		return false
	}

	var (
		p, v       int // current positions in pattern and value
		star       = -1
		vAfterStar int
	)
	for v < len(s) {
		switch {
		// The star case must come FIRST.
		case p < len(pattern) && pattern[p] == '*':
			// Remember this star and try matching zero characters first.
			star, vAfterStar = p, v
			p++
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[v]):
			p++
			v++
		case star >= 0:
			// The tail failed; let the remembered star consume one more character.
			p = star + 1
			vAfterStar++
			v = vAfterStar
		default:
			return false
		}
	}
	// Trailing stars may match the empty remainder.
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// caseOnlyHint returns a diagnostic fragment when two values differ ONLY in case.
func caseOnlyHint(actual, expected string) string {
	if actual != expected && strings.EqualFold(actual, expected) {
		return " (differs ONLY in case — Azure and OIDC subject matching are case-sensitive)"
	}
	return ""
}

// isUnscoped reports whether a subject pattern admits essentially anything.
func isUnscoped(pattern string) bool {
	trimmed := strings.TrimSpace(pattern)
	switch trimmed {
	case "", "*", "**", "?*", "*:*":
		return true
	}
	// A pattern whose every segment is a wildcard pins nothing either: "*:*:*" and "repo:*" differ, and only the first is unscoped.
	segments := strings.Split(trimmed, ":")
	for _, seg := range segments {
		if strings.Trim(seg, "*?") != "" {
			return false
		}
	}
	return len(segments) > 0
}

// unexpectedGrants reports audiences and subjects the live policy admits that the recorded intent never asked for.
func (v *TrustPolicyMatchValidator) unexpectedGrants(live *TrustPolicy) []string {
	var problems []string

	if v.expectedAudience != "" {
		for _, a := range live.Audiences {
			if a != v.expectedAudience {
				problems = append(problems, fmt.Sprintf(
					"policy also accepts audience %q, which this mechanism never configured "+
						"(the trust has been widened since setup)", a))
			}
		}
	}

	if v.expectedSubject != "" {
		for _, s := range live.Subjects {
			// A live subject is expected if it is the configured one, if the configured pattern covers it, or if it is a pattern that covers the configured subject — the last case being an operator who authored a wildcard while setup recorded a concrete example of it.
			if s == v.expectedSubject ||
				wildcardMatch(v.expectedSubject, s) ||
				wildcardMatch(s, v.expectedSubject) {
				continue
			}
			problems = append(problems, fmt.Sprintf(
				"policy also admits subject %q, which this mechanism never configured "+
					"(the trust has been widened since setup)", s))
		}
	}

	return problems
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
	check := NewCheck(v, SeverityError)

	check.Evidence["expected_issuer"] = v.expectedIssuer
	check.Evidence["expected_audience"] = v.expectedAudience
	check.Evidence["expected_subject"] = v.expectedSubject

	// No source means no live policy to compare against. Skipped, never Passed.
	if v.source == nil {
		check.Status = CheckStatusSkipped
		check.Message = "trust policy was NOT verified"
		check.Remediation = "This provider does not supply a TrustPolicySource. Manually confirm " +
			"the target trust policy pins issuer, audience and subject to the values in Evidence — " +
			"an unpinned trust is a confused-deputy risk."
		check.Duration = time.Since(start)
		return check
	}

	live, err := v.source.TrustPolicy(ctx, ref)
	if err != nil {
		check.Status = CheckStatusFailed
		check.Message = fmt.Sprintf("could not read the live trust policy: %v", err)
		check.Remediation = "Ensure the caller can read the target identity's trust policy."
		check.Duration = time.Since(start)
		return check
	}
	if live == nil {
		check.Status = CheckStatusFailed
		check.Message = "no trust policy found on the target identity"
		check.Remediation = "The mechanism may have been deleted or was never created."
		check.Duration = time.Since(start)
		return check
	}

	check.Evidence["actual_issuer"] = live.Issuer
	check.Evidence["actual_audiences"] = live.Audiences
	check.Evidence["actual_subjects"] = live.Subjects
	if live.Raw != "" {
		check.Evidence["raw_policy"] = live.Raw
	}

	var problems []string

	// Issuer: exact.
	if v.expectedIssuer != "" && live.Issuer != v.expectedIssuer {
		problems = append(problems, fmt.Sprintf(
			"issuer mismatch%s: policy trusts %q, expected %q",
			caseOnlyHint(live.Issuer, v.expectedIssuer), live.Issuer, v.expectedIssuer))
	}

	// Audience: exact membership.
	if v.expectedAudience != "" {
		found := false
		for _, a := range live.Audiences {
			if a == v.expectedAudience {
				found = true
				break
			}
		}
		if !found {
			hint := ""
			for _, a := range live.Audiences {
				if h := caseOnlyHint(a, v.expectedAudience); h != "" {
					hint = h
					break
				}
			}
			problems = append(problems, fmt.Sprintf(
				"audience %q is not accepted%s (policy accepts %v)",
				v.expectedAudience, hint, live.Audiences))
		}
	}

	// Absence is the loudest finding, and the one a membership test cannot see.
	if len(live.Subjects) == 0 {
		problems = append(problems, "trust has NO subject condition: every workload this issuer "+
			"mints a token for can assume the target identity (confused-deputy risk)")
	}

	// An unscoped pattern is a finding in its own right, even though it would "match" — it admits every workload from the issuer.
	for _, s := range live.Subjects {
		if isUnscoped(s) {
			problems = append(problems, fmt.Sprintf(
				"trust is unscoped: subject pattern %q admits any workload from this issuer "+
					"(confused-deputy risk)", s))
		}
	}
	if v.expectedSubject != "" && len(problems) == 0 {
		admitted := false
		for _, s := range live.Subjects {
			if wildcardMatch(s, v.expectedSubject) {
				admitted = true
				break
			}
		}
		if !admitted {
			hint := ""
			for _, s := range live.Subjects {
				if h := caseOnlyHint(s, v.expectedSubject); h != "" {
					hint = h
					break
				}
			}
			problems = append(problems, fmt.Sprintf(
				"subject %q is not admitted by the policy%s (policy allows %v)",
				v.expectedSubject, hint, live.Subjects))
		}
	}

	// Everything above asks "is what we expected still there?".
	problems = append(problems, v.unexpectedGrants(live)...)

	if len(problems) > 0 {
		check.Status = CheckStatusFailed
		check.Message = strings.Join(problems, "; ")
		check.Remediation = "Update the target trust policy so it pins the expected issuer, " +
			"audience and subject, then re-run validate."
	} else {
		check.Status = CheckStatusPassed
		check.Message = "trust policy pins the expected issuer, audience and subject"
	}
	check.Duration = time.Since(start)
	return check
}

// GrantedPolicySource lists the policies actually attached to a mechanism's target identity.
type GrantedPolicySource interface {
	GrantedPolicies(ctx context.Context, ref MechanismRef) ([]string, error)
}

// PermissionsValidator checks that the expected policies are actually attached.
type PermissionsValidator struct {
	requiredPermissions []string
	source              GrantedPolicySource
}

// PermissionsOption configures a PermissionsValidator.
type PermissionsOption func(*PermissionsValidator)

// WithGrantedPolicySource supplies the live attachment list to compare against.
func WithGrantedPolicySource(s GrantedPolicySource) PermissionsOption {
	return func(v *PermissionsValidator) { v.source = s }
}

// NewPermissionsValidator creates a new permissions validator.
func NewPermissionsValidator(permissions []string, opts ...PermissionsOption) *PermissionsValidator {
	v := &PermissionsValidator{requiredPermissions: permissions}
	for _, o := range opts {
		o(v)
	}
	return v
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
	check := NewCheck(v, SeverityError)

	check.Evidence["required_permissions"] = v.requiredPermissions

	if v.source == nil {
		check.Status = CheckStatusSkipped
		check.Message = "permissions were NOT verified"
		check.Remediation = "This provider does not supply a GrantedPolicySource. Manually confirm " +
			"the target identity grants the permissions listed in Evidence, and no more."
		check.Duration = time.Since(start)
		return check
	}

	granted, err := v.source.GrantedPolicies(ctx, ref)
	if err != nil {
		check.Status = CheckStatusFailed
		check.Message = fmt.Sprintf("could not list attached policies: %v", err)
		check.Remediation = "Ensure the caller can list the target identity's policies."
		check.Duration = time.Since(start)
		return check
	}
	check.Evidence["granted_policies"] = granted

	have := make(map[string]struct{}, len(granted))
	for _, g := range granted {
		have[g] = struct{}{}
	}
	var missing []string
	for _, want := range v.requiredPermissions {
		if _, ok := have[want]; !ok {
			missing = append(missing, want)
		}
	}

	if len(missing) > 0 {
		check.Evidence["missing_policies"] = missing
		check.Status = CheckStatusFailed
		check.Message = fmt.Sprintf("%d expected policy/policies not attached: %s",
			len(missing), strings.Join(missing, ", "))
		check.Remediation = "Attach the missing policies to the target identity, or update the " +
			"spec if they are no longer required."
	} else {
		check.Status = CheckStatusPassed
		check.Message = fmt.Sprintf("all %d expected policy/policies are attached", len(v.requiredPermissions))
	}
	check.Duration = time.Since(start)
	return check
}

// NewCheck starts a check carrying the validator's own identity, which every implementation was otherwise copying field by field.
func NewCheck(v Validator, sev Severity) ValidationCheck {
	return ValidationCheck{
		ID:          v.ID(),
		Name:        v.Name(),
		Description: v.Description(),
		Severity:    sev,
		Evidence:    map[string]any{},
	}
}

// RunValidation executes a set of validators and returns a report.
func RunValidation(ctx context.Context, ref MechanismRef, validators []Validator) *ValidationReport {
	report := &ValidationReport{
		Ref:         ref,
		Checks:      make([]ValidationCheck, 0, len(validators)),
		ValidatedAt: time.Now(),
	}

	for _, v := range validators {
		// Stop when the caller has given up.
		if err := ctx.Err(); err != nil {
			report.Checks = append(report.Checks, ValidationCheck{
				ID:          v.ID(),
				Name:        v.Name(),
				Description: v.Description(),
				Status:      CheckStatusSkipped,
				Severity:    SeverityError,
				Message:     fmt.Sprintf("not run: %v", err),
				Remediation: "Re-run validation with a longer timeout.",
			})
			report.Summary.SkippedChecks++
			report.Summary.TotalChecks++
			continue
		}

		check := v.Validate(ctx, ref)
		report.Checks = append(report.Checks, check)

		switch check.Status {
		case CheckStatusPassed:
			report.Summary.PassedChecks++
		case CheckStatusFailed:
			report.Summary.FailedChecks++
		case CheckStatusSkipped, CheckStatusUnknown:
			report.Summary.SkippedChecks++
		}
		report.Summary.TotalChecks++
	}

	report.Summary.IsValid = report.IsValid()
	return report
}
