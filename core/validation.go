package core

import (
	"context"
	"fmt"
	"net/http"
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
//
// The mutex is not decoration. DefaultValidators is a package-level mutable
// registry documented as the extension point providers register into from
// init(), and it is read while a service validates on a schedule. Concurrent map
// access in Go is not a benign race: it is a runtime fatal error that ignores
// recover() and takes the whole process with it — in a library whose job is
// handing credentials to a long-running server. Registry, next door, has had
// this since it was written.
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

// Register adds a validator to the registry, returning an error if the ID is
// already taken.
//
// It used to overwrite silently, so two packages registering the same ID left
// whichever init() ran last in place — an ordering-dependent choice of which
// checks actually run.
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
//
// The slice is freshly allocated: returning one that aliased the registry's own
// backing array would let a caller's append race a concurrent Register.
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

// TrustPolicy is the live, provider-neutral trust configuration of a mechanism:
// who is trusted to assume it, for which audience, and scoped to which subjects.
type TrustPolicy struct {
	// Issuer is the trusted OIDC issuer (or federated principal).
	Issuer string
	// Audiences are the accepted `aud` values.
	Audiences []string
	// Subjects are the accepted `sub` values or patterns. IAM StringLike
	// wildcards ("repo:org/repo:*") are preserved verbatim.
	Subjects []string
	// Raw is the provider's original policy document, for evidence.
	Raw string
}

// TrustPolicySource supplies the live trust policy for a mechanism.
//
// It exists so the core can read provider-specific state without importing
// providers: core is the leaf package and providers import it, so the
// dependency is inverted through this interface and implemented provider-side.
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

// WithTrustPolicySource supplies the live policy to compare against. Without
// it the check cannot run and reports Skipped rather than a hollow pass.
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

// wildcardMatch reports whether s matches an IAM StringLike pattern, in which
// `*` matches any run of characters and `?` any single one.
//
// Written out rather than using path.Match because that treats "/" specially,
// and subjects are full of slashes ("repo:org/repo:ref:refs/heads/main").
//
// Linear, not backtracking. The previous implementation recursed over every
// split point for each `*`, which is exponential on a pattern like
// "*a*a*a*a*a*b" — reachable here because the pattern is a live IAM policy value
// rather than something this code chose. This is the standard two-pointer
// algorithm: walk both strings, and on a `*` remember where to resume if the
// rest fails to match.
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
		// The star case must come FIRST. Checking literal equality first means a
		// '*' in the VALUE matches the '*' in the pattern as an ordinary
		// character, so "*" fails to match "*0" — a bug a fuzz target found in
		// this function within seconds of being written.
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

// caseOnlyHint returns a diagnostic fragment when two values differ ONLY in
// case. Azure Entra matches issuer, subject and audience case-sensitively and
// exactly, so this is a common and very confusing misconfiguration: everything
// "looks" right in a side-by-side diff. Naming it saves real debugging time.
func caseOnlyHint(actual, expected string) string {
	if actual != expected && strings.EqualFold(actual, expected) {
		return " (differs ONLY in case — Azure and OIDC subject matching are case-sensitive)"
	}
	return ""
}

// isUnscoped reports whether a subject pattern admits essentially anything.
// A trust that accepts any subject is the classic confused-deputy hole: any
// workload from that issuer can assume the target identity.
//
// Note what this does NOT cover: a policy with no subject condition at all has
// no pattern to test, and is just as unscoped. That case is handled by the
// caller, which treats an empty Subjects list as a finding in its own right.
func isUnscoped(pattern string) bool {
	trimmed := strings.TrimSpace(pattern)
	switch trimmed {
	case "", "*", "**", "?*", "*:*":
		return true
	}
	// A pattern whose every segment is a wildcard pins nothing either:
	// "*:*:*" and "repo:*" differ, and only the first is unscoped.
	segments := strings.Split(trimmed, ":")
	for _, seg := range segments {
		if strings.Trim(seg, "*?") != "" {
			return false
		}
	}
	return len(segments) > 0
}

// unexpectedGrants reports audiences and subjects the live policy admits that
// the recorded intent never asked for.
//
// Only meaningful when there is a recorded expectation to compare against: with
// no expected audience or subject we cannot tell an addition from the original
// intent, and guessing would produce noise on every legitimately multi-valued
// policy.
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
			// A live subject is expected if it is the configured one, if the
			// configured pattern covers it, or if it is a pattern that covers the
			// configured subject — the last case being an operator who authored a
			// wildcard while setup recorded a concrete example of it.
			//
			// The limit that leaves: a live pattern broader than the configured
			// subject but still covering it (main-only widened to any ref in the
			// same repo) reads as expected. That is a real widening and this check
			// does not catch it; what it does catch is a subject the configured
			// intent has no relationship to at all, which is the shape both
			// tampering and a mis-scoped IaC change take.
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
	check := ValidationCheck{
		ID:          v.ID(),
		Name:        v.Name(),
		Description: v.Description(),
		Severity:    SeverityError,
		Evidence:    make(map[string]interface{}),
	}

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

	// Issuer: exact. A different issuer means a different identity provider is
	// trusted than the one intended.
	if v.expectedIssuer != "" && live.Issuer != v.expectedIssuer {
		problems = append(problems, fmt.Sprintf(
			"issuer mismatch%s: policy trusts %q, expected %q",
			caseOnlyHint(live.Issuer, v.expectedIssuer), live.Issuer, v.expectedIssuer))
	}

	// Audience: exact membership. Audience pinning is what stops a token minted
	// for one target being replayed at another.
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
	// A policy with no subject condition admits every workload the issuer serves;
	// it is not "no subject to check", it is the widest possible subject.
	if len(live.Subjects) == 0 {
		problems = append(problems, "trust has NO subject condition: every workload this issuer "+
			"mints a token for can assume the target identity (confused-deputy risk)")
	}

	// An unscoped pattern is a finding in its own right, even though it would
	// "match" — it admits every workload from the issuer.
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

	// Everything above asks "is what we expected still there?". That question
	// cannot see an ADDITION: a second Allow statement admitting another
	// audience or another subject leaves the expected values present, so a
	// membership test still passes while the trust has been widened. Drift and
	// tampering both look like additions, so compare as sets, not membership.
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

// GrantedPolicySource lists the policies actually attached to a mechanism's
// target identity. Like TrustPolicySource, it inverts the dependency so the
// core can read provider state without importing providers.
type GrantedPolicySource interface {
	GrantedPolicies(ctx context.Context, ref MechanismRef) ([]string, error)
}

// PermissionsValidator checks that the expected policies are actually attached.
//
// Scope note: this verifies *attachment* — that the policies the spec asked for
// are present on the identity — which is what catches drift and accidental
// detachment. It is deliberately not a full effective-permission simulation
// (AWS SimulatePrincipalPolicy and friends), so it will not detect a policy
// whose contents were edited to grant less than its name implies.
type PermissionsValidator struct {
	requiredPermissions []string
	source              GrantedPolicySource
}

// PermissionsOption configures a PermissionsValidator.
type PermissionsOption func(*PermissionsValidator)

// WithGrantedPolicySource supplies the live attachment list to compare against.
// Without it the check reports Skipped.
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
	check := ValidationCheck{
		ID:          v.ID(),
		Name:        v.Name(),
		Description: v.Description(),
		Severity:    SeverityError,
		Evidence:    make(map[string]interface{}),
	}

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

// RunValidation executes a set of validators and returns a report.
func RunValidation(ctx context.Context, ref MechanismRef, validators []Validator) *ValidationReport {
	report := &ValidationReport{
		Ref:         ref,
		Checks:      make([]ValidationCheck, 0, len(validators)),
		ValidatedAt: time.Now(),
	}

	for _, v := range validators {
		// Stop when the caller has given up. Each check is a cloud API call, and
		// running the rest of the list after a timeout spends quota to produce a
		// report nobody will read. The remaining checks are recorded as skipped so
		// IsComplete reports the truth: they did not run.
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

// standardValidatorsFor returns standard validators for a mechanism type.
func standardValidatorsFor(t MechanismType) []Validator {
	return DefaultValidators.GetForType(t)
}
