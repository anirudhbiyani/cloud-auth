package verify

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// Exchanger is the one cloud-touching dependency of the runner. *broker.Broker
// satisfies it as-is: the verifier drives cloud-auth's own detect→mint→exchange
// orchestrator rather than reimplementing any part of it.
type Exchanger interface {
	Exchange(ctx context.Context, target core.Target) (*core.Credentials, *core.Runtime, error)
}

// Probe optionally proves the returned credentials actually work against the
// target cloud. Probes are pluggable and always soft: an error (or a missing
// implementation) is reported, never fatal, unless Runner.StrictProbe is set.
// A probe MUST NOT return credential material in its detail string; the
// Scrubber will redact it regardless.
type Probe func(ctx context.Context, creds *core.Credentials, c Case) (detail string, err error)

// DefaultSkew is the clock-drift tolerance applied to credential expiry.
const DefaultSkew = 60 * time.Second

// DefaultCaseTimeout bounds a single exchange so one hung STS cannot wedge the
// whole run (a Job that never exits is worse than a red one).
const DefaultCaseTimeout = 60 * time.Second

// Runner executes cases against an injected Exchanger.
type Runner struct {
	Exchanger Exchanger
	// Probes is the probe registry; nil means "no probes registered", which
	// makes every requested probe an "unimplemented" soft result.
	Probes map[string]Probe
	// Scrubber redacts credential material from every recorded string.
	Scrubber *Scrubber
	// Now defaults to time.Now; injected for deterministic expiry tests.
	Now func() time.Time
	// Skew is the credential-expiry tolerance (DefaultSkew when zero).
	Skew time.Duration
	// Timeout bounds each case (DefaultCaseTimeout when zero).
	Timeout time.Duration
	// StrictProbe promotes a probe failure to a case failure.
	StrictProbe bool
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Runner) skew() time.Duration {
	if r.Skew > 0 {
		return r.Skew
	}
	return DefaultSkew
}

func (r *Runner) timeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return DefaultCaseTimeout
}

func (r *Runner) scrubber() *Scrubber {
	if r.Scrubber == nil {
		r.Scrubber = NewScrubber()
	}
	return r.Scrubber
}

// Run executes every case in order and returns their results. It never returns
// an error: a failed case is data, not a control-flow event.
func (r *Runner) Run(ctx context.Context, cases []Case) []CaseResult {
	results := make([]CaseResult, 0, len(cases))
	for _, c := range cases {
		results = append(results, r.RunCase(ctx, c))
	}
	return results
}

// RunCase executes one case: exchange via the broker, then assert the outcome
// the plan declared.
func (r *Runner) RunCase(ctx context.Context, c Case) CaseResult {
	res := CaseResult{
		Name:          c.Name,
		SourceRuntime: CanonicalRuntime(c.SourceRuntime),
		TargetCloud:   c.Target.Cloud,
		Expect:        c.Expect,
		ExpectError:   c.ExpectError,
		Status:        StatusFail,
		Probe:         ProbeResult{Status: ProbeNotRequested},
	}
	scrub := r.scrubber()

	target, err := c.Target.Target()
	if err != nil {
		res.Error = scrub.Scrub(errSummary(err))
		return res
	}
	res.Identity = identityFromTarget(target)

	// Reject an unknown sentinel here as well as at load time: a case built in
	// code (integration tests) never passes through Plan.Validate.
	var wantErr error
	if c.Expect == ExpectError {
		var ok bool
		if wantErr, ok = SentinelFor(c.ExpectError); !ok {
			res.Error = fmt.Sprintf("unknown sentinel %q in expect_error", c.ExpectError)
			return res
		}
	}

	cctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()

	start := time.Now()
	creds, rt, exErr := r.Exchanger.Exchange(cctx, target)
	res.DurationMS = time.Since(start).Milliseconds()

	// Register secrets the moment they exist, before anything is recorded.
	scrub.AddCredentials(creds)
	mergeRuntimeIdentity(&res.Identity, rt)

	switch c.Expect {
	case ExpectError:
		r.assertExpectedError(&res, c, exErr, wantErr)
	default:
		r.assertSuccess(cctx, &res, c, creds, exErr)
	}
	res.Error = scrub.Scrub(res.Error)
	res.Note = scrub.Scrub(res.Note)
	res.Probe.Detail = scrub.Scrub(res.Probe.Detail)
	res.Identity.scrub(scrub)
	return res
}

// assertExpectedError implements the negative half of the matrix: the pair must
// fail, and it must fail with the documented sentinel. Failing for some other
// reason is not a pass — that is how a real regression would sneak through.
func (r *Runner) assertExpectedError(res *CaseResult, c Case, exErr, wantErr error) {
	switch {
	case exErr == nil:
		res.Error = fmt.Sprintf("exchange succeeded but the case expects it to fail with %s", c.ExpectError)
	case errors.Is(exErr, wantErr):
		res.Status = StatusPass
		res.MatchedSentinel = c.ExpectError
		// Keep the actual message: it is the actionable guidance cloud-auth
		// emits alongside the sentinel, and reviewing it is the point of the
		// negative test.
		res.Note = errSummary(exErr)
	default:
		res.Error = fmt.Sprintf("failed with the wrong error: got %q, want %s", errSummary(exErr), c.ExpectError)
	}
}

// assertSuccess implements the positive half: real, non-empty, unexpired
// credentials, plus the optional probe.
func (r *Runner) assertSuccess(ctx context.Context, res *CaseResult, c Case, creds *core.Credentials, exErr error) {
	if exErr != nil {
		res.Error = "exchange failed: " + errSummary(exErr)
		if s, ok := knownSentinel(exErr); ok {
			res.MatchedSentinel = s
		}
		return
	}
	if err := validateCredentials(creds, r.now(), r.skew()); err != nil {
		res.Error = errSummary(err)
		return
	}
	res.Identity.STSRequestID = creds.STSRequestID
	if !creds.Expiry.IsZero() {
		res.Identity.CredentialsExpireAt = creds.Expiry.UTC().Format(time.RFC3339)
	}
	res.Status = StatusPass

	if c.Probe == "" {
		return
	}
	res.Probe = r.runProbe(ctx, c, creds)
	if r.StrictProbe && res.Probe.Status != ProbeOK {
		res.Status = StatusFail
		res.Error = fmt.Sprintf("probe %q %s (probe-strict): %s", c.Probe, res.Probe.Status, res.Probe.Detail)
	}
}

// runProbe invokes a registered probe, containing both its errors and its
// panics: probe code talks to third-party APIs and must never take the run down.
func (r *Runner) runProbe(ctx context.Context, c Case, creds *core.Credentials) (pr ProbeResult) {
	pr = ProbeResult{Name: c.Probe, Status: ProbeUnimplemented,
		Detail: fmt.Sprintf("no probe named %q is registered in this build; credential validity was still asserted", c.Probe)}

	probe, ok := r.Probes[c.Probe]
	if !ok || probe == nil {
		return pr
	}

	start := time.Now()
	defer func() {
		pr.DurationMS = time.Since(start).Milliseconds()
		if rec := recover(); rec != nil {
			pr.Status = ProbeSoftFail
			pr.Detail = fmt.Sprintf("probe panicked: %v", rec)
		}
	}()

	detail, err := probe(ctx, creds, c)
	if err != nil {
		return ProbeResult{Name: c.Probe, Status: ProbeSoftFail, Detail: errSummary(err)}
	}
	return ProbeResult{Name: c.Probe, Status: ProbeOK, Detail: detail}
}

// validateCredentials asserts the credentials are present, populated for their
// cloud, and not (nearly) expired.
func validateCredentials(c *core.Credentials, now time.Time, skew time.Duration) error {
	if c == nil {
		return errors.New("exchange returned no credentials")
	}
	switch c.Cloud {
	case core.AWS:
		if c.AccessKeyID == "" || c.SecretAccessKey == "" {
			return errors.New("aws credentials are missing the access key id / secret access key")
		}
		if c.SessionToken == "" {
			return errors.New("aws credentials are missing the session token (federated creds are always temporary)")
		}
	case core.GCP, core.Azure:
		if c.AccessToken == "" {
			return fmt.Errorf("%s credentials are missing the access token", c.Cloud)
		}
	default:
		if c.AccessToken == "" && c.AccessKeyID == "" {
			return fmt.Errorf("credentials for cloud %q are empty", c.Cloud)
		}
	}
	if c.Expired(now, skew) {
		return fmt.Errorf("credentials are already expired or within the %s skew window (expiry %s, now %s)",
			skew, c.Expiry.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	return nil
}

// knownSentinel names the sentinel an error matches, if any — useful context on
// an unexpected failure ("trust missing" reads better than a raw STS body).
func knownSentinel(err error) (string, bool) {
	for _, name := range SentinelNames() {
		s, _ := SentinelFor(name)
		if errors.Is(err, s) {
			return name, true
		}
	}
	return "", false
}

// The report is deliberately cloud-agnostic: one shape for every pair, so the
// matrix is readable. These accessors pull whichever fields the concrete target
// happens to carry.
func roleOf(t core.Target) string {
	if a, ok := t.(core.AWSTarget); ok {
		return a.RoleARN
	}
	return ""
}

func poolOf(t core.Target) string {
	if g, ok := t.(core.GCPTarget); ok {
		return g.WorkloadIdentityPool
	}
	return ""
}

func tenantOf(t core.Target) string {
	if z, ok := t.(core.AzureTarget); ok {
		return z.Tenant
	}
	return ""
}

func clientIDOf(t core.Target) string {
	if z, ok := t.(core.AzureTarget); ok {
		return z.ClientID
	}
	return ""
}

func identityFromTarget(t core.Target) Identity {
	return Identity{
		Role:                 roleOf(t),
		WorkloadIdentityPool: poolOf(t),
		Tenant:               tenantOf(t),
		ClientID:             clientIDOf(t),
		Audience:             t.Audience(),
	}
}

func mergeRuntimeIdentity(id *Identity, rt *core.Runtime) {
	if rt == nil {
		return
	}
	id.SourceCloud = string(rt.Cloud)
	id.SourceSubRuntime = rt.SubRuntime
	if rt.Issuer != "" {
		id.Issuer = rt.Issuer
	}
	if rt.Subject != "" {
		id.Subject = rt.Subject
	}
}

// scrub passes every identity field through the scrubber. These fields are
// metadata by construction, but a subject can be operator-supplied and the
// guarantee must hold unconditionally.
func (id *Identity) scrub(s *Scrubber) {
	id.Issuer = s.Scrub(id.Issuer)
	id.Subject = s.Scrub(id.Subject)
	id.Role = s.Scrub(id.Role)
	id.WorkloadIdentityPool = s.Scrub(id.WorkloadIdentityPool)
	id.Tenant = s.Scrub(id.Tenant)
	id.ClientID = s.Scrub(id.ClientID)
	id.Audience = s.Scrub(id.Audience)
	id.STSRequestID = s.Scrub(id.STSRequestID)
}
