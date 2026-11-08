package broker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// TokenTestValidator proves a trust end to end: detect this machine's runtime, mint a proof, exchange it at the target. It is opt-in (`validate --include-token-test`) because it only means something when run from the workload whose identity the trust names.
type TokenTestValidator struct {
	broker *Broker
	target core.Target
}

// NewTokenTestValidator builds the check for one target binding; a nil broker uses the default detection and exchangers.
func NewTokenTestValidator(target core.Target, b *Broker) *TokenTestValidator {
	if b == nil {
		b = New()
	}
	return &TokenTestValidator{broker: b, target: target}
}

func (v *TokenTestValidator) ID() string   { return "token_acquisition" }
func (v *TokenTestValidator) Name() string { return "Token acquisition" }
func (v *TokenTestValidator) Description() string {
	return "Detects the local source runtime, mints a proof for the target's audience, and exchanges it; the credentials are discarded."
}

// Validate implements core.Validator.
func (v *TokenTestValidator) Validate(ctx context.Context, _ core.MechanismRef) core.ValidationCheck {
	check := core.NewCheck(v, core.SeverityError)
	start := time.Now()
	defer func() { check.Duration = time.Since(start) }()

	check.Evidence["target_cloud"] = string(v.target.Cloud())
	check.Evidence["audience"] = v.target.Audience()

	if err := v.target.Validate(); err != nil {
		check.Status = core.CheckStatusFailed
		check.Message = fmt.Sprintf("the recorded mechanism does not describe a complete runtime target: %v", err)
		return check
	}

	creds, rt, err := v.broker.Exchange(ctx, v.target)
	if rt != nil {
		check.Evidence["source_runtime"] = string(rt.Cloud) + "/" + rt.SubRuntime
		check.Evidence["source_subject"] = rt.Subject
	}
	switch {
	case err == nil:
		check.Status = core.CheckStatusPassed
		check.Message = fmt.Sprintf("exchanged a %s/%s proof for %s credentials expiring %s", rt.Cloud, rt.SubRuntime, creds.Cloud, creds.Expiry.UTC().Format(time.RFC3339))
	case rt == nil || errors.Is(err, core.ErrNotThisRuntime):
		// Nothing was detected: a laptop is not a workload, and that is not a finding about the trust.
		check.Status = core.CheckStatusSkipped
		check.Message = fmt.Sprintf("no source runtime detected on this machine (%v); run `validate --include-token-test` from the workload or CI job whose identity the trust names", err)
	case errors.Is(err, core.ErrNonFederatableSource):
		check.Status = core.CheckStatusSkipped
		check.Message = fmt.Sprintf("this runtime cannot mint a portable proof, so the trust cannot be exercised from here: %v", err)
	default:
		check.Status = core.CheckStatusFailed
		check.Message = fmt.Sprintf("the target refused this runtime's identity: %v", err)
		check.Remediation = "If this runtime is the one the trust should admit, compare its issuer, subject and audience against the trust (`cloud-auth doctor --explain`). If it is not, this failure is the trust working as intended."
	}
	return check
}
