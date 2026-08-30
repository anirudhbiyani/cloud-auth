package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// preflight is the set of injected results a diagnosis is computed over. It is
// deliberately a plain data struct so the diagnostic logic can be unit-tested
// with fakes instead of a live cloud environment.
type preflight struct {
	// runtime is the detected source runtime (nil if detection failed).
	runtime *core.Runtime
	// detectErr is the error returned by source detection, if any.
	detectErr error
	// target is the requested target binding.
	target core.Target
	// token is the minted source proof (nil if minting failed).
	token *core.SourceToken
	// mintErr is the error returned by Mint, if any.
	mintErr error
	// now is the reference time for expiry/skew checks.
	now time.Time
	// skew is the tolerated clock skew for expiry checks.
	skew time.Duration
}

// normalize replaces a nil target with core.NoTarget so every reader can call
// Cloud() and Audience() unconditionally.
//
// The production caller cannot produce a nil target — targetFlags returns a
// typed zero — but preflight is a plain struct that tests and future callers
// build by hand, and core.Target is an interface, so a field left unset is a
// panic waiting at the first method call rather than an empty report. Absorb it
// here, once, instead of guarding at each of the eleven p.target uses.
func (p preflight) normalize() preflight {
	if p.target == nil {
		p.target = core.NoTarget{}
	}
	return p
}

// diagnosis is one line of the preflight report: a status symbol and message.
type diagnosis struct {
	ok      bool
	message string
}

func (d diagnosis) String() string {
	sym := "✗"
	if d.ok {
		sym = "✓"
	}
	return fmt.Sprintf("  %s %s", sym, d.message)
}

// diagnose turns injected preflight results into an ordered list of actionable
// findings. It never performs I/O; all cloud interaction happens in the caller
// and is passed in via preflight. Each failure mode maps to a distinct,
// specific message so an operator knows exactly what to fix.
func diagnose(p preflight) []diagnosis {
	p = p.normalize()
	var out []diagnosis

	// Detection outcome.
	if p.detectErr != nil {
		out = append(out, diagnosis{false, fmt.Sprintf(
			"could not detect a source runtime: %v\n    (not running on a supported cloud? checks below cannot run)", p.detectErr)})
		return out
	}
	if p.runtime == nil {
		out = append(out, diagnosis{false, "no source runtime detected; cannot preflight"})
		return out
	}

	// Non-federatable source: nothing downstream can work.
	if !p.runtime.Federatable {
		out = append(out, diagnosis{false, fmt.Sprintf(
			"source runtime %s/%s is not federatable: it cannot mint a portable token.\n    Use an OIDC-native source (e.g. EKS IRSA, GKE Workload Identity) instead of %s.",
			p.runtime.Cloud, p.runtime.SubRuntime, p.runtime.SubRuntime)})
		return out
	}

	// Mint outcome — branch on the sentinel errors.
	if p.mintErr != nil {
		out = append(out, diagnoseMintError(p)...)
		return out
	}
	out = append(out, diagnosis{true, mintedProofSummary(p.token)})

	// Token-level checks (only meaningful when a token exists).
	if p.token != nil {
		out = append(out, diagnoseToken(p)...)
	}
	return out
}

// diagnoseMintError maps a mint error to a specific finding using errors.Is
// against the sentinel errors, plus the source→target bridge guidance.
func diagnoseMintError(p preflight) []diagnosis {
	switch {
	case errors.Is(p.mintErr, core.ErrNonFederatableSource):
		return []diagnosis{{false, fmt.Sprintf(
			"source cannot produce a federatable token (%s/%s).\n    Switch to an OIDC-native source such as EKS IRSA or GKE Workload Identity.",
			p.runtime.Cloud, p.runtime.SubRuntime)}}
	case errors.Is(p.mintErr, core.ErrNoFirstClassPath):
		return []diagnosis{{false, fmt.Sprintf(
			"no first-class keyless path from %s (%s) to %s.\n    %s",
			p.runtime.Cloud, p.runtime.SubRuntime, p.target.Cloud(), bridgeGuidance(p.runtime.Cloud, p.target.Cloud()))}}
	default:
		return []diagnosis{{false, fmt.Sprintf("minting source proof failed: %v", p.mintErr)}}
	}
}

// mintedProofSummary names the proof that was actually minted. On AWS this is
// the difference between an STS-vended OIDC JWT and a SigV4 GetCallerIdentity
// proof — the same principal either way, but verified by the target against
// completely different trust configuration, so "it minted" is not enough to know
// whether the exchange can work.
func mintedProofSummary(tok *core.SourceToken) string {
	if tok == nil {
		return "source proof minted successfully"
	}
	msg := fmt.Sprintf("source proof minted successfully (kind %s)", tok.Kind)
	if tok.Issuer != "" {
		msg += fmt.Sprintf(" from issuer %s", tok.Issuer)
	}
	if tok.Subject != "" {
		msg += fmt.Sprintf(" for subject %s", tok.Subject)
	}
	return msg
}

// diagnoseToken performs the checks that require an actual minted token:
// audience match, expiry/clock-skew, and Azure case-sensitivity. It also
// reports what an exchange would still need against the target trust.
func diagnoseToken(p preflight) []diagnosis {
	var out []diagnosis
	tok := p.token

	// Proof kind against the target BEFORE anything else, because when it is
	// wrong nothing below it matters: an audience that matches perfectly is
	// irrelevant if the target's STS will not accept this kind of proof at all.
	//
	// This is the check that made bridgeGuidance dead code. It was only reached
	// from the mint-error path, and no source returns ErrNoFirstClassPath —
	// sources return ErrNonFederatableSource, and the exchangers return
	// ErrNoFirstClassPath, which doctor never calls. So a SigV4 proof minted
	// successfully, doctor reported "minted successfully (kind AWSSigV4)", and
	// said nothing about the target refusing it.
	if d, ok := diagnoseProofKind(p); ok {
		out = append(out, d)
	}

	// Audience match: a projected-token aud must equal the pinned target aud.
	switch {
	case p.target.Audience() == "":
		out = append(out, diagnosis{false, "target audience is empty; it must be pinned per target"})
	case tok.Audience == "":
		out = append(out, diagnosis{false, fmt.Sprintf(
			"minted token has no audience but target requires %q; the source is not projecting an aud claim", p.target.Audience())})
	case tok.Audience != p.target.Audience():
		out = append(out, diagnosis{false, fmt.Sprintf(
			"audience mismatch: token aud %q ≠ target audience %q.\n    Re-project the source token with the target's audience.",
			tok.Audience, p.target.Audience())})
	default:
		out = append(out, diagnosis{true, fmt.Sprintf("audience matches target (%s)", p.target.Audience())})
	}

	// Expiry / clock skew.
	if !tok.Expiry.IsZero() {
		if tok.Expired(p.now, p.skew) {
			out = append(out, diagnosis{false, fmt.Sprintf(
				"token is expired or within clock-skew (%s) of expiry (exp %s, now %s).\n    Check the workload clock for drift and re-mint.",
				p.skew, tok.Expiry.UTC().Format(time.RFC3339), p.now.UTC().Format(time.RFC3339))})
		} else {
			out = append(out, diagnosis{true, fmt.Sprintf("token valid until %s", tok.Expiry.UTC().Format(time.RFC3339))})
		}
	}

	// Azure is case-sensitive on issuer/subject/audience; a case-only mismatch
	// against the target audience is a common, silent trust failure.
	if p.target.Cloud() == core.Azure && tok.Audience != "" && p.target.Audience() != "" &&
		tok.Audience != p.target.Audience() &&
		strings.EqualFold(tok.Audience, p.target.Audience()) {
		out = append(out, diagnosis{false, fmt.Sprintf(
			"Azure case-sensitivity: token aud %q differs only in case from target %q.\n    Azure matches issuer/subject/audience exactly; align the case.",
			tok.Audience, p.target.Audience())})
	}

	return out
}

// diagnoseProofKind reports whether the target's STS accepts this proof kind.
//
// Only GCP accepts a SigV4 GetCallerIdentity proof: it calls the AWS API to
// verify it. AWS's own AssumeRoleWithWebIdentity and Entra's client-credentials
// grant both take an OIDC JWT and nothing else.
func diagnoseProofKind(p preflight) (diagnosis, bool) {
	tok := p.token
	if tok == nil || tok.Kind == core.OIDC {
		return diagnosis{}, false
	}
	targetCloud := p.target.Cloud()
	if targetCloud == "" || targetCloud == core.GCP {
		return diagnosis{}, false
	}

	sourceCloud := core.Cloud("")
	if p.runtime != nil {
		sourceCloud = p.runtime.Cloud
	}
	return diagnosis{false, fmt.Sprintf(
		"%s's STS will not accept a %s proof.\n    %s",
		targetCloud, tok.Kind, bridgeGuidance(sourceCloud, targetCloud))}, true
}

// bridgeGuidance returns the human guidance for a source→target pair that has
// no first-class keyless path (e.g. AWS EC2 SigV4 → Azure OIDC-only STS).
func bridgeGuidance(source, target core.Cloud) string {
	if source == core.AWS {
		return fmt.Sprintf(
			"AWS presented a SigV4 GetCallerIdentity proof, which %s's STS does not accept. "+
				"Enable outbound identity federation on the account "+
				"(aws iam enable-outbound-web-identity-federation) — EC2, ECS and Lambda can then "+
				"mint a real OIDC token via sts:GetWebIdentityToken, and this path becomes "+
				"first-class. Otherwise run the workload on an OIDC-native source such as EKS IRSA.",
			target)
	}
	return fmt.Sprintf(
		"%s presents a SigV4/native proof that %s's STS does not accept directly. "+
			"Introduce an OIDC bridge (mint an RS256 OIDC token the target trusts), or run the workload on an OIDC-native source.",
		source, target)
}

// exchangeAdvisory reports, without performing the exchange, what the target
// trust must contain for the exchange to succeed. It maps ErrTrustMissing to
// per-cloud remediation. This is printed after the safe (mint-only) preflight.
func exchangeAdvisory(target core.Target) string {
	// A type switch, not a switch on Cloud(): each branch then reads only the
	// fields its own cloud actually has, and the compiler enforces that.
	switch t := target.(type) {
	case core.AWSTarget:
		return fmt.Sprintf(
			"exchange would call sts:AssumeRoleWithWebIdentity for role %q.\n    Ensure an IAM OIDC provider exists for the source issuer and the role trust policy allows this subject/audience (else: %v).",
			t.RoleARN, core.ErrTrustMissing)
	case core.GCPTarget:
		return fmt.Sprintf(
			"exchange would call GCP STS for pool %q.\n    Ensure the workload identity pool provider trusts the source issuer and the principal binding is granted (else: %v).",
			t.WorkloadIdentityPool, core.ErrTrustMissing)
	case core.AzureTarget:
		return fmt.Sprintf(
			"exchange would request a token for tenant %q, client %q.\n    Ensure a federated identity credential matches the issuer/subject/audience EXACTLY (case-sensitive) (else: %v).",
			t.Tenant, t.ClientID, core.ErrTrustMissing)
	default:
		return fmt.Sprintf("unsupported target %T", target)
	}
}

// writeDiagnoses renders the runtime summary and the diagnosis lines to w.
func writeDiagnoses(w io.Writer, p preflight, ds []diagnosis) {
	p = p.normalize()
	if p.target.Cloud() != "" {
		fmt.Fprintf(w, "\nPreflight target %s", p.target.Cloud())
		if p.target.Audience() != "" {
			fmt.Fprintf(w, " (audience %s)", p.target.Audience())
		}
		fmt.Fprintln(w, ":")
	}
	for _, d := range ds {
		fmt.Fprintln(w, d.String())
	}
	// Only advise on the exchange when the mint half succeeded.
	if p.target.Cloud() != "" && p.mintErr == nil && p.detectErr == nil &&
		p.runtime != nil && p.runtime.Federatable {
		fmt.Fprintf(w, "  → %s\n", exchangeAdvisory(p.target))
	}
}
