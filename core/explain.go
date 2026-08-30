package core

// Claim-by-claim comparison of a presented assertion against live trust.
//
// One AWS AccessDenied covers roughly fifteen distinct root causes. GCP's most
// common failure — "The attribute condition was not met" — is not on Google's
// own troubleshooting page. Microsoft's documentation states outright that a
// wrong Azure subject produces a credential that is created successfully and
// then fails without error.
//
// Everything here is a pure function over data the caller has already fetched.
// That is deliberate and it is what diagnose() already buys: the detectors are
// table-testable against fixtures, with no cloud.

// FindingSeverity orders findings for display.
type FindingSeverity int

const (
	// FindingInfo is worth knowing but is not why the exchange failed.
	FindingInfo FindingSeverity = iota
	// FindingWarning will break, or already admits more than intended.
	FindingWarning
	// FindingCritical is why this exchange is being refused.
	FindingCritical
)

func (s FindingSeverity) String() string {
	switch s {
	case FindingCritical:
		return "critical"
	case FindingWarning:
		return "warning"
	default:
		return "info"
	}
}

// Finding is one diverging claim, named so an operator can act on it.
//
// Presented and Configured are both carried because the whole point is the
// diff: "sub does not match" sends someone to read a policy, while
// "policy says repo:org/repo:…, token presents repo:org@123/repo@456:…" tells
// them what happened.
type Finding struct {
	// Detector identifies which check produced this, for --format json.
	Detector string `json:"detector"`
	// Severity orders the output.
	Severity FindingSeverity `json:"-"`
	// SeverityText is Severity for JSON consumers.
	SeverityText string `json:"severity"`
	// Claim is the claim that diverged, where one did.
	Claim string `json:"claim,omitempty"`
	// Presented is what the token carries.
	Presented string `json:"presented,omitempty"`
	// Configured is what the trust policy expects.
	Configured string `json:"configured,omitempty"`
	// Summary states the problem in one line.
	Summary string `json:"summary"`
	// Fix is what to do about it, concretely.
	Fix string `json:"fix"`
}

// newFinding builds a Finding with SeverityText filled in.
func newFinding(detector string, sev FindingSeverity, summary, fix string) Finding {
	return Finding{
		Detector: detector, Severity: sev, SeverityText: sev.String(),
		Summary: summary, Fix: fix,
	}
}

// withDiff attaches the presented/configured pair.
func (f Finding) withDiff(claim, presented, configured string) Finding {
	f.Claim, f.Presented, f.Configured = claim, presented, configured
	return f
}

// ExplainInput is everything the detectors compare. The caller fetches it; no
// function in this file performs I/O.
type ExplainInput struct {
	// Trust is the live trust policy read from the target.
	Trust *TrustPolicy
	// Token is the proof the source minted, or nil if minting failed.
	Token *SourceToken
	// Target is the binding being preflighted.
	Target Target
	// SourceCloud is the detected source cloud, where known.
	SourceCloud Cloud
}

// Explain runs every detector and returns findings, most severe first.
func Explain(in ExplainInput) []Finding {
	if in.Trust == nil {
		return nil
	}

	var out []Finding
	for _, detect := range []func(ExplainInput) []Finding{
		detectImmutableSubjectMismatch,
		detectEnvironmentOverridesBranch,
		detectExactOperatorWithWildcard,
		detectCaseOnlyMismatch,
		detectOversizedMappedSubject,
		detectForkPullRequestExposure,
		detectIssuerMismatch,
	} {
		out = append(out, detect(in)...)
	}

	// Stable, severity-first ordering. Sorting by severity alone would let the
	// detector map's order leak through for equal severities.
	sortFindings(out)
	return out
}

func sortFindings(f []Finding) {
	// Insertion sort: the list is a handful of entries and this keeps equal
	// severities in detector-declaration order, which is deliberate.
	for i := 1; i < len(f); i++ {
		for j := i; j > 0 && f[j].Severity > f[j-1].Severity; j-- {
			f[j], f[j-1] = f[j-1], f[j]
		}
	}
}

// presentedSubject returns the token's subject, if there is one.
func presentedSubject(in ExplainInput) string {
	if in.Token == nil {
		return ""
	}
	return in.Token.Subject
}
