package core

// Claim-by-claim comparison of a presented assertion against live trust.

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

// ExplainInput is everything the detectors compare.
type ExplainInput struct {
	// Trust is the live trust policy read from the target.
	Trust *TrustPolicy
	// Token is the proof the source minted, or nil if minting failed.
	Token *SourceToken
	// Target is the binding being preflighted.
	Target Target
	// SourceCloud is the detected source cloud, where known.
	SourceCloud Cloud
	// IdPAuthorizedRoles is the "https://aws.amazon.com/roles" claim from the presented token, if it carries one.
	IdPAuthorizedRoles []string
	// TargetRole is the role the exchange will attempt to assume.
	TargetRole string
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
		detectIdPAuthorizedRoleMismatch,
	} {
		out = append(out, detect(in)...)
	}

	// Stable, severity-first ordering.
	sortFindings(out)
	return out
}

func sortFindings(f []Finding) {
	// Insertion sort: the list is a handful of entries and this keeps equal severities in detector-declaration order, which is deliberate.
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
