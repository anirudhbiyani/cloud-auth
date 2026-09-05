package core

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Subject breadth scoring.

// Breadth is how much a subject pattern admits.
type Breadth int

const (
	// BreadthExact admits one workload. No wildcards.
	BreadthExact Breadth = iota
	// BreadthInfo has an interior wildcard: narrower than it looks, but worth seeing.
	BreadthInfo
	// BreadthMedium admits every ref, tag and event of one repository — including pull_request, which a fork reaches.
	BreadthMedium
	// BreadthHigh admits every repository in an organisation, or every ServiceAccount in a cluster, including ones that do not exist yet.
	BreadthHigh
	// BreadthCritical admits any tenant of the issuer.
	BreadthCritical
)

func (b Breadth) String() string {
	switch b {
	case BreadthCritical:
		return "critical"
	case BreadthHigh:
		return "high"
	case BreadthMedium:
		return "medium"
	case BreadthInfo:
		return "info"
	default:
		return "exact"
	}
}

// BreadthAssessment is a scored subject with the reasoning attached.
type BreadthAssessment struct {
	// Subject is the pattern as written.
	Subject string `json:"subject"`
	// Breadth is the score.
	Breadth Breadth `json:"-"`
	// BreadthText is Breadth for JSON consumers.
	BreadthText string `json:"breadth"`
	// Admits says what this pattern lets in, concretely.
	Admits string `json:"admits"`
	// Advice is what to do about it, or empty when there is nothing to fix.
	Advice string `json:"advice,omitempty"`
}

// NeedsJustification reports whether a subject is broad enough that creating it should be a deliberate, recorded act rather than a default.
func (a BreadthAssessment) NeedsJustification() bool { return a.Breadth >= BreadthCritical }

// ScoreSubject grades how much a subject pattern admits.
func ScoreSubject(subject string) BreadthAssessment {
	trimmed := strings.TrimSpace(subject)

	if trimmed == "" {
		return BreadthAssessment{
			Subject: subject, Breadth: BreadthCritical, BreadthText: BreadthCritical.String(),
			Admits: "every workload this issuer will ever mint a token for — there is no subject " +
				"condition at all",
			Advice: "add a subject condition. The audience does not narrow anything: it is chosen " +
				"by the token requester, and for the common issuers it is a well-known constant",
		}
	}

	// Pins nothing at all.
	if isUnscoped(trimmed) {
		return BreadthAssessment{
			Subject: subject, Breadth: BreadthCritical, BreadthText: BreadthCritical.String(),
			Admits: "every workload this issuer will ever mint a token for",
			Advice: "pin the subject to the workload you mean",
		}
	}

	if !strings.ContainsAny(trimmed, "*?") {
		return BreadthAssessment{
			Subject: subject, Breadth: BreadthExact, BreadthText: BreadthExact.String(),
			Admits: "exactly one workload",
		}
	}

	segments := strings.Split(trimmed, ":")

	// A wildcard in the FIRST segment of a namespaced subject leaves the tenant unpinned.
	if len(segments) > 1 && strings.ContainsAny(segments[0], "*?") {
		return BreadthAssessment{
			Subject: subject, Breadth: BreadthCritical, BreadthText: BreadthCritical.String(),
			Admits: "any tenant of this issuer — the leading segment is a wildcard, and the common " +
				"issuers run ONE issuer across every tenant on the platform",
			Advice: "pin the leading segment to your own tenant",
		}
	}

	// "repo:*" — one segment pinned, the rest wide. Same conclusion.
	if len(segments) == 2 && strings.Trim(segments[1], "*?") == "" {
		return BreadthAssessment{
			Subject: subject, Breadth: BreadthCritical, BreadthText: BreadthCritical.String(),
			Admits: "every repository of every organisation on this issuer",
			Advice: "pin the organisation and repository: repo:<org>/<repo>:ref:refs/heads/<branch>",
		}
	}

	if a, ok := scoreNamespaceWildcard(subject, segments); ok {
		return a
	}

	// A trailing ":*" on an otherwise-pinned subject.
	if strings.HasSuffix(trimmed, ":*") {
		return BreadthAssessment{
			Subject: subject, Breadth: BreadthMedium, BreadthText: BreadthMedium.String(),
			Admits: "every branch, tag and event of this workload, including pull_request — which a " +
				"pull request from a FORK reaches",
			Advice: "pin the final segment: :ref:refs/heads/main for a branch, or " +
				":environment:production for an environment",
		}
	}

	return BreadthAssessment{
		Subject: subject, Breadth: BreadthInfo, BreadthText: BreadthInfo.String(),
		Admits: "more than one workload, through an interior wildcard",
		Advice: "confirm the wildcard admits only what you intend",
	}
}

// scoreNamespaceWildcard handles a wildcard in a middle segment, which is where "every repo in the org" and "every ServiceAccount in the cluster" live.
func scoreNamespaceWildcard(subject string, segments []string) (BreadthAssessment, bool) {
	// system:serviceaccount:<namespace>:<name> — a wildcard in either position admits every ServiceAccount in a namespace, or in the whole cluster.
	if len(segments) >= 4 && segments[0] == "system" && segments[1] == "serviceaccount" {
		nsWild := strings.ContainsAny(segments[2], "*?")
		nameWild := strings.ContainsAny(segments[3], "*?")
		switch {
		case nsWild && nameWild:
			return BreadthAssessment{
				Subject: subject, Breadth: BreadthHigh, BreadthText: BreadthHigh.String(),
				Admits: "every ServiceAccount in every namespace of this cluster, including ones " +
					"created later",
				Advice: "pin the namespace and the ServiceAccount name",
			}, true
		case nsWild:
			return BreadthAssessment{
				Subject: subject, Breadth: BreadthHigh, BreadthText: BreadthHigh.String(),
				Admits: "a ServiceAccount of that name in EVERY namespace, including namespaces " +
					"created later",
				Advice: "pin the namespace",
			}, true
		case nameWild:
			return BreadthAssessment{
				Subject: subject, Breadth: BreadthHigh, BreadthText: BreadthHigh.String(),
				Admits: "every ServiceAccount in that namespace, including ones created later",
				Advice: "pin the ServiceAccount name",
			}, true
		}
		return BreadthAssessment{}, false
	}

	// repo:<org>/<repo>:… — a wildcard in the org/repo segment admits every repository in the organisation.
	if len(segments) >= 2 && segments[0] == "repo" && strings.ContainsAny(segments[1], "*?") {
		owner, _, hasSlash := strings.Cut(segments[1], "/")
		if hasSlash && !strings.ContainsAny(owner, "*?") {
			return BreadthAssessment{
				Subject: subject, Breadth: BreadthHigh, BreadthText: BreadthHigh.String(),
				Admits: fmt.Sprintf("every repository in the %q organisation, including repositories "+
					"created later and repositories transferred in", owner),
				Advice: "pin the repository, or create one role per repository",
			}, true
		}
	}
	return BreadthAssessment{}, false
}

// SharedIssuerNote is context worth carrying next to a broad subject.
const SharedIssuerNote = "AWS's shared-IdP guardrail requires only that `sub` be EVALUATED, not that " +
	"it be narrow, and does not apply to roles created before June 2025"

// SubjectBreadthValidator reports how much each subject in the live trust admits.
type SubjectBreadthValidator struct {
	source TrustPolicySource
}

// NewSubjectBreadthValidator builds the validator.
func NewSubjectBreadthValidator(source TrustPolicySource) *SubjectBreadthValidator {
	return &SubjectBreadthValidator{source: source}
}

func (v *SubjectBreadthValidator) ID() string   { return "subject_breadth" }
func (v *SubjectBreadthValidator) Name() string { return "Subject Breadth" }
func (v *SubjectBreadthValidator) Description() string {
	return "Scores how much each trusted subject admits"
}

// Validate scores every subject in the live trust policy.
func (v *SubjectBreadthValidator) Validate(ctx context.Context, ref MechanismRef) ValidationCheck {
	start := time.Now()
	check := NewCheck(v, SeverityWarning)

	if v.source == nil {
		check.Status = CheckStatusSkipped
		check.Message = "subject breadth was NOT scored: no trust policy source is configured"
		check.Remediation = "Inspect the trust policy's subject conditions by hand."
		check.Duration = time.Since(start)
		return check
	}

	live, err := v.source.TrustPolicy(ctx, ref)
	if err != nil || live == nil {
		check.Status = CheckStatusSkipped
		check.Message = "subject breadth was NOT scored: the live trust policy could not be read"
		if err != nil {
			check.Evidence["error"] = err.Error()
		}
		check.Remediation = "Inspect the trust policy's subject conditions by hand."
		check.Duration = time.Since(start)
		return check
	}

	if len(live.Subjects) == 0 {
		// No condition at all is the widest possible subject, and TrustPolicyMatchValidator already fails on it — so this reports the breadth without also failing, rather than double-counting one problem as two failures.
		a := ScoreSubject("")
		check.Severity = SeverityCritical
		check.Status = CheckStatusFailed
		check.Message = "no subject condition: " + a.Admits
		check.Remediation = a.Advice
		check.Evidence["breadth"] = a.BreadthText
		check.Duration = time.Since(start)
		return check
	}

	var worst BreadthAssessment
	var messages []string
	assessments := make([]BreadthAssessment, 0, len(live.Subjects))
	for _, s := range live.Subjects {
		a := ScoreSubject(s)
		assessments = append(assessments, a)
		if a.Breadth > worst.Breadth {
			worst = a
		}
		if a.Breadth > BreadthExact {
			messages = append(messages, fmt.Sprintf("%q (%s) admits %s", s, a.Breadth, a.Admits))
		}
	}
	check.Evidence["subjects"] = assessments

	if worst.Breadth == BreadthExact {
		check.Status = CheckStatusPassed
		check.Message = "every trusted subject names exactly one workload"
		check.Duration = time.Since(start)
		return check
	}

	// The severity, not the status, is what grades this.
	check.Severity = severityForBreadth(worst.Breadth)
	check.Status = CheckStatusFailed
	check.Message = strings.Join(messages, "; ")
	check.Remediation = worst.Advice + ". " + SharedIssuerNote
	check.Duration = time.Since(start)
	return check
}

// severityForBreadth maps a breadth score onto the validation severity scale.
func severityForBreadth(b Breadth) Severity {
	switch b {
	case BreadthCritical:
		return SeverityCritical
	case BreadthHigh:
		return SeverityError
	case BreadthMedium:
		return SeverityWarning
	default:
		return SeverityInfo
	}
}
