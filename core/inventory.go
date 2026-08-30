package core

import (
	"context"
	"fmt"
	"strings"
)

// Cross-cloud trust inventory.
//
// Nobody can answer "which external identities can assume anything in any of
// our clouds". AWS IAM Access Analyzer surfaces federated principals but does
// not distinguish repo:org/specific-repo:ref:refs/heads/main from repo:org/*.
// Prowler and ScoutSuite do partial single-cloud trust checks. Cloudsplaining
// covers permissions policies, not trust policies. Every existing tool is
// single-cloud and posture-oriented.
//
// This is also the one place where CROSS-cloud genuinely earns its existence in
// this product. Setup is a one-time per-pair job that vendor documentation
// covers well; this is the same question with three incompatible answers.

// TrustRecord is one federated trust relationship, normalized across clouds.
type TrustRecord struct {
	// Cloud is where the trusting resource lives.
	Cloud Cloud `json:"cloud"`
	// Resource is the trusting identity: a role ARN, a pool provider resource
	// name, an application object id.
	Resource string `json:"resource"`
	// Name is the short human-facing name of that resource.
	Name string `json:"name,omitempty"`
	// Issuer is the external OIDC issuer trusted to assume it.
	Issuer string `json:"issuer,omitempty"`
	// SubjectCondition is the subject pattern, verbatim.
	SubjectCondition string `json:"subject_condition,omitempty"`
	// Operator is how SubjectCondition is matched, where the cloud has one.
	Operator string `json:"operator,omitempty"`
	// Audiences are the accepted aud values.
	Audiences []string `json:"audiences,omitempty"`

	// Breadth is how much SubjectCondition admits.
	Breadth BreadthAssessment `json:"breadth"`
	// Liveness is whether the namespace it trusts still exists and is ours.
	Liveness LivenessResult `json:"liveness"`
	// RenameFragile marks a GitHub subject in the legacy format, which breaks
	// the first time the repository is renamed or transferred.
	RenameFragile bool `json:"rename_fragile"`
}

// Severity is the worst thing this record says about itself.
func (r TrustRecord) Severity() FindingSeverity {
	switch {
	case r.Liveness.State == NamespaceUnregistered,
		r.Liveness.State == NamespaceNotOurs,
		r.Breadth.Breadth >= BreadthCritical:
		return FindingCritical
	case r.Breadth.Breadth >= BreadthHigh, r.RenameFragile:
		return FindingWarning
	default:
		return FindingInfo
	}
}

// NamespaceState classifies whether a trusted namespace still exists.
type NamespaceState string

const (
	// NamespaceLive means the namespace exists and is one of ours.
	NamespaceLive NamespaceState = "live-and-ours"
	// NamespaceNotOurs means it exists and belongs to somebody else. Whoever
	// holds it can mint a token with this subject.
	NamespaceNotOurs NamespaceState = "live-but-not-ours"
	// NamespaceUnregistered means the namespace does not exist and can be
	// claimed by anyone, right now.
	NamespaceUnregistered NamespaceState = "unregistered"
	// NamespaceUnknown means liveness could not be determined. Never a pass.
	NamespaceUnknown NamespaceState = "unknown"
)

// LivenessResult is the outcome of resolving a trusted namespace.
type LivenessResult struct {
	// Namespace is what was resolved, e.g. "myorg/myrepo" or a Kubernetes
	// namespace. Empty when none could be parsed.
	Namespace string `json:"namespace,omitempty"`
	// State is the classification.
	State NamespaceState `json:"state"`
	// Detail explains an unknown or a negative result.
	Detail string `json:"detail,omitempty"`
}

// NamespaceResolver answers whether a namespace on a shared issuer still
// exists, and whether it is ours.
//
// An interface because the answer is issuer-specific — a GitHub org, a GitLab
// group, a Terraform Cloud organisation — and because unit tests must be able
// to answer without a network.
type NamespaceResolver interface {
	// Issuer reports which issuer this resolver speaks for.
	Issuer() string
	// Resolve classifies a namespace parsed from a subject condition.
	Resolve(ctx context.Context, namespace string) (NamespaceState, string, error)
}

// sharedIssuers run ONE OIDC issuer across every tenant, and permit namespace
// reuse. Delete an organisation, someone re-registers the name, mints a token
// with an identical sub, and assumes a role that is still sitting there.
//
// Published 2026 telemetry found 14% of GitHub namespaces referenced in AWS
// trust policies were unregistered and claimable, and 24% for Azure, with each
// dead namespace trusted by roughly twelve distinct identities. The check is one
// API call that no mainstream scanner makes.
var sharedIssuers = map[string]bool{
	"token.actions.githubusercontent.com": true,
	"gitlab.com":                          true,
	"app.terraform.io":                    true,
}

// IsSharedIssuer reports whether an issuer is one global issuer serving every
// tenant, which is what makes namespace liveness matter.
func IsSharedIssuer(issuer string) bool {
	host := strings.TrimPrefix(strings.TrimPrefix(issuer, "https://"), "http://")
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	return sharedIssuers[host]
}

// NamespaceFromSubject extracts the tenant namespace a subject condition trusts.
//
// The namespace is what somebody else could register: a GitHub org/repo, a
// GitLab group/project, a Kubernetes namespace. A wildcard in the namespace
// position means there is nothing specific to resolve, and reporting one as
// "unregistered" would be wrong — it is unbounded, which the breadth score
// already says.
func NamespaceFromSubject(subject string) (string, bool) {
	trimmed := strings.TrimSpace(subject)
	if trimmed == "" {
		return "", false
	}
	segments := strings.Split(trimmed, ":")

	switch {
	// repo:<org>/<repo>:… — GitHub Actions.
	case segments[0] == "repo" && len(segments) >= 2:
		return namespaceIfConcrete(segments[1])

	// project_path:<group>/<project>:… — GitLab CI.
	case segments[0] == "project_path" && len(segments) >= 2:
		return namespaceIfConcrete(segments[1])

	// organization:<org>:project:<project>:… — Terraform Cloud.
	case segments[0] == "organization" && len(segments) >= 2:
		return namespaceIfConcrete(segments[1])

	// system:serviceaccount:<namespace>:<name> — Kubernetes.
	case len(segments) >= 3 && segments[0] == "system" && segments[1] == "serviceaccount":
		return namespaceIfConcrete(segments[2])
	}
	return "", false
}

// namespaceIfConcrete returns the namespace unless it contains a wildcard.
func namespaceIfConcrete(ns string) (string, bool) {
	if ns == "" || strings.ContainsAny(ns, "*?") {
		return "", false
	}
	return ns, true
}

// ResolveLiveness classifies a record's trusted namespace.
//
// Unknown is the answer whenever the question could not be asked, and it is
// never reported as fine: "we could not tell" and "it is safe" are different
// answers, and conflating them here would be the same mistake as a validator
// reporting a skipped check as passed.
func ResolveLiveness(ctx context.Context, issuer, subject string, resolvers []NamespaceResolver) LivenessResult {
	if !IsSharedIssuer(issuer) {
		return LivenessResult{
			State: NamespaceUnknown,
			Detail: "not a shared issuer: this issuer serves one tenant, so its namespaces cannot " +
				"be re-registered by somebody else",
		}
	}

	namespace, ok := NamespaceFromSubject(subject)
	if !ok {
		return LivenessResult{
			State:  NamespaceUnknown,
			Detail: "no concrete namespace in the subject condition to resolve",
		}
	}

	for _, r := range resolvers {
		if !issuerMatches(r.Issuer(), issuer) {
			continue
		}
		state, detail, err := r.Resolve(ctx, namespace)
		if err != nil {
			return LivenessResult{
				Namespace: namespace, State: NamespaceUnknown,
				Detail: fmt.Sprintf("could not resolve: %v", err),
			}
		}
		return LivenessResult{Namespace: namespace, State: state, Detail: detail}
	}

	return LivenessResult{
		Namespace: namespace, State: NamespaceUnknown,
		Detail: "no resolver is configured for this issuer",
	}
}

// issuerMatches compares issuers ignoring scheme and trailing slash, which
// providers store inconsistently.
func issuerMatches(a, b string) bool {
	norm := func(v string) string {
		v = strings.TrimPrefix(strings.TrimPrefix(v, "https://"), "http://")
		return strings.TrimSuffix(v, "/")
	}
	return strings.EqualFold(norm(a), norm(b))
}

// IsRenameFragile reports whether a GitHub subject uses the legacy format, which
// stops matching the first time the repository is renamed or transferred.
//
// GitHub's immutable subject enforcement applies to any renamed or transferred
// repository, not only to new ones. That makes this a scheduled outage nobody
// has scheduled: the trust works until somebody renames a repo, and the change
// that breaks it looks nothing like an authentication change.
func IsRenameFragile(issuer, subject string) bool {
	if !issuerMatches(issuer, "token.actions.githubusercontent.com") {
		return false
	}
	if !strings.HasPrefix(subject, "repo:") {
		return false
	}
	repoPart := strings.TrimPrefix(subject, "repo:")
	if i := strings.Index(repoPart, ":"); i >= 0 {
		repoPart = repoPart[:i]
	}
	if strings.ContainsAny(repoPart, "*?") {
		// A wildcard survives a rename by construction; breadth is its problem.
		return false
	}
	// The immutable form carries numeric ids after "@".
	return !strings.Contains(repoPart, "@")
}

// InventorySource enumerates the federated trust relationships in one cloud.
//
// Like TrustPolicySource, this inverts the dependency so core stays a leaf: the
// implementations live provider-side and are injected.
type InventorySource interface {
	// InventoryCloud reports which cloud this source enumerates.
	InventoryCloud() Cloud
	// ListTrustRecords enumerates every identity with an external federated
	// trust. Breadth and Liveness are left zero; BuildInventory fills them.
	ListTrustRecords(ctx context.Context) ([]TrustRecord, error)
}

// BuildInventory enumerates, scores and resolves every trust relationship.
//
// A source that fails does not abort the others: a missing GCP credential must
// not hide the AWS findings. The failures are returned alongside the records so
// the caller can report an inventory as INCOMPLETE rather than silently short.
func BuildInventory(ctx context.Context, sources []InventorySource, resolvers []NamespaceResolver) ([]TrustRecord, []error) {
	var records []TrustRecord
	var failures []error

	for _, s := range sources {
		found, err := s.ListTrustRecords(ctx)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", s.InventoryCloud(), err))
			continue
		}
		for _, r := range found {
			r.Breadth = ScoreSubject(r.SubjectCondition)
			r.Liveness = ResolveLiveness(ctx, r.Issuer, r.SubjectCondition, resolvers)
			r.RenameFragile = IsRenameFragile(r.Issuer, r.SubjectCondition)
			records = append(records, r)
		}
	}
	return records, failures
}
