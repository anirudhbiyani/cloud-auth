package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/anirudhbiyani/cloud-auth/core"
	awsprovider "github.com/anirudhbiyani/cloud-auth/provider/aws"
	azureprovider "github.com/anirudhbiyani/cloud-auth/provider/azure"
	gcpprovider "github.com/anirudhbiyani/cloud-auth/provider/gcp"
	"github.com/anirudhbiyani/cloud-auth/source"
)

// `cloud-auth audit` — the cross-cloud trust inventory.
//
// The question nobody can answer today: which external identities can assume
// anything in any of our clouds. Access Analyzer surfaces federated principals
// without distinguishing repo:org/specific-repo:ref:refs/heads/main from
// repo:org/*; Prowler and ScoutSuite do partial single-cloud trust checks;
// Cloudsplaining covers permissions policies rather than trust policies. Every
// one of them is single-cloud.

// auditOpts are the command's flags.
type auditOpts struct {
	format       string
	failOn       string
	githubOwners []string
	verbose      bool
}

func cmdAudit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	format := fs.String("format", "table", "output format: table|json")
	failOn := fs.String("fail-on", "", "exit non-zero when a finding reaches this severity: critical|warning")
	owners := fs.String("github-owner", "",
		"comma-separated GitHub organisations you control; a namespace outside them is somebody else's")
	verbose := fs.Bool("verbose", false, "diagnostic output on stderr")
	if err := fs.Parse(args); err != nil {
		return err
	}

	opts := &auditOpts{format: *format, failOn: *failOn, verbose: *verbose}
	if *owners != "" {
		for _, o := range strings.Split(*owners, ",") {
			if trimmed := strings.TrimSpace(o); trimmed != "" {
				opts.githubOwners = append(opts.githubOwners, trimmed)
			}
		}
	}

	log := newLogger(opts.verbose)
	log.Info("enumerating federated trust", "clouds", "aws, gcp, azure")

	// Every wired provider that can enumerate. A source that cannot reach its
	// cloud fails on its own and the others still report — which is why the
	// list is unconditional rather than gated on detected credentials.
	sources := []core.InventorySource{
		awsprovider.New(),
		gcpprovider.New(),
		azureprovider.New(),
	}

	resolvers := []core.NamespaceResolver{
		source.NewGitHubNamespaceResolver(source.WithOurGitHubOwners(opts.githubOwners...)),
	}

	records, failures := core.BuildInventory(ctx, sources, resolvers)

	sortRecords(records)

	if opts.format == "json" {
		if err := writeAuditJSON(os.Stdout, records, failures); err != nil {
			return err
		}
	} else {
		writeAuditTable(os.Stdout, records, failures)
	}

	return auditExit(records, failures, opts.failOn)
}

// sortRecords orders worst-first, then by resource so the output is diffable
// between runs.
func sortRecords(records []core.TrustRecord) {
	sort.SliceStable(records, func(i, j int) bool {
		si, sj := records[i].Severity(), records[j].Severity()
		if si != sj {
			return si > sj
		}
		if records[i].Resource != records[j].Resource {
			return records[i].Resource < records[j].Resource
		}
		return records[i].SubjectCondition < records[j].SubjectCondition
	})
}

// auditReport is the --format json shape.
type auditReport struct {
	Records []core.TrustRecord `json:"records"`
	// Incomplete says whether every source was enumerated. A cloud that could
	// not be read makes the inventory short, and short must never read as
	// clean — the same rule validate applies to a skipped check.
	Incomplete bool     `json:"incomplete"`
	Failures   []string `json:"failures,omitempty"`
	Summary    struct {
		Total    int `json:"total"`
		Critical int `json:"critical"`
		Warning  int `json:"warning"`
	} `json:"summary"`
}

func writeAuditJSON(w io.Writer, records []core.TrustRecord, failures []error) error {
	report := auditReport{Records: records, Incomplete: len(failures) > 0}
	if report.Records == nil {
		report.Records = []core.TrustRecord{}
	}
	for _, f := range failures {
		report.Failures = append(report.Failures, f.Error())
	}
	report.Summary.Total = len(records)
	for _, r := range records {
		switch r.Severity() {
		case core.FindingCritical:
			report.Summary.Critical++
		case core.FindingWarning:
			report.Summary.Warning++
		}
	}

	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding the audit report: %w", err)
	}
	_, err = fmt.Fprintln(w, string(encoded))
	return err
}

func writeAuditTable(w io.Writer, records []core.TrustRecord, failures []error) {
	if len(failures) > 0 {
		// Printed FIRST, not appended as a footnote: an inventory missing a
		// cloud is not an inventory, and a reader who stops at the table would
		// otherwise conclude those clouds were clean.
		fmt.Fprintf(w, "⚠ INCOMPLETE — %d cloud(s) could not be enumerated, so nothing below\n"+
			"  says anything about them:\n", len(failures))
		for _, f := range failures {
			fmt.Fprintf(w, "    %v\n", f)
		}
		fmt.Fprintln(w)
	}

	if len(records) == 0 {
		fmt.Fprintln(w, "No federated trust relationships found.")
		return
	}

	fmt.Fprintf(w, "%-6s %-38s %-42s %-9s %-18s\n",
		"SEV", "RESOURCE", "SUBJECT", "BREADTH", "NAMESPACE")
	fmt.Fprintln(w, strings.Repeat("-", 118))

	var critical, warning int
	for _, r := range records {
		switch r.Severity() {
		case core.FindingCritical:
			critical++
		case core.FindingWarning:
			warning++
		}
		fmt.Fprintf(w, "%-6s %-38s %-42s %-9s %-18s\n",
			severityMark(r.Severity()),
			truncate(shortResource(r.Resource), 38),
			truncate(orNone(r.SubjectCondition), 42),
			r.Breadth.Breadth,
			r.Liveness.State)
	}

	fmt.Fprintf(w, "\n%d trust relationship(s): %d critical, %d warning\n",
		len(records), critical, warning)

	// The detail behind every critical row, because a table cell cannot carry
	// "anyone can register this name and assume this role right now".
	for _, r := range records {
		if r.Severity() != core.FindingCritical {
			continue
		}
		fmt.Fprintf(w, "\n%s %s\n", severityMark(r.Severity()), shortResource(r.Resource))
		fmt.Fprintf(w, "    subject:   %s\n", orNone(r.SubjectCondition))
		if r.Liveness.Detail != "" {
			fmt.Fprintf(w, "    namespace: %s — %s\n", r.Liveness.State,
				wrapFix(r.Liveness.Detail, 70, "               "))
		}
		if r.Breadth.Breadth >= core.BreadthHigh {
			fmt.Fprintf(w, "    breadth:   %s — %s\n", r.Breadth.Breadth,
				wrapFix(r.Breadth.Admits, 70, "               "))
		}
	}

	if renameFragile := countRenameFragile(records); renameFragile > 0 {
		fmt.Fprintf(w, "\n%d trust(s) use GitHub's legacy subject format and will break the first\n"+
			"time their repository is renamed or transferred. That enforcement applies to any\n"+
			"renamed or transferred repository, not only to new ones.\n", renameFragile)
	}
}

func countRenameFragile(records []core.TrustRecord) int {
	var n int
	for _, r := range records {
		if r.RenameFragile {
			n++
		}
	}
	return n
}

// shortResource trims an ARN to its recognisable tail.
func shortResource(v string) string {
	if i := strings.Index(v, ":role/"); i >= 0 {
		return "role/" + v[i+len(":role/"):]
	}
	if i := strings.LastIndex(v, "/"); i >= 0 && len(v) > 38 {
		return "…/" + v[i+1:]
	}
	return v
}

func orNone(v string) string {
	if v == "" {
		return "(no subject condition)"
	}
	return v
}

// auditExit maps the inventory onto an exit code.
func auditExit(records []core.TrustRecord, failures []error, failOn string) error {
	if failOn == "" {
		return nil
	}

	var threshold core.FindingSeverity
	switch strings.ToLower(failOn) {
	case "critical":
		threshold = core.FindingCritical
	case "warning":
		threshold = core.FindingWarning
	default:
		return fmt.Errorf("--fail-on %q: want critical or warning", failOn)
	}

	var n int
	for _, r := range records {
		if r.Severity() >= threshold {
			n++
		}
	}
	if n > 0 {
		return errValidationFailed(fmt.Errorf("%d trust relationship(s) at %s severity or above",
			n, threshold))
	}
	// An incomplete inventory must not report success under --fail-on: the
	// clouds that could not be read are exactly where an unseen finding would
	// be, and a green gate over an unread cloud is worse than no gate.
	if len(failures) > 0 {
		return errValidationFailed(fmt.Errorf(
			"nothing reached %s severity, but %d cloud(s) could not be enumerated — "+
				"this inventory is incomplete", threshold, len(failures)))
	}
	return nil
}
