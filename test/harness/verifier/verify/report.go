package verify

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
)

// Process exit codes. The driver branches on these.
const (
	// ExitOK means every selected case passed.
	ExitOK = 0
	// ExitFailure means at least one case failed.
	ExitFailure = 1
	// ExitUsage means the verifier could not run at all (bad plan, no runtime).
	ExitUsage = 2
)

// Status is the outcome of a single case.
type Status string

const (
	StatusPass Status = "pass"
	StatusFail Status = "fail"
	StatusSkip Status = "skip"
)

// ProbeStatus is the outcome of the optional post-exchange credential probe.
// A probe never fails a case by itself (unless -probe-strict): it is corroborating
// evidence, and the harness must not go red because a probe is unimplemented.
type ProbeStatus string

const (
	ProbeNotRequested  ProbeStatus = "not-requested"
	ProbeOK            ProbeStatus = "ok"
	ProbeSoftFail      ProbeStatus = "soft-fail"
	ProbeUnimplemented ProbeStatus = "unimplemented"
)

// errSummary bounds.
const (
	maxErrSummary   = 512
	truncatedMarker = "…(truncated)"
)

// Identity is the non-secret metadata proving *which* identity was exchanged.
// Everything here is safe to log; credential material never appears.
type Identity struct {
	Issuer               string `json:"issuer,omitempty"`
	Subject              string `json:"subject,omitempty"`
	SourceCloud          string `json:"source_cloud,omitempty"`
	SourceSubRuntime     string `json:"source_sub_runtime,omitempty"`
	Role                 string `json:"role,omitempty"`
	WorkloadIdentityPool string `json:"workload_identity_pool,omitempty"`
	Tenant               string `json:"tenant,omitempty"`
	ClientID             string `json:"client_id,omitempty"`
	Audience             string `json:"audience,omitempty"`
	STSRequestID         string `json:"sts_request_id,omitempty"`
	CredentialsExpireAt  string `json:"credentials_expire_at,omitempty"`
}

// ProbeResult records the optional credential probe.
type ProbeResult struct {
	Name       string      `json:"name,omitempty"`
	Status     ProbeStatus `json:"status"`
	Detail     string      `json:"detail,omitempty"`
	DurationMS int64       `json:"duration_ms,omitempty"`
}

// CaseResult is one row of the machine-readable report.
type CaseResult struct {
	Name            string `json:"name"`
	SourceRuntime   string `json:"source_runtime"`
	TargetCloud     string `json:"target_cloud"`
	Expect          string `json:"expect"`
	ExpectError     string `json:"expect_error,omitempty"`
	Status          Status `json:"status"`
	DurationMS      int64  `json:"duration_ms"`
	Error           string `json:"error,omitempty"`
	MatchedSentinel string `json:"matched_sentinel,omitempty"`
	// Note carries non-fatal context, e.g. the guidance text that accompanied
	// an expected sentinel failure.
	Note     string      `json:"note,omitempty"`
	Identity Identity    `json:"identity"`
	Probe    ProbeResult `json:"probe"`
}

// Summary aggregates the run.
type Summary struct {
	Total               int `json:"total"`
	Passed              int `json:"passed"`
	Failed              int `json:"failed"`
	Skipped             int `json:"skipped"`
	SoftProbeFailures   int `json:"soft_probe_failures"`
	ProbesUnimplemented int `json:"probes_unimplemented"`
}

// RuntimeInfo is the detected runtime, as reported.
type RuntimeInfo struct {
	Cloud       string `json:"cloud"`
	SubRuntime  string `json:"sub_runtime"`
	Federatable bool   `json:"federatable"`
	Issuer      string `json:"issuer,omitempty"`
	Subject     string `json:"subject,omitempty"`
}

// ReportSchemaVersion versions the stdout contract for the driver.
const ReportSchemaVersion = 1

// Report is the document the verifier writes to stdout.
type Report struct {
	SchemaVersion  int          `json:"schema_version"`
	RunID          string       `json:"run_id,omitempty"`
	DetectedKey    string       `json:"detected_runtime"`
	Detected       *RuntimeInfo `json:"detected,omitempty"`
	StartedAt      time.Time    `json:"started_at"`
	DurationMS     int64        `json:"duration_ms"`
	Summary        Summary      `json:"summary"`
	Results        []CaseResult `json:"results"`
	Notes          []string     `json:"notes,omitempty"`
	CredentialsNot string       `json:"credentials_note"`
}

// credentialsNote states, in the artifact itself, the security property the
// harness contract requires of this output.
const credentialsNote = "no credential, token, or assertion values appear in this report; identity metadata only"

// BuildReport assembles the report from finished case results.
func BuildReport(runID, detectedKey string, rt *cloudauth.Runtime, results []CaseResult, startedAt time.Time, total time.Duration) Report {
	var info *RuntimeInfo
	if rt != nil {
		info = &RuntimeInfo{
			Cloud:       string(rt.Cloud),
			SubRuntime:  rt.SubRuntime,
			Federatable: rt.Federatable,
			Issuer:      rt.Issuer,
			Subject:     rt.Subject,
		}
	}
	if results == nil {
		results = []CaseResult{}
	}
	return Report{
		SchemaVersion:  ReportSchemaVersion,
		RunID:          runID,
		DetectedKey:    detectedKey,
		Detected:       info,
		StartedAt:      startedAt.UTC(),
		DurationMS:     total.Milliseconds(),
		Summary:        summarize(results),
		Results:        results,
		CredentialsNot: credentialsNote,
	}
}

// summarize counts outcomes.
func summarize(results []CaseResult) Summary {
	s := Summary{Total: len(results)}
	for _, r := range results {
		switch r.Status {
		case StatusPass:
			s.Passed++
		case StatusFail:
			s.Failed++
		case StatusSkip:
			s.Skipped++
		}
		switch r.Probe.Status {
		case ProbeSoftFail:
			s.SoftProbeFailures++
		case ProbeUnimplemented:
			s.ProbesUnimplemented++
		}
	}
	return s
}

// ExitCode is ExitFailure when any case failed, else ExitOK.
func (r Report) ExitCode() int {
	if r.Summary.Failed > 0 {
		return ExitFailure
	}
	return ExitOK
}

// WriteJSON renders the machine-readable report. The rendered bytes get a final
// scrub pass so a future field cannot leak by being forgotten at build time.
func (r Report) WriteJSON(w io.Writer, s *Scrubber) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("verify: rendering report: %w", err)
	}
	if s != nil {
		b = s.ScrubBytes(b)
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

// WriteHuman renders the operator-facing summary (stderr).
func (r Report) WriteHuman(w io.Writer, s *Scrubber) {
	scrub := func(v string) string {
		if s == nil {
			return v
		}
		return s.Scrub(v)
	}
	fmt.Fprintf(w, "\ncloud-auth verifier — runtime %s", orNone(r.DetectedKey))
	if r.RunID != "" {
		fmt.Fprintf(w, " — run %s", scrub(r.RunID))
	}
	fmt.Fprintf(w, "\n%s\n", strings.Repeat("-", 60))

	for _, c := range r.Results {
		fmt.Fprintf(w, "  %s %-28s → %-5s  %s  (%dms)\n",
			symbol(c.Status), scrub(c.Name), c.TargetCloud, c.Status, c.DurationMS)
		if c.MatchedSentinel != "" {
			fmt.Fprintf(w, "      expected failure matched %s\n", c.MatchedSentinel)
		}
		if c.Note != "" {
			fmt.Fprintf(w, "      %s\n", scrub(c.Note))
		}
		if id := identityLine(c.Identity); id != "" {
			fmt.Fprintf(w, "      %s\n", scrub(id))
		}
		if c.Probe.Status != ProbeNotRequested && c.Probe.Status != "" {
			fmt.Fprintf(w, "      probe %s: %s %s\n", c.Probe.Name, c.Probe.Status, scrub(c.Probe.Detail))
		}
		if c.Error != "" {
			fmt.Fprintf(w, "      %s\n", scrub(c.Error))
		}
	}

	fmt.Fprintf(w, "%s\n", strings.Repeat("-", 60))
	fmt.Fprintf(w, "  %d passed, %d failed, %d skipped", r.Summary.Passed, r.Summary.Failed, r.Summary.Skipped)
	if r.Summary.SoftProbeFailures > 0 || r.Summary.ProbesUnimplemented > 0 {
		fmt.Fprintf(w, " (probes: %d soft-fail, %d unimplemented — not counted as failures)",
			r.Summary.SoftProbeFailures, r.Summary.ProbesUnimplemented)
	}
	fmt.Fprintf(w, "\n")
	for _, n := range r.Notes {
		fmt.Fprintf(w, "  note: %s\n", scrub(n))
	}
}

func identityLine(id Identity) string {
	var parts []string
	add := func(k, v string) {
		if v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	add("issuer", id.Issuer)
	add("subject", id.Subject)
	add("role", id.Role)
	add("pool", id.WorkloadIdentityPool)
	add("client_id", id.ClientID)
	add("sts_request_id", id.STSRequestID)
	add("expires", id.CredentialsExpireAt)
	return strings.Join(parts, " ")
}

func symbol(s Status) string {
	switch s {
	case StatusPass:
		return "✓"
	case StatusSkip:
		return "-"
	default:
		return "✗"
	}
}

func orNone(s string) string {
	if s == "" {
		return "(undetected)"
	}
	return s
}

// errSummary flattens an error into a single bounded line, so one enormous STS
// body cannot drown the report.
func errSummary(err error) string {
	if err == nil {
		return ""
	}
	s := strings.Join(strings.Fields(err.Error()), " ")
	if len(s) > maxErrSummary {
		s = s[:maxErrSummary] + truncatedMarker
	}
	return s
}
