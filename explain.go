package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/anirudhbiyani/cloud-auth/core"
	awsprovider "github.com/anirudhbiyani/cloud-auth/provider/aws"
	gcpprovider "github.com/anirudhbiyani/cloud-auth/provider/gcp"
)

// The I/O half of `doctor --explain`.

// trustForTarget reads the live trust configuration a target's exchange will be evaluated against.
func trustForTarget(ctx context.Context, target core.Target) (*core.TrustPolicy, error) {
	switch t := target.(type) {
	case core.AWSTarget:
		roleName, err := roleNameFromARN(t.RoleARN)
		if err != nil {
			return nil, err
		}
		return awsprovider.New().TrustPolicy(ctx, core.MechanismRef{
			ID:          t.RoleARN,
			Provider:    core.AWS,
			ResourceIDs: map[string]string{"role_name": roleName},
		})

	case core.GCPTarget:
		providerName := strings.TrimPrefix(t.WorkloadIdentityPool, "//iam.googleapis.com/")
		if !strings.Contains(providerName, "/providers/") {
			return nil, fmt.Errorf("--explain needs the pool PROVIDER resource name "+
				"(…/workloadIdentityPools/<pool>/providers/<provider>), got %q", t.WorkloadIdentityPool)
		}
		return gcpprovider.New().TrustPolicy(ctx, core.MechanismRef{
			ID:          providerName,
			Provider:    core.GCP,
			ResourceIDs: map[string]string{"provider_name": providerName},
		})

	case core.AzureTarget:
		// Reading a federated identity credential needs the application's OBJECT id, and an AzureTarget carries its client id — a different identifier, resolvable only through a Graph lookup this command does not do.
		return nil, fmt.Errorf("--explain cannot read Azure trust from a runtime target: "+
			"a federated identity credential is addressed by the application's object id, and "+
			"--client-id %s is the client id. Use `cloud-auth validate --ref <mechanism>` on a "+
			"mechanism this tool created", t.ClientID)

	default:
		return nil, fmt.Errorf("--explain does not support %T", target)
	}
}

// roleNameFromARN extracts the role name, including any path.
func roleNameFromARN(arn string) (string, error) {
	i := strings.Index(arn, ":role/")
	if i < 0 {
		return "", fmt.Errorf("--explain needs an IAM role ARN, got %q", arn)
	}
	name := arn[i+len(":role/"):]
	if name == "" {
		return "", fmt.Errorf("role ARN %q names no role", arn)
	}
	// A path is part of the role's identity but not its name.
	if j := strings.LastIndex(name, "/"); j >= 0 {
		name = name[j+1:]
	}
	return name, nil
}

// writeExplanation renders the findings.
func writeExplanation(w io.Writer, trust *core.TrustPolicy, findings []core.Finding, trustErr error) {
	if trustErr != nil {
		// A failure to READ the trust is not a finding about the trust, and must never render as "no problems found".
		fmt.Fprintf(w, "\n⚠ could not read the target's trust configuration, so nothing below was\n"+
			"  compared against it: %v\n", trustErr)
		return
	}
	if trust == nil {
		return
	}

	fmt.Fprintf(w, "\nLive trust configuration:\n")
	if trust.Issuer != "" {
		fmt.Fprintf(w, "  issuer:     %s\n", trust.Issuer)
	}
	for _, c := range trust.Conditions {
		fmt.Fprintf(w, "  %-10s %s %q\n", c.Claim+":", c.Operator, c.Value)
	}
	if len(trust.Conditions) == 0 {
		fmt.Fprintf(w, "  (no conditions on aud or sub — this trust admits every identity its\n"+
			"   issuer will mint a token for)\n")
	}

	if len(findings) == 0 {
		fmt.Fprintf(w, "\n✓ every claim this token presents matches the trust configuration\n")
		return
	}

	fmt.Fprintf(w, "\n%d finding(s):\n", len(findings))
	for _, f := range findings {
		fmt.Fprintf(w, "\n  %s %s\n", severityMark(f.Severity), f.Summary)
		if f.Claim != "" && (f.Presented != "" || f.Configured != "") {
			fmt.Fprintf(w, "      claim:      %s\n", f.Claim)
			fmt.Fprintf(w, "      presented:  %s\n", quoteOrNone(f.Presented))
			fmt.Fprintf(w, "      configured: %s\n", quoteOrNone(f.Configured))
		}
		fmt.Fprintf(w, "      fix:        %s\n", wrapFix(f.Fix, 74, "                  "))
	}
}

func severityMark(s core.FindingSeverity) string {
	switch s {
	case core.FindingCritical:
		return "✗"
	case core.FindingWarning:
		return "⚠"
	default:
		return "•"
	}
}

func quoteOrNone(v string) string {
	if v == "" {
		return "(absent)"
	}
	return fmt.Sprintf("%q", v)
}

// wrapFix hard-wraps remediation text, which is long by design — a fix that fits on one line is usually not a fix.
func wrapFix(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return s
	}
	var b strings.Builder
	lineLen := 0
	for i, w := range words {
		if i > 0 {
			if lineLen+1+len(w) > width {
				b.WriteString("\n" + indent)
				lineLen = 0
			} else {
				b.WriteString(" ")
				lineLen++
			}
		}
		b.WriteString(w)
		lineLen += len(w)
	}
	return b.String()
}

// doctorReport is the --format json shape.
type doctorReport struct {
	Runtime  *runtimeReport `json:"runtime"`
	Target   *targetReport  `json:"target,omitempty"`
	Checks   []checkReport  `json:"checks"`
	Trust    *trustReport   `json:"trust,omitempty"`
	Findings []core.Finding `json:"findings"`
	TrustErr string         `json:"trust_error,omitempty"`
	Complete bool           `json:"complete"`
}

type runtimeReport struct {
	Cloud       string `json:"cloud,omitempty"`
	SubRuntime  string `json:"sub_runtime,omitempty"`
	Federatable bool   `json:"federatable"`
	Subject     string `json:"subject,omitempty"`
	Issuer      string `json:"issuer,omitempty"`
	Error       string `json:"error,omitempty"`
}

type targetReport struct {
	Cloud    string `json:"cloud"`
	Audience string `json:"audience,omitempty"`
}

type checkReport struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

type trustReport struct {
	Issuer     string                `json:"issuer,omitempty"`
	Conditions []core.TrustCondition `json:"conditions"`
}

// writeDoctorJSON renders the report as a single JSON document.
func writeDoctorJSON(w io.Writer, p preflight, diagnoses []diagnosis,
	trust *core.TrustPolicy, findings []core.Finding, trustErr error) error {

	report := doctorReport{
		Checks:   make([]checkReport, 0, len(diagnoses)),
		Findings: findings,
		// Complete says whether everything that was asked for actually ran.
		Complete: trustErr == nil,
	}
	if report.Findings == nil {
		report.Findings = []core.Finding{} // [] rather than null
	}

	report.Runtime = &runtimeReport{}
	if p.detectErr != nil {
		report.Runtime.Error = p.detectErr.Error()
	}
	if p.runtime != nil {
		report.Runtime.Cloud = string(p.runtime.Cloud)
		report.Runtime.SubRuntime = p.runtime.SubRuntime
		report.Runtime.Federatable = p.runtime.Federatable
		report.Runtime.Subject = p.runtime.Subject
		report.Runtime.Issuer = p.runtime.Issuer
	}
	if p.target != nil && p.target.Cloud() != "" {
		report.Target = &targetReport{
			Cloud:    string(p.target.Cloud()),
			Audience: p.target.Audience(),
		}
	}
	for _, d := range diagnoses {
		report.Checks = append(report.Checks, checkReport{OK: d.ok, Message: d.message})
	}
	if trust != nil {
		report.Trust = &trustReport{Issuer: trust.Issuer, Conditions: trust.Conditions}
		if report.Trust.Conditions == nil {
			report.Trust.Conditions = []core.TrustCondition{}
		}
	}
	if trustErr != nil {
		report.TrustErr = trustErr.Error()
	}

	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding the doctor report: %w", err)
	}
	_, err = fmt.Fprintln(w, string(encoded))
	return err
}
