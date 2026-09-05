// Package verify holds the cloud-independent core of the harness verifier: the targets.json plan model, runtime self-selection, sentinel-error mapping, the case runner (over an injected exchanger), credential redaction, and the machine-readable report.
package verify

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// Environment variables the verifier reads for its plan.
const (
	// EnvTargetsInline carries the targets.json document itself.
	EnvTargetsInline = "CLOUD_AUTH_TARGETS_JSON"
	// EnvTargetsFile overrides the --targets flag with a path.
	EnvTargetsFile = "CLOUD_AUTH_TARGETS_FILE"
)

// Expect values for a case outcome.
const (
	ExpectSuccess = "success"
	ExpectError   = "error"
)

// Canonical source-runtime keys.
const (
	RuntimeAWSEC2            = "aws-ec2"
	RuntimeAWSECS            = "aws-ecs"
	RuntimeAWSLambda         = "aws-lambda"
	RuntimeAWSEKSIRSA        = "aws-eks-irsa"
	RuntimeAWSEKSPodIdentity = "aws-eks-pod-identity"
	RuntimeGCPGCE            = "gcp-gce"
	RuntimeGCPGKE            = "gcp-gke"
	RuntimeGCPCloudRun       = "gcp-cloud-run"
	RuntimeAzureAKSWI        = "azure-aks-workload-identity"
	RuntimeAzureVM           = "azure-vm"
)

// runtimeAliases maps every spelling the harness may use (contract prose says "AKS-WI", stage-1 outputs say "aks-workload-identity", cloud-auth's own detector says "aks-workload-identity") onto one canonical key.
var runtimeAliases = map[string]string{
	// AWS
	"aws-ec2": RuntimeAWSEC2, "ec2": RuntimeAWSEC2,
	"aws-ecs": RuntimeAWSECS, "ecs": RuntimeAWSECS,
	"aws-lambda": RuntimeAWSLambda, "lambda": RuntimeAWSLambda,
	"aws-eks-irsa": RuntimeAWSEKSIRSA, "eks-irsa": RuntimeAWSEKSIRSA,
	"aws-eks": RuntimeAWSEKSIRSA, "irsa": RuntimeAWSEKSIRSA,
	"aws-eks-pod-identity": RuntimeAWSEKSPodIdentity, "eks-pod-identity": RuntimeAWSEKSPodIdentity,
	// GCP
	"gcp-gce": RuntimeGCPGCE, "gce": RuntimeGCPGCE, "gcp-vm": RuntimeGCPGCE,
	"gcp-gke": RuntimeGCPGKE, "gke": RuntimeGCPGKE,
	"gcp-cloud-run": RuntimeGCPCloudRun, "cloud-run": RuntimeGCPCloudRun,
	// Azure
	"azure-aks-workload-identity": RuntimeAzureAKSWI, "aks-workload-identity": RuntimeAzureAKSWI,
	"azure-aks-wi": RuntimeAzureAKSWI, "aks-wi": RuntimeAzureAKSWI,
	"azure-aks": RuntimeAzureAKSWI, "aks": RuntimeAzureAKSWI,
	"azure-vm": RuntimeAzureVM, "azure-vmss": RuntimeAzureVM,
}

// sentinels maps the names the contract uses in expect_error onto the real sentinel errors.
var sentinels = map[string]error{
	"errnofirstclasspath":     core.ErrNoFirstClassPath,
	"errtrustmissing":         core.ErrTrustMissing,
	"errnonfederatablesource": core.ErrNonFederatableSource,
	"errnotthisruntime":       core.ErrNotThisRuntime,
}

// Plan is the merged state/targets.json the driver produces from the stage-2 outputs of every cloud.
type Plan struct {
	RunID string `json:"run_id"`
	Cases []Case `json:"cases"`
}

// Case is one source→target pair from the matrix.
type Case struct {
	Name string `json:"name"`
	// Expect is "success" or "error".
	Expect string `json:"expect"`
	// ExpectError names the sentinel a case with expect="error" must match, e.g. "ErrNoFirstClassPath" for the documented AWS-EC2→Azure gap.
	ExpectError string `json:"expect_error,omitempty"`
	// SourceRuntime is the canonical runtime this case runs on.
	SourceRuntime string `json:"source_runtime"`
	// Target is the explicit target binding.
	Target TargetSpec `json:"target"`
	// Probe optionally names a post-exchange check that the credentials really work.
	Probe string `json:"probe,omitempty"`
}

// TargetSpec is the JSON form of core.Target.
type TargetSpec struct {
	Cloud    string `json:"cloud"`
	Audience string `json:"audience"`

	// AWS
	Role string `json:"role,omitempty"`

	// GCP (pool | workload_identity_pool | provider are equivalent)
	Pool                 string `json:"pool,omitempty"`
	WorkloadIdentityPool string `json:"workload_identity_pool,omitempty"`
	Provider             string `json:"provider,omitempty"`
	Impersonate          string `json:"impersonate_service_account,omitempty"`

	// Azure
	Tenant   string `json:"tenant,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	Scope    string `json:"scope,omitempty"`
}

// pool returns the workload identity pool/provider under whichever key it came.
func (s TargetSpec) pool() string {
	for _, v := range []string{s.Pool, s.WorkloadIdentityPool, s.Provider} {
		if v != "" {
			return v
		}
	}
	return ""
}

// Target converts the spec into the core binding the broker consumes.
func (s TargetSpec) Target() (core.Target, error) {
	cloud, err := core.ParseFederationTarget(s.Cloud)
	if err != nil {
		return nil, err
	}
	switch cloud {
	case core.AWS:
		return core.AWSTarget{RoleARN: s.Role, TokenAudience: s.Audience}, nil
	case core.GCP:
		return core.GCPTarget{
			WorkloadIdentityPool:      s.pool(),
			ImpersonateServiceAccount: s.Impersonate,
			TokenAudience:             s.Audience,
		}, nil
	case core.Azure:
		return core.AzureTarget{
			Tenant:        s.Tenant,
			ClientID:      s.ClientID,
			TokenAudience: s.Audience,
			Scope:         s.Scope,
		}, nil
	default:
		return nil, fmt.Errorf("verify: unsupported target cloud %q", cloud)
	}
}

// CanonicalRuntime normalizes a source-runtime spelling to its canonical key, returning "" when the value is not a runtime this harness knows about.
func CanonicalRuntime(s string) string {
	k := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), "_", "-")
	return runtimeAliases[k]
}

// RuntimeKey derives the canonical runtime key from cloud-auth's own detection result.
func RuntimeKey(rt *core.Runtime) string {
	if rt == nil {
		return ""
	}
	return CanonicalRuntime(string(rt.Cloud) + "-" + rt.SubRuntime)
}

// SelectCases returns the cases whose source_runtime matches runtime.
func SelectCases(cases []Case, runtime string) []Case {
	key := CanonicalRuntime(runtime)
	if key == "" {
		return nil
	}
	var out []Case
	for _, c := range cases {
		if CanonicalRuntime(c.SourceRuntime) == key {
			out = append(out, c)
		}
	}
	return out
}

// SentinelFor maps an expect_error name to the sentinel error it denotes.
func SentinelFor(name string) (error, bool) {
	err, ok := sentinels[strings.ToLower(strings.TrimSpace(name))]
	return err, ok
}

// SentinelNames lists the accepted expect_error values, for error messages.
func SentinelNames() []string {
	return []string{"ErrNoFirstClassPath", "ErrTrustMissing", "ErrNonFederatableSource", "ErrNotThisRuntime"}
}

// LoadPlan parses and validates a targets.json document.
func LoadPlan(data []byte) (*Plan, error) {
	var p Plan
	// Unknown keys are tolerated: the driver may add provenance fields, and a stricter decode would couple the verifier to the driver's bookkeeping.
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("verify: parsing targets.json: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate checks the plan is internally consistent and executable.
func (p *Plan) Validate() error {
	if len(p.Cases) == 0 {
		return errors.New("verify: targets.json has no cases")
	}
	seen := make(map[string]bool, len(p.Cases))
	for i, c := range p.Cases {
		if err := c.Validate(); err != nil {
			return fmt.Errorf("verify: case %d %q: %w", i, c.Name, err)
		}
		if seen[c.Name] {
			return fmt.Errorf("verify: duplicate case name %q", c.Name)
		}
		seen[c.Name] = true
	}
	return nil
}

// Validate checks a single case.
func (c Case) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return errors.New("name is required")
	}
	if CanonicalRuntime(c.SourceRuntime) == "" {
		return fmt.Errorf("unknown source_runtime %q", c.SourceRuntime)
	}
	switch c.Expect {
	case ExpectSuccess:
		if c.ExpectError != "" {
			return errors.New("expect_error is meaningless with expect=success")
		}
	case ExpectError:
		if c.ExpectError == "" {
			return fmt.Errorf("expect=error requires expect_error (one of %s)",
				strings.Join(SentinelNames(), ", "))
		}
		if _, ok := SentinelFor(c.ExpectError); !ok {
			return fmt.Errorf("unknown sentinel %q (want one of %s)",
				c.ExpectError, strings.Join(SentinelNames(), ", "))
		}
	default:
		return fmt.Errorf("expect must be %q or %q, got %q", ExpectSuccess, ExpectError, c.Expect)
	}
	return c.Target.validate()
}

func (s TargetSpec) validate() error {
	cloud, err := core.ParseFederationTarget(s.Cloud)
	if err != nil {
		return fmt.Errorf("target cloud: %w", err)
	}
	if s.Audience == "" {
		return errors.New("target audience is required and must be pinned per target")
	}
	switch cloud {
	case core.AWS:
		if s.Role == "" {
			return errors.New("aws target requires role (the role ARN to assume)")
		}
	case core.GCP:
		if s.pool() == "" {
			return errors.New("gcp target requires pool (the workload identity pool provider)")
		}
	case core.Azure:
		if s.Tenant == "" {
			return errors.New("azure target requires tenant")
		}
		if s.ClientID == "" {
			return errors.New("azure target requires client_id")
		}
	}
	return nil
}

// ErrPlanNotFound means no targets.json was supplied by env or file.
var ErrPlanNotFound = errors.New("verify: no targets.json found")

// ResolvePlan loads the plan from, in order: the inline env document, the env path override, then path.
func ResolvePlan(getenv func(string) string, path string) (*Plan, string, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	if inline := strings.TrimSpace(getenv(EnvTargetsInline)); inline != "" {
		p, err := LoadPlan([]byte(inline))
		return p, "$" + EnvTargetsInline, err
	}
	if p := strings.TrimSpace(getenv(EnvTargetsFile)); p != "" {
		path = p
	}
	if path == "" {
		return nil, "", ErrPlanNotFound
	}
	// #nosec G304 -- plan path is supplied by the harness driver (--targets).
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, path, fmt.Errorf("%w: %s (set $%s or $%s)", ErrPlanNotFound, path, EnvTargetsInline, EnvTargetsFile)
	}
	if err != nil {
		return nil, path, fmt.Errorf("verify: reading %s: %w", path, err)
	}
	plan, err := LoadPlan(data)
	return plan, path, err
}
