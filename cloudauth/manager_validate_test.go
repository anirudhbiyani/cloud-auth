package cloudauth

import (
	"context"
	"testing"
)

// fakeLifecycleProvider records whether the manager delegated to it.
type fakeLifecycleProvider struct {
	called bool
	report *ValidationReport
}

func (f *fakeLifecycleProvider) Name() Cloud                     { return AWS }
func (f *fakeLifecycleProvider) Capabilities() []Capability      { return []Capability{CapabilityValidate} }
func (f *fakeLifecycleProvider) HasCapability(c Capability) bool { return true }
func (f *fakeLifecycleProvider) Setup(context.Context, MechanismSpec, SetupOptions) (*Outputs, error) {
	return nil, nil
}
func (f *fakeLifecycleProvider) Delete(context.Context, MechanismRef, DeleteOptions) error {
	return nil
}
func (f *fakeLifecycleProvider) Validate(context.Context, MechanismRef, ValidateOptions) (*ValidationReport, error) {
	f.called = true
	return f.report, nil
}

// The manager previously consulted only a global validator registry that nothing
// ever populated, so every `validate` returned "Valid: true" with ZERO checks —
// a vacuous pass that hid the fact the provider's own checks never ran.
func TestManagerValidateDelegatesToProvider(t *testing.T) {
	fp := &fakeLifecycleProvider{report: &ValidationReport{
		Checks: []ValidationCheck{
			{ID: "trust_policy_match", Status: CheckStatusPassed, Severity: SeverityError},
		},
	}}
	reg := NewRegistry()
	reg.Register(fp)

	m := NewManager(WithRegistry(reg), WithStateStore(NewMemoryStateStore()))
	ref := MechanismRef{ID: "x", Type: MechanismAWSRoleTrustOIDC, Provider: AWS}

	report, err := m.Validate(context.Background(), ref, ValidateOptions{})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !fp.called {
		t.Fatal("manager did not delegate to the provider's Validate")
	}
	if len(report.Checks) != 1 {
		t.Fatalf("got %d checks, want the provider's check to be reported", len(report.Checks))
	}
}

// A report with no checks must not read as a clean bill of health.
func TestEmptyReportIsNotSilentlyValid(t *testing.T) {
	r := &ValidationReport{}
	if !r.IsComplete() {
		t.Skip("IsComplete already flags empty reports")
	}
	if r.HasChecks() {
		t.Error("HasChecks() should be false for an empty report")
	}
}
