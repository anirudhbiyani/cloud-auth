package core

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type failingStore struct{ MemoryStateStore }

func (f *failingStore) Save(context.Context, MechanismRef) error {
	return errors.New("disk full")
}

type stubLifecycle struct{ ref MechanismRef }

func (s *stubLifecycle) Name() Cloud                   { return AWS }
func (s *stubLifecycle) Capabilities() []Capability    { return []Capability{CapabilitySetup} }
func (s *stubLifecycle) HasCapability(Capability) bool { return true }
func (s *stubLifecycle) Setup(context.Context, MechanismSpec, SetupOptions) (*Outputs, error) {
	return &Outputs{Ref: s.ref, Values: map[string]string{"role_arn": "arn:aws:iam::1:role/r"}}, nil
}
func (s *stubLifecycle) Validate(context.Context, MechanismRef, ValidateOptions) (*ValidationReport, error) {
	return &ValidationReport{}, nil
}
func (s *stubLifecycle) Delete(context.Context, MechanismRef, DeleteOptions) error { return nil }

// A state-store failure used to be printed to stdout and forgotten.
func TestSetupReportsAStateStoreFailure(t *testing.T) {
	reg := NewRegistry()
	ref := CreateMechanismRef(MechanismAWSRoleTrustOIDC, AWS,
		map[string]string{"role_name": "deploy"})
	if err := reg.Register(&stubLifecycle{ref: ref}); err != nil {
		t.Fatal(err)
	}
	m := NewManager(WithRegistry(reg), WithStateStore(&failingStore{*NewMemoryStateStore()}))

	spec := &AWSRoleTrustOIDCSpec{
		RoleName: "deploy", AccountID: "123456789012",
		OIDCProviderURL: "https://token.actions.githubusercontent.com",
		Audience:        "sts.amazonaws.com",
		Subject:         "repo:o/r:ref:refs/heads/main",
	}
	out, err := m.Setup(context.Background(), spec, SetupOptions{})
	if err != nil {
		t.Fatalf("Setup should still return the outputs: %v", err)
	}

	joined := strings.Join(out.Instructions, "\n")
	if !strings.Contains(joined, "WARNING") || !strings.Contains(joined, "disk full") {
		t.Errorf("the state-store failure was not reported to the caller: %q", joined)
	}
	// The resource identifiers must survive, or there is no way to clean up.
	if !strings.Contains(joined, "role_name") {
		t.Errorf("instructions should carry the resource IDs for manual cleanup: %q", joined)
	}
}

type slowValidator struct{ id string }

func (s slowValidator) ID() string          { return s.id }
func (s slowValidator) Name() string        { return s.id }
func (s slowValidator) Description() string { return s.id }
func (s slowValidator) Validate(ctx context.Context, _ MechanismRef) ValidationCheck {
	select {
	case <-ctx.Done():
	case <-time.After(50 * time.Millisecond):
	}
	return ValidationCheck{ID: s.id, Status: CheckStatusPassed, Severity: SeverityError}
}

// Each check is a cloud API call.
func TestRunValidationStopsWhenCancelled(t *testing.T) {
	validators := []Validator{
		slowValidator{"one"}, slowValidator{"two"}, slowValidator{"three"}, slowValidator{"four"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	report := RunValidation(ctx, MechanismRef{}, validators)

	if report.Summary.TotalChecks != len(validators) {
		t.Errorf("every validator should appear in the report; got %d of %d",
			report.Summary.TotalChecks, len(validators))
	}
	if report.Summary.SkippedChecks == 0 {
		t.Error("checks that did not run must be recorded as skipped")
	}
	// The whole point: a truncated run must not look complete.
	if report.IsComplete() {
		t.Error("a cancelled validation must not report IsComplete")
	}
}
