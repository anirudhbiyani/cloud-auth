package core

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
)

type stubValidator struct{ id string }

func (s stubValidator) ID() string          { return s.id }
func (s stubValidator) Name() string        { return s.id }
func (s stubValidator) Description() string { return s.id }
func (s stubValidator) Validate(context.Context, MechanismRef) ValidationCheck {
	return ValidationCheck{ID: s.id, Status: CheckStatusPassed}
}

// This used to be "fatal error: concurrent map read and map write" — a runtime
// abort that recover() cannot catch, in a package whose registry is documented
// as the extension point providers register into from init().
func TestValidatorRegistryIsSafeForConcurrentUse(t *testing.T) {
	r := NewValidatorRegistry()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(3)
		go func(i int) {
			defer wg.Done()
			_ = r.Register(stubValidator{id: fmt.Sprintf("v%d", i)}, MechanismAWSRoleTrustOIDC)
		}(i)
		go func() {
			defer wg.Done()
			_ = r.GetForType(MechanismAWSRoleTrustOIDC)
		}()
		go func(i int) {
			defer wg.Done()
			_, _ = r.Get(fmt.Sprintf("v%d", i))
		}(i)
	}
	wg.Wait()

	if got := len(r.GetForType(MechanismAWSRoleTrustOIDC)); got != 100 {
		t.Errorf("registered %d validators, want 100", got)
	}
}

// A silent overwrite made which checks actually run depend on init() ordering.
func TestValidatorRegistryRejectsDuplicates(t *testing.T) {
	r := NewValidatorRegistry()
	if err := r.Register(stubValidator{id: "dup"}, MechanismAWSRoleTrustOIDC); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	err := r.Register(stubValidator{id: "dup"}, MechanismAWSRoleTrustOIDC)
	if err == nil {
		t.Fatal("want an error on a duplicate ID")
	}
	if !strings.Contains(err.Error(), "already registered") {
		t.Errorf("unexpected error: %v", err)
	}
	if got := len(r.GetForType(MechanismAWSRoleTrustOIDC)); got != 1 {
		t.Errorf("a rejected duplicate must not be indexed; got %d entries", got)
	}
}

func TestValidatorRegistryRejectsUnusableValidators(t *testing.T) {
	r := NewValidatorRegistry()
	if err := r.Register(nil); err == nil {
		t.Error("want an error for a nil validator")
	}
	if err := r.Register(stubValidator{id: ""}); err == nil {
		t.Error("want an error for a validator with no ID")
	}
}

// A returned slice must not alias the registry's backing array, or a caller's
// append races a concurrent Register.
func TestGetForTypeReturnsAnIndependentSlice(t *testing.T) {
	r := NewValidatorRegistry()
	for i := 0; i < 3; i++ {
		if err := r.Register(stubValidator{id: fmt.Sprintf("v%d", i)}, MechanismAWSRoleTrustOIDC); err != nil {
			t.Fatal(err)
		}
	}
	first := r.GetForType(MechanismAWSRoleTrustOIDC)
	first = append(first, stubValidator{id: "intruder"})
	_ = first

	if got := len(r.GetForType(MechanismAWSRoleTrustOIDC)); got != 3 {
		t.Errorf("the registry was mutated through a returned slice; got %d entries", got)
	}
}
