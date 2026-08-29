package core

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// DefaultManager is the default mechanism manager implementation.
type DefaultManager struct {
	registry   *Registry
	stateStore StateStore
	validators *ValidatorRegistry
}

// ManagerOption configures the DefaultManager.
type ManagerOption func(*DefaultManager)

// WithRegistry sets the provider registry.
func WithRegistry(r *Registry) ManagerOption {
	return func(m *DefaultManager) {
		m.registry = r
	}
}

// WithStateStore sets the state store.
func WithStateStore(s StateStore) ManagerOption {
	return func(m *DefaultManager) {
		m.stateStore = s
	}
}

// WithValidators sets the validator registry.
func WithValidators(v *ValidatorRegistry) ManagerOption {
	return func(m *DefaultManager) {
		m.validators = v
	}
}

// NewManager creates a new DefaultManager with the given options.
func NewManager(opts ...ManagerOption) *DefaultManager {
	m := &DefaultManager{
		registry:   DefaultRegistry,
		stateStore: NewMemoryStateStore(),
		validators: DefaultValidators,
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// Setup implements MechanismManager.
func (m *DefaultManager) Setup(ctx context.Context, spec MechanismSpec, opts SetupOptions) (*Outputs, error) {
	// Validate spec
	if err := spec.Validate(); err != nil {
		return nil, ErrValidation(err.Error()).WithOperation("setup")
	}

	// Get the lifecycle provider for the target cloud
	targetProvider := spec.TargetProvider()
	provider, err := m.registry.GetLifecycleProvider(targetProvider)
	if err != nil {
		return nil, err
	}

	// Delegate to provider
	outputs, err := provider.Setup(ctx, spec, opts)
	if err != nil {
		return nil, err
	}

	// Store reference in state store (unless dry-run).
	//
	// A failure here is not cosmetic and must not be printed and forgotten: the
	// cloud resources exist, but nothing records that cloud-auth created them, so
	// Delete will later refuse to remove them as "not owned". Surface it in the
	// Outputs the caller already has to read, since failing outright would be
	// worse — that would hide the identifiers needed to clean up by hand.
	if !opts.DryRun {
		if err := m.stateStore.Save(ctx, outputs.Ref); err != nil {
			outputs.Instructions = append(outputs.Instructions, fmt.Sprintf(
				"WARNING: the resources were created but could not be recorded in the state "+
					"store: %v. `delete` will refuse to remove them as not-owned; either fix the "+
					"state store and re-run setup, or delete them manually. Resource IDs: %v",
				err, outputs.Ref.ResourceIDs))
		}
	}

	return outputs, nil
}

// Validate implements MechanismManager.
func (m *DefaultManager) Validate(ctx context.Context, ref MechanismRef, opts ValidateOptions) (*ValidationReport, error) {
	// Get validators for this mechanism type
	validators := m.validators.GetForType(ref.Type)

	// Filter by requested check IDs if specified
	if len(opts.CheckIDs) > 0 {
		checkSet := make(map[string]bool)
		for _, id := range opts.CheckIDs {
			checkSet[id] = true
		}

		filtered := make([]Validator, 0)
		for _, v := range validators {
			if checkSet[v.ID()] {
				filtered = append(filtered, v)
			}
		}
		validators = filtered
	}

	// Set timeout context if specified
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	// Run any registry-registered validators.
	report := RunValidation(ctx, ref, validators)

	// Delegate to the provider as well.
	//
	// The registry alone is not enough: nothing populates it for the built-in
	// mechanism types, so relying on it made every `validate` return
	// "Valid: true" with zero checks while the provider's real checks — role
	// existence, trust-policy match, attached permissions — never ran at all.
	if provider, err := m.registry.GetLifecycleProvider(ref.Provider); err == nil && provider != nil {
		if pr, perr := provider.Validate(ctx, ref, opts); perr != nil {
			return nil, perr
		} else if pr != nil {
			report.Checks = append(report.Checks, pr.Checks...)
			report.Summary = summarize(report.Checks)
		}
	}

	return report, nil
}

// summarize recomputes the counts after merging provider checks in.
func summarize(checks []ValidationCheck) ValidationSummary {
	var s ValidationSummary
	s.TotalChecks = len(checks)
	for _, c := range checks {
		switch c.Status {
		case CheckStatusPassed:
			s.PassedChecks++
		case CheckStatusFailed:
			s.FailedChecks++
		case CheckStatusSkipped, CheckStatusUnknown:
			s.SkippedChecks++
		}
	}
	s.IsValid = true
	for _, c := range checks {
		if c.Status == CheckStatusFailed && c.Severity.Rank() >= SeverityError.Rank() {
			s.IsValid = false
			break
		}
	}
	return s
}

// Delete implements MechanismManager.
func (m *DefaultManager) Delete(ctx context.Context, ref MechanismRef, opts DeleteOptions) error {
	// Check ownership if OwnedOnly is set (default behavior)
	if opts.OwnedOnly || (!opts.Force && !opts.OwnedOnly) {
		storedRef, err := m.stateStore.Get(ctx, ref.ID)
		if err != nil {
			if IsCategory(err, ErrCategoryNotFound) {
				// Not in our state store - check if Force is set
				if !opts.Force {
					return ErrPermission("mechanism not owned by cloud-auth; use Force to override").
						WithResource("mechanism", ref.ID)
				}
			} else {
				return err
			}
		} else if !storedRef.Owned && !opts.Force {
			return ErrPermission("mechanism not owned by cloud-auth; use Force to override").
				WithResource("mechanism", ref.ID)
		}
	}

	// Get lifecycle provider
	provider, err := m.registry.GetLifecycleProvider(ref.Provider)
	if err != nil {
		return err
	}

	// If confirmation callback is set, build plan and ask for confirmation
	if opts.Confirm != nil && !opts.DryRun {
		// Build deletion plan
		plan := Plan{
			Actions: []PlannedAction{
				{
					Operation:    "delete",
					ResourceType: string(ref.Type),
					ResourceID:   ref.ID,
					Details:      map[string]interface{}{"resource_ids": ref.ResourceIDs},
					Reversible:   false,
				},
			},
			Summary: fmt.Sprintf("Delete mechanism %s and %d associated resources", ref.ID, len(ref.ResourceIDs)),
		}

		if !opts.Confirm(plan) {
			return ErrValidation("deletion cancelled by user")
		}
	}

	// Delegate to provider
	if err := provider.Delete(ctx, ref, opts); err != nil {
		return err
	}

	// Remove from state store. The provider deletion already succeeded, so
	// returning an error here would make a successful delete look failed and
	// invite a retry against resources that are gone — but a stale record is
	// still worth reporting, since it will make future runs behave oddly.
	if !opts.DryRun {
		if err := m.stateStore.Delete(ctx, ref.ID); err != nil {
			return fmt.Errorf("resources deleted, but the state record for %s could not be "+
				"removed (it will show as an existing mechanism until cleaned up): %w", ref.ID, err)
		}
	}

	return nil
}

// Get implements MechanismManager.
func (m *DefaultManager) Get(ctx context.Context, ref MechanismRef) (Mechanism, error) {
	// First check state store
	storedRef, err := m.stateStore.Get(ctx, ref.ID)
	if err != nil {
		return nil, err
	}

	// Return a mechanism wrapper
	return &storedMechanism{
		ref:        *storedRef,
		manager:    m,
		validators: m.validators,
	}, nil
}

// List implements MechanismManager.
func (m *DefaultManager) List(ctx context.Context, filter ListFilter) ([]MechanismRef, error) {
	return m.stateStore.List(ctx, filter)
}

// storedMechanism is a Mechanism backed by a stored reference.
type storedMechanism struct {
	ref        MechanismRef
	spec       MechanismSpec // may be nil if spec wasn't stored
	manager    *DefaultManager
	validators *ValidatorRegistry
}

func (m *storedMechanism) Type() MechanismType {
	return m.ref.Type
}

func (m *storedMechanism) Spec() MechanismSpec {
	return m.spec
}

func (m *storedMechanism) Ref() MechanismRef {
	return m.ref
}

func (m *storedMechanism) Validate(ctx context.Context, opts ValidateOptions) (*ValidationReport, error) {
	return m.manager.Validate(ctx, m.ref, opts)
}

// generateMechanismID generates a unique ID for a mechanism.
func generateMechanismID(mechType MechanismType, provider Cloud) string {
	return fmt.Sprintf("%s-%s-%s", mechType, provider, uuid.New().String()[:8])
}

// CreateMechanismRef creates a new MechanismRef with standard fields populated.
func CreateMechanismRef(mechType MechanismType, provider Cloud, resourceIDs map[string]string) MechanismRef {
	return MechanismRef{
		ID:          generateMechanismID(mechType, provider),
		Type:        mechType,
		Provider:    provider,
		ResourceIDs: resourceIDs,
		CreatedAt:   time.Now(),
		Owned:       true,
		Version:     1,
	}
}

// Top-level convenience functions

// Setup creates a mechanism using the default manager.
func Setup(ctx context.Context, spec MechanismSpec, opts ...SetupOptions) (*Outputs, error) {
	opt := SetupOptions{}
	if len(opts) > 0 {
		opt = opts[0]
	}
	return globalManager.Setup(ctx, spec, opt)
}

// Validate validates a mechanism using the default manager.
func Validate(ctx context.Context, ref MechanismRef, opts ...ValidateOptions) (*ValidationReport, error) {
	opt := ValidateOptions{}
	if len(opts) > 0 {
		opt = opts[0]
	}
	return globalManager.Validate(ctx, ref, opt)
}

// Delete deletes a mechanism using the default manager.
func Delete(ctx context.Context, ref MechanismRef, opts ...DeleteOptions) error {
	opt := DeleteOptions{OwnedOnly: true}
	if len(opts) > 0 {
		opt = opts[0]
	}
	return globalManager.Delete(ctx, ref, opt)
}

// globalManager backs the package-level Setup, Validate and Delete helpers.
//
// It is deliberately not replaceable. The previous SetGlobalManager and
// GetGlobalManager existed to swap process-wide state "useful for testing", which
// meant one test could change which registry and state store every other caller
// saw. Anything needing its own wiring constructs a DefaultManager with
// NewManager and calls it directly — which is what the tests in this repository
// already do.
var globalManager = NewManager()
