package core

import (
	"context"
)

// Mechanism represents a cross-cloud authentication configuration instance.
type Mechanism interface {
	// Type returns the mechanism type identifier.
	Type() MechanismType

	// Spec returns the specification used to create this mechanism.
	Spec() MechanismSpec

	// Ref returns a stable reference to this mechanism instance.
	Ref() MechanismRef

	// Validate checks if the mechanism is correctly configured.
	Validate(ctx context.Context, opts ValidateOptions) (*ValidationReport, error)
}

// MechanismSpec is the base interface for all mechanism specifications.
type MechanismSpec interface {
	// Type returns the mechanism type this spec configures.
	Type() MechanismType

	// Validate validates the spec fields.
	Validate() error

	// SourceProvider returns the source identity's cloud provider.
	SourceProvider() Cloud

	// TargetProvider returns the target identity's cloud provider.
	TargetProvider() Cloud
}

// MechanismManager provides lifecycle operations for mechanisms.
type MechanismManager interface {
	// Setup creates or updates a mechanism based on the provided specification.
	Setup(ctx context.Context, spec MechanismSpec, opts SetupOptions) (*Outputs, error)

	// Validate checks if a mechanism is correctly configured and functional.
	Validate(ctx context.Context, ref MechanismRef, opts ValidateOptions) (*ValidationReport, error)

	// Delete removes a mechanism and its associated resources.
	Delete(ctx context.Context, ref MechanismRef, opts DeleteOptions) error

	// Get retrieves a mechanism by its reference.
	Get(ctx context.Context, ref MechanismRef) (Mechanism, error)

	// List returns all mechanisms matching the given filter.
	List(ctx context.Context, filter ListFilter) ([]MechanismRef, error)
}

// ListFilter specifies criteria for listing mechanisms.
type ListFilter struct {
	// Type filters by mechanism type.
	Type MechanismType

	// Provider filters by cloud provider.
	Provider Cloud

	// Tags filters by tag key-value pairs.
	Tags map[string]string

	// Limit is the maximum number of results to return.
	Limit int

	// Offset is the starting index for pagination.
	Offset int
}

// Provider is the base interface for cloud provider implementations.
type Provider interface {
	// Name returns the provider identifier.
	Name() Cloud

	// Capabilities returns the features supported by this provider.
	Capabilities() []Capability

	// HasCapability checks if the provider supports a specific capability.
	HasCapability(cap Capability) bool
}

// LifecycleProvider extends Provider with mechanism lifecycle operations.
type LifecycleProvider interface {
	Provider

	// Setup creates or updates mechanism resources.
	Setup(ctx context.Context, spec MechanismSpec, opts SetupOptions) (*Outputs, error)

	// Validate checks mechanism configuration.
	Validate(ctx context.Context, ref MechanismRef, opts ValidateOptions) (*ValidationReport, error)

	// Delete removes mechanism resources.
	Delete(ctx context.Context, ref MechanismRef, opts DeleteOptions) error
}
