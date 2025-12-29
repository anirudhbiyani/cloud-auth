package cloudauth

import (
	"context"
)

// Mechanism represents a cross-cloud authentication configuration instance.
// A mechanism encapsulates all the resources and configuration needed for
// one identity to assume another identity across cloud boundaries.
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
// Each mechanism type has its own concrete spec type implementing this interface.
type MechanismSpec interface {
	// Type returns the mechanism type this spec configures.
	Type() MechanismType

	// Validate validates the spec fields.
	Validate() error

	// SourceProvider returns the source identity's cloud provider.
	SourceProvider() CloudProvider

	// TargetProvider returns the target identity's cloud provider.
	TargetProvider() CloudProvider
}

// MechanismManager provides lifecycle operations for mechanisms.
// This is the primary interface for managing cross-cloud authentication.
type MechanismManager interface {
	// Setup creates or updates a mechanism based on the provided specification.
	// If DryRun is set in options, returns a Plan without making changes.
	//
	// Setup is designed to be idempotent: calling it multiple times with the
	// same spec should result in the same end state.
	Setup(ctx context.Context, spec MechanismSpec, opts SetupOptions) (*Outputs, error)

	// Validate checks if a mechanism is correctly configured and functional.
	// Returns a detailed ValidationReport with individual check results.
	Validate(ctx context.Context, ref MechanismRef, opts ValidateOptions) (*ValidationReport, error)

	// Delete removes a mechanism and its associated resources.
	// By default, only deletes resources that were created by cloud-auth (owned).
	// Set Force to delete non-owned resources.
	//
	// Delete is designed to be idempotent: calling it on an already-deleted
	// mechanism should succeed without error.
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
	Provider CloudProvider

	// Tags filters by tag key-value pairs.
	Tags map[string]string

	// Limit is the maximum number of results to return.
	Limit int

	// Offset is the starting index for pagination.
	Offset int
}

// Provider is the base interface for cloud provider implementations.
// Providers handle authentication and API interactions with a specific cloud.
type Provider interface {
	// Name returns the provider identifier.
	Name() CloudProvider

	// Capabilities returns the features supported by this provider.
	Capabilities() []Capability

	// HasCapability checks if the provider supports a specific capability.
	HasCapability(cap Capability) bool
}

// TokenProvider extends Provider with token acquisition capability.
// This maintains backward compatibility with existing Token(...) flows.
type TokenProvider interface {
	Provider

	// Token acquires a token for accessing the target identity.
	// This is the existing token acquisition flow.
	Token(ctx context.Context, req TokenRequest) (*TokenResponse, error)
}

// TokenRequest contains parameters for token acquisition.
type TokenRequest struct {
	// SourceIdentity is the identity making the request.
	SourceIdentity string

	// TargetIdentity is the identity to assume.
	TargetIdentity string

	// Audience is the intended audience for the token.
	Audience string

	// Scopes are the requested permission scopes.
	Scopes []string

	// Duration is the requested token lifetime.
	Duration int
}

// TokenResponse contains an acquired token and metadata.
type TokenResponse struct {
	// Token is the authentication token.
	Token string

	// ExpiresAt is when the token expires.
	ExpiresAt int64

	// TokenType is the token type (e.g., "Bearer").
	TokenType string

	// Scopes are the granted permission scopes.
	Scopes []string
}

// LifecycleProvider extends Provider with mechanism lifecycle operations.
// Providers that can create, validate, and delete mechanisms implement this.
type LifecycleProvider interface {
	Provider

	// Setup creates or updates mechanism resources.
	Setup(ctx context.Context, spec MechanismSpec, opts SetupOptions) (*Outputs, error)

	// Validate checks mechanism configuration.
	Validate(ctx context.Context, ref MechanismRef, opts ValidateOptions) (*ValidationReport, error)

	// Delete removes mechanism resources.
	Delete(ctx context.Context, ref MechanismRef, opts DeleteOptions) error
}

// ProviderFactory creates provider instances.
type ProviderFactory interface {
	// Create creates a new provider instance with the given configuration.
	Create(ctx context.Context, config map[string]interface{}) (Provider, error)
}

