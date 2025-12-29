package cloudauth

import (
	"context"
	"fmt"
	"sync"
)

// Registry manages provider registration and discovery.
// It provides thread-safe access to registered providers.
type Registry struct {
	mu        sync.RWMutex
	providers map[CloudProvider]Provider
	factories map[CloudProvider]ProviderFactory
}

// DefaultRegistry is the global provider registry.
// Providers register themselves via init() functions.
var DefaultRegistry = NewRegistry()

// NewRegistry creates a new empty registry.
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[CloudProvider]Provider),
		factories: make(map[CloudProvider]ProviderFactory),
	}
}

// Register adds a provider to the registry.
// This is typically called from provider package init() functions.
func (r *Registry) Register(p Provider) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := p.Name()
	if _, exists := r.providers[name]; exists {
		return fmt.Errorf("provider already registered: %s", name)
	}

	r.providers[name] = p
	return nil
}

// RegisterFactory adds a provider factory to the registry.
// Factories allow lazy/configured provider instantiation.
func (r *Registry) RegisterFactory(name CloudProvider, f ProviderFactory) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.factories[name]; exists {
		return fmt.Errorf("provider factory already registered: %s", name)
	}

	r.factories[name] = f
	return nil
}

// Get retrieves a registered provider by name.
func (r *Registry) Get(name CloudProvider) (Provider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, exists := r.providers[name]
	if !exists {
		return nil, ErrNotFound("provider", string(name))
	}
	return p, nil
}

// GetOrCreate retrieves a provider or creates one using the factory.
func (r *Registry) GetOrCreate(ctx context.Context, name CloudProvider, config map[string]interface{}) (Provider, error) {
	// First try to get existing provider
	r.mu.RLock()
	p, exists := r.providers[name]
	r.mu.RUnlock()

	if exists {
		return p, nil
	}

	// Try to create using factory
	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check after acquiring write lock
	if p, exists = r.providers[name]; exists {
		return p, nil
	}

	factory, exists := r.factories[name]
	if !exists {
		return nil, ErrNotFound("provider or factory", string(name))
	}

	p, err := factory.Create(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create provider %s: %w", name, err)
	}

	r.providers[name] = p
	return p, nil
}

// GetTokenProvider retrieves a provider that supports token acquisition.
func (r *Registry) GetTokenProvider(name CloudProvider) (TokenProvider, error) {
	p, err := r.Get(name)
	if err != nil {
		return nil, err
	}

	tp, ok := p.(TokenProvider)
	if !ok {
		return nil, fmt.Errorf("provider %s does not support token acquisition", name)
	}

	if !tp.HasCapability(CapabilityToken) {
		return nil, fmt.Errorf("provider %s does not have token capability", name)
	}

	return tp, nil
}

// GetLifecycleProvider retrieves a provider that supports lifecycle operations.
func (r *Registry) GetLifecycleProvider(name CloudProvider) (LifecycleProvider, error) {
	p, err := r.Get(name)
	if err != nil {
		return nil, err
	}

	lp, ok := p.(LifecycleProvider)
	if !ok {
		return nil, fmt.Errorf("provider %s does not support lifecycle operations", name)
	}

	return lp, nil
}

// List returns all registered provider names.
func (r *Registry) List() []CloudProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]CloudProvider, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	return names
}

// ListByCapability returns providers that have a specific capability.
func (r *Registry) ListByCapability(cap Capability) []CloudProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var names []CloudProvider
	for name, p := range r.providers {
		if p.HasCapability(cap) {
			names = append(names, name)
		}
	}
	return names
}

// Capabilities returns capabilities for a provider.
func (r *Registry) Capabilities(name CloudProvider) ([]Capability, error) {
	p, err := r.Get(name)
	if err != nil {
		return nil, err
	}
	return p.Capabilities(), nil
}

// Unregister removes a provider from the registry.
// This is mainly useful for testing.
func (r *Registry) Unregister(name CloudProvider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.providers, name)
}

// Clear removes all providers from the registry.
// This is mainly useful for testing.
func (r *Registry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers = make(map[CloudProvider]Provider)
	r.factories = make(map[CloudProvider]ProviderFactory)
}

// Global convenience functions that use DefaultRegistry

// Register adds a provider to the default registry.
func Register(p Provider) error {
	return DefaultRegistry.Register(p)
}

// RegisterFactory adds a provider factory to the default registry.
func RegisterFactory(name CloudProvider, f ProviderFactory) error {
	return DefaultRegistry.RegisterFactory(name, f)
}

// GetProvider retrieves a provider from the default registry.
func GetProvider(name CloudProvider) (Provider, error) {
	return DefaultRegistry.Get(name)
}

// GetTokenProviderFromRegistry retrieves a token provider from the default registry.
func GetTokenProviderFromRegistry(name CloudProvider) (TokenProvider, error) {
	return DefaultRegistry.GetTokenProvider(name)
}

// GetLifecycleProviderFromRegistry retrieves a lifecycle provider from the default registry.
func GetLifecycleProviderFromRegistry(name CloudProvider) (LifecycleProvider, error) {
	return DefaultRegistry.GetLifecycleProvider(name)
}

// ListProviders returns all providers in the default registry.
func ListProviders() []CloudProvider {
	return DefaultRegistry.List()
}

// ProviderInfo contains metadata about a registered provider.
type ProviderInfo struct {
	Name         CloudProvider
	Capabilities []Capability
	IsToken      bool
	IsLifecycle  bool
}

// DescribeProviders returns detailed info about all registered providers.
func DescribeProviders() []ProviderInfo {
	registry := DefaultRegistry
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	var infos []ProviderInfo
	for name, p := range registry.providers {
		info := ProviderInfo{
			Name:         name,
			Capabilities: p.Capabilities(),
		}
		_, info.IsToken = p.(TokenProvider)
		_, info.IsLifecycle = p.(LifecycleProvider)
		infos = append(infos, info)
	}
	return infos
}

