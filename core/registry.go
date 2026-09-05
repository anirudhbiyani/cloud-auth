package core

import (
	"fmt"
	"sync"
)

// Registry manages provider registration and discovery.
// It provides thread-safe access to registered providers.
type Registry struct {
	mu        sync.RWMutex
	providers map[Cloud]Provider
}

// DefaultRegistry is the global provider registry.
// Providers register themselves via init() functions.
var DefaultRegistry = NewRegistry()

// NewRegistry creates a new empty registry.
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[Cloud]Provider),
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

// Get retrieves a registered provider by name.
func (r *Registry) Get(name Cloud) (Provider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, exists := r.providers[name]
	if !exists {
		return nil, ErrNotFound("provider", string(name))
	}
	return p, nil
}

// GetLifecycleProvider retrieves a provider that supports lifecycle operations.
func (r *Registry) GetLifecycleProvider(name Cloud) (LifecycleProvider, error) {
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
func (r *Registry) List() []Cloud {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]Cloud, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	return names
}

// Capabilities returns capabilities for a provider.
func (r *Registry) Capabilities(name Cloud) ([]Capability, error) {
	p, err := r.Get(name)
	if err != nil {
		return nil, err
	}
	return p.Capabilities(), nil
}

// Global convenience functions that use DefaultRegistry

// Register adds a provider to the default registry.
func Register(p Provider) error {
	return DefaultRegistry.Register(p)
}

// GetLifecycleProviderFromRegistry retrieves a lifecycle provider from the default registry.
func GetLifecycleProviderFromRegistry(name Cloud) (LifecycleProvider, error) {
	return DefaultRegistry.GetLifecycleProvider(name)
}

// ProviderInfo contains metadata about a registered provider.
type ProviderInfo struct {
	Name         Cloud
	Capabilities []Capability
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
		_, info.IsLifecycle = p.(LifecycleProvider)
		infos = append(infos, info)
	}
	return infos
}
