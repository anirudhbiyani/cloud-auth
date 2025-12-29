package cloudauth

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// StateStore provides persistent storage for mechanism references and ownership tracking.
// This enables safe deletion (only delete resources we created) and idempotency.
type StateStore interface {
	// Save stores a mechanism reference.
	Save(ctx context.Context, ref MechanismRef) error

	// Get retrieves a mechanism reference by ID.
	Get(ctx context.Context, id string) (*MechanismRef, error)

	// List returns all stored mechanism references matching the filter.
	List(ctx context.Context, filter ListFilter) ([]MechanismRef, error)

	// Delete removes a mechanism reference from the store.
	Delete(ctx context.Context, id string) error

	// Exists checks if a mechanism reference exists.
	Exists(ctx context.Context, id string) (bool, error)

	// UpdateOwnership updates the ownership status of a mechanism.
	UpdateOwnership(ctx context.Context, id string, owned bool) error
}

// StateStoreVersion is the current schema version for state storage.
const StateStoreVersion = 1

// StateData is the serializable state format.
type StateData struct {
	Version    int                     `json:"version"`
	Mechanisms map[string]MechanismRef `json:"mechanisms"`
	UpdatedAt  time.Time               `json:"updated_at"`
}

// MemoryStateStore is an in-memory StateStore implementation for testing.
type MemoryStateStore struct {
	mu    sync.RWMutex
	state StateData
}

// NewMemoryStateStore creates a new in-memory state store.
func NewMemoryStateStore() *MemoryStateStore {
	return &MemoryStateStore{
		state: StateData{
			Version:    StateStoreVersion,
			Mechanisms: make(map[string]MechanismRef),
			UpdatedAt:  time.Now(),
		},
	}
}

// Save implements StateStore.
func (s *MemoryStateStore) Save(ctx context.Context, ref MechanismRef) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state.Mechanisms[ref.ID] = ref
	s.state.UpdatedAt = time.Now()
	return nil
}

// Get implements StateStore.
func (s *MemoryStateStore) Get(ctx context.Context, id string) (*MechanismRef, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ref, exists := s.state.Mechanisms[id]
	if !exists {
		return nil, ErrNotFound("mechanism", id)
	}
	return &ref, nil
}

// List implements StateStore.
func (s *MemoryStateStore) List(ctx context.Context, filter ListFilter) ([]MechanismRef, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var refs []MechanismRef
	for _, ref := range s.state.Mechanisms {
		if filter.Type != "" && ref.Type != filter.Type {
			continue
		}
		if filter.Provider != "" && ref.Provider != filter.Provider {
			continue
		}
		refs = append(refs, ref)
	}

	// Apply pagination
	if filter.Offset > 0 && filter.Offset < len(refs) {
		refs = refs[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(refs) {
		refs = refs[:filter.Limit]
	}

	return refs, nil
}

// Delete implements StateStore.
func (s *MemoryStateStore) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.state.Mechanisms[id]; !exists {
		// Idempotent: deleting non-existent is not an error
		return nil
	}

	delete(s.state.Mechanisms, id)
	s.state.UpdatedAt = time.Now()
	return nil
}

// Exists implements StateStore.
func (s *MemoryStateStore) Exists(ctx context.Context, id string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, exists := s.state.Mechanisms[id]
	return exists, nil
}

// UpdateOwnership implements StateStore.
func (s *MemoryStateStore) UpdateOwnership(ctx context.Context, id string, owned bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ref, exists := s.state.Mechanisms[id]
	if !exists {
		return ErrNotFound("mechanism", id)
	}

	ref.Owned = owned
	s.state.Mechanisms[id] = ref
	s.state.UpdatedAt = time.Now()
	return nil
}

// FileStateStore is a file-based StateStore implementation.
type FileStateStore struct {
	mu       sync.RWMutex
	filePath string
	state    StateData
}

// NewFileStateStore creates a new file-based state store.
// If the file exists, it loads the existing state.
func NewFileStateStore(filePath string) (*FileStateStore, error) {
	s := &FileStateStore{
		filePath: filePath,
		state: StateData{
			Version:    StateStoreVersion,
			Mechanisms: make(map[string]MechanismRef),
			UpdatedAt:  time.Now(),
		},
	}

	// Try to load existing state
	if err := s.load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to load state: %w", err)
	}

	return s, nil
}

// load reads state from file.
func (s *FileStateStore) load() error {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}

	var state StateData
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("invalid state file format: %w", err)
	}

	// Handle version migration
	if state.Version != StateStoreVersion {
		if err := s.migrate(&state); err != nil {
			return fmt.Errorf("state migration failed: %w", err)
		}
	}

	if state.Mechanisms == nil {
		state.Mechanisms = make(map[string]MechanismRef)
	}

	s.state = state
	return nil
}

// migrate handles schema version upgrades.
func (s *FileStateStore) migrate(state *StateData) error {
	// Currently only version 1, no migration needed
	// Future versions would add migration logic here
	state.Version = StateStoreVersion
	return nil
}

// save writes state to file atomically.
func (s *FileStateStore) save() error {
	s.state.UpdatedAt = time.Now()

	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(s.filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create state directory: %w", err)
	}

	// Write atomically using temp file
	tmpFile := s.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write temp state file: %w", err)
	}

	if err := os.Rename(tmpFile, s.filePath); err != nil {
		os.Remove(tmpFile) // Clean up temp file
		return fmt.Errorf("failed to rename state file: %w", err)
	}

	return nil
}

// Save implements StateStore.
func (s *FileStateStore) Save(ctx context.Context, ref MechanismRef) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state.Mechanisms[ref.ID] = ref
	return s.save()
}

// Get implements StateStore.
func (s *FileStateStore) Get(ctx context.Context, id string) (*MechanismRef, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ref, exists := s.state.Mechanisms[id]
	if !exists {
		return nil, ErrNotFound("mechanism", id)
	}
	return &ref, nil
}

// List implements StateStore.
func (s *FileStateStore) List(ctx context.Context, filter ListFilter) ([]MechanismRef, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var refs []MechanismRef
	for _, ref := range s.state.Mechanisms {
		if filter.Type != "" && ref.Type != filter.Type {
			continue
		}
		if filter.Provider != "" && ref.Provider != filter.Provider {
			continue
		}
		refs = append(refs, ref)
	}

	// Apply pagination
	if filter.Offset > 0 && filter.Offset < len(refs) {
		refs = refs[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(refs) {
		refs = refs[:filter.Limit]
	}

	return refs, nil
}

// Delete implements StateStore.
func (s *FileStateStore) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.state.Mechanisms[id]; !exists {
		return nil // Idempotent
	}

	delete(s.state.Mechanisms, id)
	return s.save()
}

// Exists implements StateStore.
func (s *FileStateStore) Exists(ctx context.Context, id string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, exists := s.state.Mechanisms[id]
	return exists, nil
}

// UpdateOwnership implements StateStore.
func (s *FileStateStore) UpdateOwnership(ctx context.Context, id string, owned bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ref, exists := s.state.Mechanisms[id]
	if !exists {
		return ErrNotFound("mechanism", id)
	}

	ref.Owned = owned
	s.state.Mechanisms[id] = ref
	return s.save()
}

// DefaultStateStorePath returns the default path for the state store file.
func DefaultStateStorePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".cloud-auth", "state.json")
}

