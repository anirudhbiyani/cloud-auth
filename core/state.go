package core

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

// stateStoreVersion is the current schema version for state storage.
const stateStoreVersion = 1

// stateData is the serializable state format.
type stateData struct {
	Version    int                     `json:"version"`
	Mechanisms map[string]MechanismRef `json:"mechanisms"`
	UpdatedAt  time.Time               `json:"updated_at"`
}

// MemoryStateStore is an in-memory StateStore implementation for testing.
type MemoryStateStore struct {
	mu    sync.RWMutex
	state stateData
}

// NewMemoryStateStore creates a new in-memory state store.
func NewMemoryStateStore() *MemoryStateStore {
	return &MemoryStateStore{
		state: stateData{
			Version:    stateStoreVersion,
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
	state    stateData
}

// NewFileStateStore creates a new file-based state store.
// If the file exists, it loads the existing state.
func NewFileStateStore(filePath string) (*FileStateStore, error) {
	s := &FileStateStore{
		filePath: filePath,
		state: stateData{
			Version:    stateStoreVersion,
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

	var state stateData
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("invalid state file format: %w", err)
	}

	// Handle version migration
	if state.Version != stateStoreVersion {
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
func (s *FileStateStore) migrate(state *stateData) error {
	// Currently only version 1, no migration needed
	// Future versions would add migration logic here
	state.Version = stateStoreVersion
	return nil
}

// save writes state to file durably.
//
// The state file records which resources cloud-auth created, and Delete refuses
// to remove anything not listed in it. A lost record therefore does not just
// lose information: it makes a real cloud resource undeletable through this tool
// ("mechanism not owned by cloud-auth"). That is what the three additions here
// are for.
//
// A unique temp name, because a fixed ".tmp" meant two concurrent runs wrote the
// same path and one clobbered the other mid-write.
//
// fsync on the file and on the directory, because rename only guarantees
// atomicity of the name change, not that either the data or the directory entry
// reached disk. A crash between the two left a state file that is valid JSON and
// missing entries.
//
// And a lock file around the whole read-modify-write, because the in-process
// mutex says nothing about a second cloud-auth process.
func (s *FileStateStore) save() error {
	s.state.UpdatedAt = time.Now()

	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	dir := filepath.Dir(s.filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create state directory: %w", err)
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(s.filePath)+".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp state file: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup on every failure path below.
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to set state file permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to write temp state file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to flush state file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp state file: %w", err)
	}

	if err := os.Rename(tmpName, s.filePath); err != nil {
		return fmt.Errorf("failed to rename state file: %w", err)
	}
	tmpName = "" // renamed; nothing to clean up

	// Persist the directory entry itself, or the rename can be lost on crash.
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("failed to flush state directory: %w", err)
	}
	return nil
}

// syncDir fsyncs a directory so a rename within it survives a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- the state directory we just wrote
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// withLock runs fn holding an exclusive advisory lock on the state file's
// lock sibling, so two cloud-auth processes cannot interleave a
// read-modify-write and lose each other's ownership records.
func (s *FileStateStore) withLock(fn func() error) error {
	dir := filepath.Dir(s.filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create state directory: %w", err)
	}
	lockPath := s.filePath + ".lock"

	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600) // #nosec G304 -- derived from the configured state path
	if err != nil {
		return fmt.Errorf("failed to open state lock: %w", err)
	}
	defer func() { _ = f.Close() }()

	if err := lockFile(f); err != nil {
		return fmt.Errorf("failed to lock state file: %w", err)
	}
	defer func() { _ = unlockFile(f) }()

	return fn()
}

// Save implements StateStore.
func (s *FileStateStore) Save(ctx context.Context, ref MechanismRef) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.withLock(func() error {
		// Re-read inside the lock: our in-memory copy may predate another
		// process's writes, and saving over them would lose its records — which
		// makes the resources they describe undeletable.
		if err := s.load(); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to re-read state before save: %w", err)
		}
		s.state.Mechanisms[ref.ID] = ref
		return s.save()
	})
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

	return s.withLock(func() error {
		if err := s.load(); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to re-read state before delete: %w", err)
		}
		if _, exists := s.state.Mechanisms[id]; !exists {
			return nil // Idempotent
		}
		delete(s.state.Mechanisms, id)
		return s.save()
	})
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

	return s.withLock(func() error {
		if err := s.load(); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to re-read state before update: %w", err)
		}
		ref, exists := s.state.Mechanisms[id]
		if !exists {
			return ErrNotFound("mechanism", id)
		}
		ref.Owned = owned
		s.state.Mechanisms[id] = ref
		return s.save()
	})
}

// DefaultStateStorePath returns the default path for the state store file.
func DefaultStateStorePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".cloud-auth", "state.json")
}
