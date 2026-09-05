// Package state provides a shared, remote StateStore.
package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// stateDocument is the stored shape.
type stateDocument struct {
	Version    int                          `json:"version"`
	Mechanisms map[string]core.MechanismRef `json:"mechanisms"`
	UpdatedAt  time.Time                    `json:"updated_at"`
}

// documentVersion is the schema version this package writes.
const documentVersion = 1

// ErrPreconditionFailed means the stored document changed between the read and the write.
var ErrPreconditionFailed = errors.New("state: the stored document changed concurrently")

// ErrNotFound means the object does not exist yet.
var ErrNotFound = errors.New("state: no stored document")

// ObjectStore is the small surface a remote backend has to provide.
type ObjectStore interface {
	// Get returns the document and an opaque version tag.
	Get(ctx context.Context) (data []byte, version string, err error)

	// Put writes data only if the stored version still matches expectedVersion.
	Put(ctx context.Context, data []byte, expectedVersion string) error

	// Describe names the location, for error messages.
	Describe() string
}

// Store is a StateStore over any ObjectStore.
type Store struct {
	objects ObjectStore
	// maxAttempts bounds the compare-and-swap retry loop.
	maxAttempts int
	// backoff is the base delay between attempts.
	backoff time.Duration
	// sleep is injectable so tests do not spend real time.
	sleep func(context.Context, time.Duration) error
}

// Option configures a Store.
type Option func(*Store)

// WithMaxAttempts overrides the compare-and-swap retry budget.
func WithMaxAttempts(n int) Option {
	return func(s *Store) { s.maxAttempts = n }
}

// WithBackoff overrides the base delay between compare-and-swap attempts.
func WithBackoff(d time.Duration) Option {
	return func(s *Store) { s.backoff = d }
}

// WithSleep overrides how the retry loop waits. For tests.
func WithSleep(fn func(context.Context, time.Duration) error) Option {
	return func(s *Store) { s.sleep = fn }
}

// New builds a StateStore over an ObjectStore.
func New(objects ObjectStore, opts ...Option) *Store {
	s := &Store{
		objects:     objects,
		maxAttempts: 8,
		backoff:     5 * time.Millisecond,
		sleep:       sleepCtx,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// sleepCtx waits for d, or until ctx is done.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// retryDelay returns how long to wait before the next attempt.
func (s *Store) retryDelay(attempt int) time.Duration {
	if s.backoff <= 0 {
		return 0
	}
	shift := attempt
	if shift > 6 {
		shift = 6
	}
	window := s.backoff << shift
	return time.Duration(rand.Int63n(int64(window) + 1)) // #nosec G404 -- load spreading, not a secret
}

// read loads the document and its version tag.
func (s *Store) read(ctx context.Context) (*stateDocument, string, error) {
	data, version, err := s.objects.Get(ctx)
	if errors.Is(err, ErrNotFound) {
		return &stateDocument{Version: documentVersion, Mechanisms: map[string]core.MechanismRef{}}, "", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("state: reading %s: %w", s.objects.Describe(), err)
	}

	var doc stateDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		// Loudly.
		return nil, "", fmt.Errorf("state: %s holds a document that is not valid JSON: %w",
			s.objects.Describe(), err)
	}
	if doc.Version > documentVersion {
		return nil, "", fmt.Errorf("state: %s holds schema version %d, but this build understands "+
			"at most %d — upgrade cloud-auth rather than letting an older build rewrite it",
			s.objects.Describe(), doc.Version, documentVersion)
	}
	if doc.Mechanisms == nil {
		doc.Mechanisms = map[string]core.MechanismRef{}
	}
	return &doc, version, nil
}

// mutate applies fn to the document under compare-and-swap, retrying when another writer got there first.
func (s *Store) mutate(ctx context.Context, fn func(*stateDocument) error) error {
	var lastErr error
	for attempt := range s.maxAttempts {
		doc, version, err := s.read(ctx)
		if err != nil {
			return err
		}
		if err := fn(doc); err != nil {
			return err
		}

		doc.Version = documentVersion
		doc.UpdatedAt = time.Now().UTC()

		encoded, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return fmt.Errorf("state: encoding the document: %w", err)
		}

		err = s.objects.Put(ctx, encoded, version)
		if err == nil {
			return nil
		}
		if !errors.Is(err, ErrPreconditionFailed) {
			return fmt.Errorf("state: writing %s: %w", s.objects.Describe(), err)
		}
		lastErr = err
		if err := s.sleep(ctx, s.retryDelay(attempt)); err != nil {
			return err
		}
	}
	return fmt.Errorf("state: %s changed under %d successive attempts: %w",
		s.objects.Describe(), s.maxAttempts, lastErr)
}

// Save stores a mechanism reference.
func (s *Store) Save(ctx context.Context, ref core.MechanismRef) error {
	if ref.ID == "" {
		return fmt.Errorf("state: cannot save a mechanism with no ID")
	}
	return s.mutate(ctx, func(doc *stateDocument) error {
		doc.Mechanisms[ref.ID] = ref
		return nil
	})
}

// Get retrieves a mechanism reference by ID.
func (s *Store) Get(ctx context.Context, id string) (*core.MechanismRef, error) {
	doc, _, err := s.read(ctx)
	if err != nil {
		return nil, err
	}
	ref, ok := doc.Mechanisms[id]
	if !ok {
		return nil, core.ErrNotFound("mechanism", id)
	}
	return &ref, nil
}

// List returns stored mechanisms matching the filter.
func (s *Store) List(ctx context.Context, filter core.ListFilter) ([]core.MechanismRef, error) {
	doc, _, err := s.read(ctx)
	if err != nil {
		return nil, err
	}

	var refs []core.MechanismRef
	for _, ref := range doc.Mechanisms {
		if filter.Type != "" && ref.Type != filter.Type {
			continue
		}
		if filter.Provider != "" && ref.Provider != filter.Provider {
			continue
		}
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].ID < refs[j].ID })

	if filter.Offset > 0 {
		if filter.Offset >= len(refs) {
			return []core.MechanismRef{}, nil
		}
		refs = refs[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(refs) {
		refs = refs[:filter.Limit]
	}
	return refs, nil
}

// Delete removes a mechanism reference.
func (s *Store) Delete(ctx context.Context, id string) error {
	return s.mutate(ctx, func(doc *stateDocument) error {
		if _, ok := doc.Mechanisms[id]; !ok {
			return core.ErrNotFound("mechanism", id)
		}
		delete(doc.Mechanisms, id)
		return nil
	})
}

// Exists reports whether a mechanism is stored.
func (s *Store) Exists(ctx context.Context, id string) (bool, error) {
	doc, _, err := s.read(ctx)
	if err != nil {
		return false, err
	}
	_, ok := doc.Mechanisms[id]
	return ok, nil
}

// UpdateOwnership updates whether cloud-auth owns a mechanism.
func (s *Store) UpdateOwnership(ctx context.Context, id string, owned bool) error {
	return s.mutate(ctx, func(doc *stateDocument) error {
		ref, ok := doc.Mechanisms[id]
		if !ok {
			return core.ErrNotFound("mechanism", id)
		}
		ref.Owned = owned
		doc.Mechanisms[id] = ref
		return nil
	})
}

// Describe names the backing location.
func (s *Store) Describe() string { return s.objects.Describe() }

// compile-time check.
var _ core.StateStore = (*Store)(nil)
