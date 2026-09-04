package state_test

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/internal/statetest"
	"github.com/anirudhbiyani/cloud-auth/state"
)

// fakeObjects is an in-memory ObjectStore with real compare-and-swap semantics.
//
// The version tag increments on every successful write, so a caller holding a
// stale tag loses exactly as it would against S3. Without that this suite would
// prove the retry loop compiles and nothing about whether it works.
type fakeObjects struct {
	mu      sync.Mutex
	data    []byte
	version int
	stored  bool

	// puts counts writes, so a test can show the retry actually retried.
	puts int
	// failNext makes the next Put fail with a non-precondition error.
	failNext error
}

func (f *fakeObjects) Get(context.Context) ([]byte, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.stored {
		return nil, "", state.ErrNotFound
	}
	out := make([]byte, len(f.data))
	copy(out, f.data)
	return out, versionTag(f.version), nil
}

func (f *fakeObjects) Put(_ context.Context, data []byte, expected string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.puts++

	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		return err
	}

	current := ""
	if f.stored {
		current = versionTag(f.version)
	}
	if expected != current {
		return state.ErrPreconditionFailed
	}

	f.data = make([]byte, len(data))
	copy(f.data, data)
	f.version++
	f.stored = true
	return nil
}

func (f *fakeObjects) Describe() string { return "fake://state" }

// versionTag must NOT wrap. An earlier version used n%10, so after ten writes
// the tags repeated and a writer holding a stale tag matched a later state —
// compare-and-swap succeeded when it should have failed, and the suite caught it
// as a lost update. Real ETags are content hashes and do not recur; a fake that
// does is testing something weaker than the thing it stands in for.
func versionTag(n int) string { return `"v` + strconv.Itoa(n) + `"` }

// The acceptance criterion: the remote backend passes the same suite as the
// file store. Both run it below, from the same package, so neither can drift.
func TestRemoteStoreConformance(t *testing.T) {
	statetest.Run(t, func(t *testing.T) (core.StateStore, core.StateStore) {
		objects := &fakeObjects{}
		// Two Stores over ONE object: two processes sharing a bucket.
		return state.New(objects, state.WithMaxAttempts(64)),
			state.New(objects, state.WithMaxAttempts(64))
	})
}

// A losing compare-and-swap must re-read and retry, not overwrite. Retrying
// with a stale in-memory copy would silently discard whichever write lost.
func TestConcurrentSaveRetriesRatherThanClobbering(t *testing.T) {
	objects := &fakeObjects{}
	a := state.New(objects, state.WithMaxAttempts(32))
	b := state.New(objects, state.WithMaxAttempts(32))
	ctx := context.Background()

	var wg sync.WaitGroup
	for i, store := range []*state.Store{a, b} {
		wg.Add(1)
		go func(i int, s *state.Store) {
			defer wg.Done()
			for n := range 20 {
				id := fmt.Sprintf("writer%d-%02d", i, n)
				if err := s.Save(ctx, core.MechanismRef{
					ID: id, Type: core.MechanismAWSRoleTrustOIDC, Provider: core.AWS,
				}); err != nil {
					t.Errorf("Save: %v", err)
					return
				}
			}
		}(i, store)
	}
	wg.Wait()

	refs, err := a.List(ctx, core.ListFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(refs) != 40 {
		t.Errorf("got %d records, want 40 — a losing write clobbered a winning one", len(refs))
	}
	// If nothing ever lost a race the test proved nothing about retrying.
	if objects.puts <= 40 {
		t.Logf("puts = %d; no compare-and-swap actually lost, so the retry path was not exercised",
			objects.puts)
	}
}

// A retry budget has to be bounded, and running out has to say so rather than
// silently doing nothing.
func TestExhaustedRetriesIsAnError(t *testing.T) {
	// maxAttempts 0 means every attempt is skipped, so the loop cannot succeed.
	s := state.New(&alwaysConflicting{}, state.WithMaxAttempts(3))
	err := s.Save(context.Background(), core.MechanismRef{ID: "x", Provider: core.AWS})
	if err == nil {
		t.Fatal("want an error when the document keeps changing")
	}
	if !strings.Contains(err.Error(), "successive attempts") {
		t.Errorf("the error does not explain what happened: %v", err)
	}
}

type alwaysConflicting struct{}

func (alwaysConflicting) Get(context.Context) ([]byte, string, error) {
	return []byte(`{"version":1,"mechanisms":{}}`), `"stale"`, nil
}
func (alwaysConflicting) Put(context.Context, []byte, string) error {
	return state.ErrPreconditionFailed
}
func (alwaysConflicting) Describe() string { return "fake://conflicting" }

// A document that is not JSON must fail loudly. Starting from empty would orphan
// every resource it recorded — cloud-auth would then refuse to delete them,
// because it no longer believes it created them.
func TestCorruptDocumentIsAnError(t *testing.T) {
	objects := &fakeObjects{data: []byte("not json"), stored: true}
	_, err := state.New(objects).Get(context.Background(), "anything")
	if err == nil {
		t.Fatal("a corrupt document was silently treated as empty")
	}
	if !strings.Contains(err.Error(), "not valid JSON") {
		t.Errorf("error = %v", err)
	}
}

// A newer schema must not be rewritten by an older build, which would drop
// whatever fields it does not understand.
func TestNewerSchemaIsRefused(t *testing.T) {
	objects := &fakeObjects{data: []byte(`{"version":99,"mechanisms":{}}`), stored: true}
	_, err := state.New(objects).Get(context.Background(), "anything")
	if err == nil {
		t.Fatal("a future schema version was accepted")
	}
	if !strings.Contains(err.Error(), "upgrade cloud-auth") {
		t.Errorf("the error does not say what to do: %v", err)
	}
}

// An absent object is an empty store, not an error: the first operator to run
// setup against a fresh bucket must not have to create the object by hand.
func TestAbsentObjectIsAnEmptyStore(t *testing.T) {
	s := state.New(&fakeObjects{})
	refs, err := s.List(context.Background(), core.ListFilter{})
	if err != nil {
		t.Fatalf("List on an absent object: %v", err)
	}
	if len(refs) != 0 {
		t.Errorf("got %d refs", len(refs))
	}
	if err := s.Save(context.Background(), core.MechanismRef{ID: "first", Provider: core.AWS}); err != nil {
		t.Fatalf("Save against an absent object: %v", err)
	}
}

// A non-precondition error is a real failure and must not be retried away.
func TestNonPreconditionErrorsAreNotRetried(t *testing.T) {
	objects := &fakeObjects{failNext: errors.New("access denied")}
	err := state.New(objects).Save(context.Background(),
		core.MechanismRef{ID: "x", Provider: core.AWS})
	if err == nil {
		t.Fatal("want the underlying error")
	}
	if !strings.Contains(err.Error(), "access denied") {
		t.Errorf("the cause was lost: %v", err)
	}
	if objects.puts != 1 {
		t.Errorf("made %d writes; a permission failure must not be retried", objects.puts)
	}
}

func TestParseS3URL(t *testing.T) {
	for _, tc := range []struct {
		in          string
		bucket, key string
		ok          bool
	}{
		{"s3://my-bucket/state.json", "my-bucket", "state.json", true},
		{"s3://my-bucket/team/prod/state.json", "my-bucket", "team/prod/state.json", true},
		{"s3://my-bucket", "", "", false},
		{"s3://my-bucket/", "", "", false},
		{"/local/path/state.json", "", "", false},
		{"", "", "", false},
	} {
		t.Run(tc.in, func(t *testing.T) {
			bucket, key, ok := state.ParseS3URL(tc.in)
			if ok != tc.ok || bucket != tc.bucket || key != tc.key {
				t.Errorf("got (%q, %q, %v), want (%q, %q, %v)",
					bucket, key, ok, tc.bucket, tc.key, tc.ok)
			}
		})
	}
}
