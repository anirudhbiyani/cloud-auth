// Package statetest holds the StateStore conformance suite.
//
// It exists as a shared package so the remote backend is held to the SAME
// assertions as the file store rather than to a parallel set that drifts. The
// file store's own tests additionally cover file-specific properties — temp
// files, permission bits, fsync — which have no remote equivalent; everything
// here is a property any StateStore must have.
package statetest

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// Factory returns a fresh, empty store, and a second handle to the SAME
// underlying storage.
//
// Two handles is the whole point of the concurrency assertions: one store's
// in-process mutex says nothing about a second process, and it is the second
// process that loses records.
type Factory func(t *testing.T) (a, b core.StateStore)

// Run executes the conformance suite against a store implementation.
func Run(t *testing.T, newStores Factory) {
	t.Helper()
	t.Run("SaveAndGet", func(t *testing.T) { testSaveAndGet(t, newStores) })
	t.Run("ConcurrentWritersDoNotLoseRecords", func(t *testing.T) { testConcurrentWriters(t, newStores) })
	t.Run("SeparateHandlesSeeEachOther", func(t *testing.T) { testSeparateHandles(t, newStores) })
	t.Run("DeleteRemoves", func(t *testing.T) { testDelete(t, newStores) })
	t.Run("UpdateOwnershipSurvivesAConcurrentWrite", func(t *testing.T) { testOwnership(t, newStores) })
	t.Run("ListIsDeterministicAndPages", func(t *testing.T) { testListPaging(t, newStores) })
	t.Run("MissingMechanismIsNotFound", func(t *testing.T) { testNotFound(t, newStores) })
}

func ref(id string) core.MechanismRef {
	return core.MechanismRef{
		ID: id, Type: core.MechanismAWSRoleTrustOIDC, Provider: core.AWS, Owned: true,
		ResourceIDs: map[string]string{"role_name": id},
	}
}

func testSaveAndGet(t *testing.T, newStores Factory) {
	store, _ := newStores(t)
	ctx := context.Background()

	if err := store.Save(ctx, ref("mech-1")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := store.Get(ctx, "mech-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != "mech-1" || !got.Owned {
		t.Errorf("round-trip lost fields: %+v", got)
	}
	exists, err := store.Exists(ctx, "mech-1")
	if err != nil || !exists {
		t.Errorf("Exists = %v, %v", exists, err)
	}
}

// Every lost record is a resource this tool will refuse to delete, because it no
// longer believes it created it.
func testConcurrentWriters(t *testing.T, newStores Factory) {
	const writers, each = 4, 25
	ctx := context.Background()

	// Two handles over ONE store, which is what two processes look like — the
	// factory is called once, because calling it again would hand back a fresh
	// empty store and each writer would be writing somewhere nobody reads.
	a, b := newStores(t)
	handles := []core.StateStore{a, b}

	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			store := handles[w%len(handles)]
			for i := range each {
				if err := store.Save(ctx, ref(fmt.Sprintf("mech-%d-%d", w, i))); err != nil {
					t.Errorf("Save: %v", err)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	reader := a
	refs, err := reader.List(ctx, core.ListFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(refs) != writers*each {
		t.Errorf("recorded %d mechanisms, want %d: records were lost, and every lost record "+
			"is a resource this tool will refuse to delete", len(refs), writers*each)
	}
}

// A write through one handle must be visible through another, or two operators
// each hold a private view and neither can see what the other created.
func testSeparateHandles(t *testing.T, newStores Factory) {
	a, b := newStores(t)
	ctx := context.Background()

	if err := a.Save(ctx, ref("shared")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := b.Get(ctx, "shared")
	if err != nil {
		t.Fatalf("the second handle cannot see the first handle's write: %v", err)
	}
	if got.ID != "shared" {
		t.Errorf("got %+v", got)
	}
}

func testDelete(t *testing.T, newStores Factory) {
	a, b := newStores(t)
	ctx := context.Background()

	if err := a.Save(ctx, ref("doomed")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := a.Delete(ctx, "doomed"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	exists, err := b.Exists(ctx, "doomed")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if exists {
		t.Error("the delete was not visible through a second handle")
	}
}

// Ownership decides whether delete touches a resource, so a lost update here is
// the most expensive one: two operators, two read-modify-writes, and a resource
// nobody will clean up.
func testOwnership(t *testing.T, newStores Factory) {
	a, b := newStores(t)
	ctx := context.Background()

	if err := a.Save(ctx, ref("owned")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// A concurrent write through the other handle, between the read and the
	// write the ownership update performs.
	if err := b.Save(ctx, ref("other")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := a.UpdateOwnership(ctx, "owned", false); err != nil {
		t.Fatalf("UpdateOwnership: %v", err)
	}

	got, err := b.Get(ctx, "owned")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Owned {
		t.Error("the ownership update was lost")
	}
	// And the concurrent write must have survived it.
	if _, err := a.Get(ctx, "other"); err != nil {
		t.Errorf("the concurrent write was clobbered by the ownership update: %v", err)
	}
}

// Paging must partition the set: every entry exactly once, no repeats, no gaps.
func testListPaging(t *testing.T, newStores Factory) {
	store, _ := newStores(t)
	ctx := context.Background()

	const total, page = 10, 3
	for i := range total {
		if err := store.Save(ctx, ref(fmt.Sprintf("mech-%02d", i))); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}

	seen := map[string]int{}
	for offset := 0; offset < total; offset += page {
		refs, err := store.List(ctx, core.ListFilter{Offset: offset, Limit: page})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		for _, r := range refs {
			seen[r.ID]++
		}
	}
	if len(seen) != total {
		t.Errorf("saw %d distinct mechanisms across all pages, want %d", len(seen), total)
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("%s appeared %d times across pages, want once", id, n)
		}
	}

	// An offset past the end returns nothing, or a client paging until it gets
	// an empty page never gets one.
	refs, err := store.List(ctx, core.ListFilter{Offset: total + 5})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(refs) != 0 {
		t.Errorf("an offset past the end returned %d entries", len(refs))
	}
}

func testNotFound(t *testing.T, newStores Factory) {
	store, _ := newStores(t)
	ctx := context.Background()

	if _, err := store.Get(ctx, "absent"); err == nil {
		t.Error("Get on a missing mechanism returned no error")
	}
	exists, err := store.Exists(ctx, "absent")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if exists {
		t.Error("Exists = true for a missing mechanism")
	}
}
