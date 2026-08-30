package core

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
)

// Both stores built their List slice by ranging a map, and Go randomizes map
// iteration order on purpose — so Offset/Limit were slicing a different
// arrangement every call. Page 2 could repeat an entry from page 1 and omit
// another, and nothing about the result would look wrong.
//
// FileStateStore is the one the CLI uses, so this was production behaviour, not
// just a test-store quirk.

// stores returns both implementations under one interface, so every case here
// runs against both. The PRD named only the memory store; the file store had the
// same two bugs.
func stores(t *testing.T) map[string]StateStore {
	t.Helper()
	file, err := NewFileStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("NewFileStateStore: %v", err)
	}
	return map[string]StateStore{
		"memory": NewMemoryStateStore(),
		"file":   file,
	}
}

// seed writes n mechanisms with sortable ids.
func seed(t *testing.T, store StateStore, n int) {
	t.Helper()
	ctx := context.Background()
	for i := range n {
		ref := MechanismRef{
			ID:       fmt.Sprintf("mech-%02d", i),
			Type:     MechanismAWSRoleTrustOIDC,
			Provider: "aws",
			Owned:    true,
		}
		if err := store.Save(ctx, ref); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}
}

func ids(refs []MechanismRef) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.ID)
	}
	return out
}

func TestListIsDeterministicallyOrdered(t *testing.T) {
	for name, store := range stores(t) {
		t.Run(name, func(t *testing.T) {
			seed(t, store, 10)
			ctx := context.Background()

			var first []string
			// Repeat enough times that a randomized map order would show.
			for range 20 {
				refs, err := store.List(ctx, ListFilter{})
				if err != nil {
					t.Fatalf("List: %v", err)
				}
				got := ids(refs)
				if first == nil {
					first = got
					continue
				}
				for i := range got {
					if got[i] != first[i] {
						t.Fatalf("List order changed between calls:\n first: %v\n then:  %v", first, got)
					}
				}
			}
			// Sorted by ID, which is the only field guaranteed present and unique.
			for i := 1; i < len(first); i++ {
				if first[i-1] >= first[i] {
					t.Errorf("not sorted at %d: %v", i, first)
					break
				}
			}
		})
	}
}

// Paging must partition the set: every entry exactly once, no repeats, no gaps.
// That is the property the random order actually broke.
func TestPagingCoversEveryEntryExactlyOnce(t *testing.T) {
	for name, store := range stores(t) {
		t.Run(name, func(t *testing.T) {
			const total, pageSize = 10, 3
			seed(t, store, total)
			ctx := context.Background()

			seen := map[string]int{}
			for offset := 0; offset < total; offset += pageSize {
				refs, err := store.List(ctx, ListFilter{Offset: offset, Limit: pageSize})
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
			for id, count := range seen {
				if count != 1 {
					t.Errorf("%s appeared %d times across pages, want once", id, count)
				}
			}
		})
	}
}

// The second bug, which the PRD did not name: the guard was
// `Offset > 0 && Offset < len(refs)`, so an offset past the end skipped the
// slice entirely and returned the FULL list. A client walking pages until it got
// an empty one never got one.
func TestOffsetPastTheEndReturnsNothing(t *testing.T) {
	for name, store := range stores(t) {
		t.Run(name, func(t *testing.T) {
			seed(t, store, 3)
			ctx := context.Background()

			for _, offset := range []int{3, 4, 100} {
				refs, err := store.List(ctx, ListFilter{Offset: offset})
				if err != nil {
					t.Fatalf("List: %v", err)
				}
				if len(refs) != 0 {
					t.Errorf("Offset %d returned %d entries (%v), want none — "+
						"a paginating client would loop forever", offset, len(refs), ids(refs))
				}
			}
		})
	}
}

func TestPaginationEdges(t *testing.T) {
	for name, store := range stores(t) {
		t.Run(name, func(t *testing.T) {
			seed(t, store, 5)
			ctx := context.Background()

			for _, tc := range []struct {
				name   string
				filter ListFilter
				want   []string
			}{
				{"no window", ListFilter{}, []string{"mech-00", "mech-01", "mech-02", "mech-03", "mech-04"}},
				{"limit only", ListFilter{Limit: 2}, []string{"mech-00", "mech-01"}},
				{"offset only", ListFilter{Offset: 3}, []string{"mech-03", "mech-04"}},
				{"offset and limit", ListFilter{Offset: 1, Limit: 2}, []string{"mech-01", "mech-02"}},
				{"limit past the end", ListFilter{Limit: 99}, []string{"mech-00", "mech-01", "mech-02", "mech-03", "mech-04"}},
				{"last page is short", ListFilter{Offset: 4, Limit: 3}, []string{"mech-04"}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					refs, err := store.List(ctx, tc.filter)
					if err != nil {
						t.Fatalf("List: %v", err)
					}
					got := ids(refs)
					if len(got) != len(tc.want) {
						t.Fatalf("got %v, want %v", got, tc.want)
					}
					for i := range got {
						if got[i] != tc.want[i] {
							t.Fatalf("got %v, want %v", got, tc.want)
						}
					}
				})
			}
		})
	}
}
