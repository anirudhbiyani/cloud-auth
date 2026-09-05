package state_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/internal/statetest"
)

// The acceptance criterion, stated literally: the remote backend passes the same durability suite as the file store.
func TestFileStoreConformance(t *testing.T) {
	if runtime.GOOS == "windows" {
		// The concurrency assertions need a real cross-process lock, and the file store's is a documented no-op off unix.
		t.Skip("cross-process file locking is a no-op on this platform; " +
			"FileStateStore does not serialize concurrent processes here")
	}

	statetest.Run(t, func(t *testing.T) (core.StateStore, core.StateStore) {
		path := filepath.Join(t.TempDir(), "state.json")
		a, err := core.NewFileStateStore(path)
		if err != nil {
			t.Fatalf("NewFileStateStore: %v", err)
		}
		// A second, independent store over the same file: two processes, not two references to one object, so the in-process mutex does not cover them and flock is what genuinely arbitrates.
		b, err := core.NewFileStateStore(path)
		if err != nil {
			t.Fatalf("NewFileStateStore: %v", err)
		}
		return a, b
	})
}
