package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The state file decides what Delete is willing to remove.
func TestConcurrentWritersDoNotLoseRecords(t *testing.T) {
	// This test drives four independent stores over one file, so the in-process mutex does not cover them and flock is what genuinely arbitrates.
	if !lockingIsReal {
		t.Skip("cross-process file locking is a no-op on this platform; " +
			"FileStateStore does not serialize concurrent processes here")
	}

	path := filepath.Join(t.TempDir(), "state.json")

	// Two independent stores over one file: this is what two cloud-auth processes look like, and the in-process mutex says nothing about it.
	const writers, each = 4, 25
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			store, err := NewFileStateStore(path)
			if err != nil {
				t.Errorf("NewFileStateStore: %v", err)
				return
			}
			for i := 0; i < each; i++ {
				ref := CreateMechanismRef(MechanismAWSRoleTrustOIDC, AWS,
					map[string]string{"role_name": "r"})
				ref.ID = fmt.Sprintf("mech-%d-%d", w, i)
				if err := store.Save(context.Background(), ref); err != nil {
					t.Errorf("Save: %v", err)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	final, err := NewFileStateStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, err := final.List(context.Background(), ListFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != writers*each {
		t.Errorf("recorded %d mechanisms, want %d: records were lost, and every lost record "+
			"is a resource this tool will refuse to delete", len(got), writers*each)
	}
}

// A fixed ".tmp" name meant two concurrent writers used the same path and one clobbered the other mid-write.
func TestSaveLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	store, err := NewFileStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		ref := CreateMechanismRef(MechanismAWSRoleTrustOIDC, AWS, nil)
		if err := store.Save(context.Background(), ref); err != nil {
			t.Fatal(err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestStateFileIsNotWorldReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := NewFileStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), CreateMechanismRef(MechanismAWSRoleTrustOIDC, AWS, nil)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()
	if !posixFileModes {
		// Windows has no POSIX permission bits: os.Chmod toggles a read-only flag and Perm() reports 0666 whatever was requested.
		if perm == 0o600 {
			t.Errorf("mode = 0600 on a platform without POSIX modes; " +
				"posixFileModes is wrong for this build")
		}
		t.Logf("state file mode = %04o; POSIX modes are unavailable here, so the "+
			"file's protection comes from the containing directory's ACL", perm)
		return
	}
	if perm != 0o600 {
		t.Errorf("state file mode = %04o, want 0600", perm)
	}
}

// A malformed state file must fail loudly.
func TestCorruptStateFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileStateStore(path); err == nil {
		t.Fatal("a corrupt state file must not be silently discarded")
	}
}
