//go:build unix

package core

import "os"

// syncDirectory fsyncs a directory so a rename within it survives a crash.
//
// This is the half of the durability story that fsyncing the file alone does
// not give you: the file's contents are on disk, but the directory entry
// pointing at its new name may not be.
func syncDirectory(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- the state directory we just wrote
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// lockingIsReal reports whether lockFile actually serializes across processes.
//
// True here: state_lock_unix.go uses syscall.Flock. Tests that assert
// multi-process durability check this rather than assuming, so on a platform
// where the lock is a no-op they skip loudly instead of failing or, worse,
// passing for the wrong reason.
const lockingIsReal = true
