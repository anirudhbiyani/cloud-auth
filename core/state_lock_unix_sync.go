//go:build unix

package core

import "os"

// syncDirectory fsyncs a directory so a rename within it survives a crash.
func syncDirectory(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- the state directory we just wrote
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// lockingIsReal reports whether lockFile actually serializes across processes.
const lockingIsReal = true

// posixFileModes reports whether this platform honours POSIX permission bits.
const posixFileModes = true
