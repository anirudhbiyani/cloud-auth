//go:build !unix

package core

import "os"

// lockFile is a no-op where flock is unavailable.
func lockFile(*os.File) error { return nil }

func unlockFile(*os.File) error { return nil }

// syncDirectory is a no-op where a directory cannot be opened as a file handle.
func syncDirectory(string) error { return nil }

// lockingIsReal reports whether lockFile actually serializes across processes.
const lockingIsReal = false

// posixFileModes reports whether this platform honours POSIX permission bits.
const posixFileModes = false
