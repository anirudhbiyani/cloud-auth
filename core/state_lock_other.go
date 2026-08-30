//go:build !unix

package core

import "os"

// lockFile is a no-op where flock is unavailable. The in-process mutex still
// applies; only cross-process serialization is missing, and failing to save
// would be a worse outcome than the race.
func lockFile(*os.File) error { return nil }

func unlockFile(*os.File) error { return nil }

// syncDirectory is a no-op where a directory cannot be opened as a file handle.
//
// Windows has no equivalent of fsync on a directory: os.Open on one succeeds,
// and Sync fails with "Access is denied". Returning the error made every save
// fail, so the state store did not work on Windows at all. A rename is already
// atomic on Windows within a volume; what is lost is the guarantee that the
// directory entry reaches disk before a crash, which is the same guarantee the
// no-op lock above already trades away.
func syncDirectory(string) error { return nil }

// lockingIsReal reports whether lockFile actually serializes across processes.
//
// False here, and tests that assert multi-process durability check it so they
// skip loudly rather than fail — or, worse, pass for the wrong reason.
const lockingIsReal = false
