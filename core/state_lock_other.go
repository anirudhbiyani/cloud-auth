//go:build !unix

package core

import "os"

// lockFile is a no-op where flock is unavailable. The in-process mutex still
// applies; only cross-process serialization is missing, and failing to save
// would be a worse outcome than the race.
func lockFile(*os.File) error { return nil }

func unlockFile(*os.File) error { return nil }
