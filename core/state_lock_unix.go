//go:build unix

package core

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive advisory lock, waiting if another process holds it.
func lockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX) }

func unlockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
