//go:build unix

package core

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive advisory lock, waiting if another process holds it.
//
// syscall.Flock rather than golang.org/x/sys/unix: it is two calls, and adding a
// module dependency for them would be the wrong trade. flock is also released
// automatically when the process dies, which matters more here than the lock
// being mandatory — a stale lock file outliving a crashed run would be worse
// than the race it prevents.
func lockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX) }

func unlockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
