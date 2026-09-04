package architecture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Go treats a trailing _<GOOS> or _<GOARCH> in a filename as an implicit build
// constraint. `client_arm.go` therefore compiled only on ARM targets, and the
// package failed with "does not implement ARMClient" while the method sat right
// there in the file — a failure whose message points nowhere near its cause.
//
// It happened twice. The first time was the source file; the second was a test
// file added months later, because the fix was a rename plus a one-time sweep,
// and a sweep is not a rule. This is the rule.
//
// Only accidental constraints are caught. A file that genuinely means to be
// platform-specific declares it with an explicit //go:build line, which is
// visible in review — state_lock_unix.go and state_lock_other.go do exactly
// that and are not affected, because "unix" and "other" are not GOOS values.

// implicitConstraints are the suffixes Go reads as build constraints.
//
// The list is the union of GOOS and GOARCH values, plus the few aliases. It
// does not need to be exhaustive to be useful: it needs to contain the ones
// somebody would plausibly name a file after, and "arm" is the one that has
// already cost this repository twice.
var implicitConstraints = map[string]bool{
	// GOARCH
	"386": true, "amd64": true, "arm": true, "arm64": true, "loong64": true,
	"mips": true, "mips64": true, "mips64le": true, "mipsle": true,
	"ppc64": true, "ppc64le": true, "riscv64": true, "s390x": true, "wasm": true,
	// GOOS
	"aix": true, "android": true, "darwin": true, "dragonfly": true,
	"freebsd": true, "hurd": true, "illumos": true, "ios": true, "js": true,
	"linux": true, "netbsd": true, "openbsd": true, "plan9": true,
	"solaris": true, "windows": true, "zos": true,
}

func TestNoAccidentalBuildConstraintsInFilenames(t *testing.T) {
	root := "../.."

	var offenders []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}

		base := strings.TrimSuffix(d.Name(), ".go")
		base = strings.TrimSuffix(base, "_test")
		i := strings.LastIndex(base, "_")
		if i < 0 {
			return nil
		}
		if suffix := base[i+1:]; implicitConstraints[suffix] {
			rel, _ := filepath.Rel(root, path)
			offenders = append(offenders, rel+" (suffix _"+suffix+")")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}

	for _, o := range offenders {
		t.Errorf("%s: Go reads this suffix as an implicit build constraint, so the file compiles "+
			"only on that platform — silently, and the resulting error names a missing method "+
			"rather than a missing file. Rename it, or if the constraint is intended, say so with "+
			"an explicit //go:build line and a name that does not imply it.", o)
	}
}
