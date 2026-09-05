package architecture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Go treats a trailing _<GOOS> or _<GOARCH> in a filename as an implicit build constraint.

// implicitConstraints are the suffixes Go reads as build constraints.
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
