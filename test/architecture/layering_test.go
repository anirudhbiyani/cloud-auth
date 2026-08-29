// Package architecture asserts the import structure, because it is a property
// this codebase deliberately maintains and nothing else would notice breaking.
//
// The alternative was splitting the control plane into its own module, which
// would let the compiler enforce the same boundary. Measured, that split saved
// 76 KB of binary and two go.sum entries — Go's linker already eliminates the
// unused code, and the data plane pulls most of the AWS SDK anyway through one
// LoadDefaultConfig call. It would also have added permanent multi-module
// friction: replace directives, two-commit changes, two tags in order. These
// tests buy the property that actually mattered for the cost of one file.
package architecture

import (
	"encoding/json"
	"os/exec"
	"sort"
	"strings"
	"testing"
)

const module = "github.com/anirudhbiyani/cloud-auth"

// pkg is the subset of `go list -json` output these tests need.
type pkg struct {
	ImportPath  string
	Name        string
	Imports     []string
	TestImports []string
}

// firstPartyImports returns every in-module package each package imports,
// including from its tests: a test-only edge is still an edge, and a layering
// violation introduced in a test tends to become one in production later.
func firstPartyImports(t *testing.T) map[string][]string {
	t.Helper()

	// ./... from the repository root. The test binary runs in this directory, so
	// walk up two levels.
	cmd := exec.Command("go", "list", "-json", "./...")
	cmd.Dir = "../.."
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}

	graph := map[string][]string{}
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for dec.More() {
		var p pkg
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("decoding go list output: %v", err)
		}
		var deps []string
		for _, imp := range append(append([]string{}, p.Imports...), p.TestImports...) {
			if strings.HasPrefix(imp, module) && imp != p.ImportPath {
				deps = append(deps, short(imp))
			}
		}
		sort.Strings(deps)
		graph[short(p.ImportPath)] = dedupe(deps)
	}
	if len(graph) == 0 {
		t.Fatal("go list returned no packages")
	}
	return graph
}

func short(importPath string) string {
	if importPath == module {
		return "."
	}
	return strings.TrimPrefix(importPath, module+"/")
}

func dedupe(xs []string) []string {
	seen := map[string]bool{}
	out := xs[:0]
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// dataPlane is what a workload imports to obtain credentials at run time.
var dataPlane = []string{"source", "target", "broker", "adapters", "config"}

// The data plane must not reach the control plane.
//
// A provider talks to IAM, Graph or Vault with ambient administrative
// credentials. A workload obtaining its own credentials has no business linking
// that code, and more importantly no business being able to call it: the two
// halves have completely different trust assumptions, and the moment one imports
// the other, "this binary can only mint credentials" stops being true.
func TestDataPlaneDoesNotImportTheControlPlane(t *testing.T) {
	graph := firstPartyImports(t)

	for _, p := range dataPlane {
		deps, ok := graph[p]
		if !ok {
			t.Errorf("package %q not found; update dataPlane in this test", p)
			continue
		}
		for _, dep := range deps {
			if strings.HasPrefix(dep, "provider/") {
				t.Errorf("%s imports %s: the data plane must not link the control plane. "+
					"A provider carries administrative cloud clients, and a workload that "+
					"only mints its own credentials should not be able to reach them.", p, dep)
			}
		}
	}
}

// core is a leaf. Everything else may import it; it imports nothing of ours.
//
// This is what lets the control-plane validators read provider state without
// core importing providers — the dependency is inverted through
// TrustPolicySource and GrantedPolicySource instead. Give core one first-party
// import and that inversion is no longer necessary, so it will stop being
// maintained.
func TestCoreIsALeaf(t *testing.T) {
	graph := firstPartyImports(t)

	if deps, ok := graph["core"]; !ok {
		t.Fatal("core not found")
	} else if len(deps) != 0 {
		t.Errorf("core imports %v; it must remain a leaf so providers can import it "+
			"and the validation interfaces can stay inverted", deps)
	}
}

// No provider imports another. They are meant to evolve independently, and a
// shared helper between two of them belongs in core or internal.
func TestProvidersDoNotImportEachOther(t *testing.T) {
	graph := firstPartyImports(t)

	found := 0
	for p, deps := range graph {
		if !strings.HasPrefix(p, "provider/") {
			continue
		}
		found++
		for _, dep := range deps {
			if strings.HasPrefix(dep, "provider/") {
				t.Errorf("%s imports %s: providers must evolve independently; shared code "+
					"belongs in core or internal", p, dep)
			}
		}
	}
	if found == 0 {
		t.Fatal("no provider packages found")
	}
}

// adapters wraps a source and an exchanger the CALLER supplies, so it depends on
// neither. That is what lets a consumer inject a fake for testing without
// standing up the whole data plane.
func TestAdaptersDependOnNeitherSourceNorTarget(t *testing.T) {
	graph := firstPartyImports(t)

	for _, dep := range graph["adapters"] {
		if dep == "source" || dep == "target" {
			t.Errorf("adapters imports %s: it should accept a SourceProvider and an "+
				"Exchanger from the caller, so a consumer can inject fakes", dep)
		}
	}
}

// internal/redact is imported by the error and audit paths, so it must stay
// dependency-free: an import cycle through core would be the one way to make
// redaction impossible to apply where it is needed.
func TestRedactStaysDependencyFree(t *testing.T) {
	graph := firstPartyImports(t)

	if deps, ok := graph["internal/redact"]; !ok {
		t.Fatal("internal/redact not found")
	} else if len(deps) != 0 {
		t.Errorf("internal/redact imports %v; it must stay dependency-free so every "+
			"package that formats an error can use it", deps)
	}
}

// The graph must be acyclic. Go rejects import cycles at compile time for
// production code, but this also covers test-only edges, which it does not.
func TestNoImportCycles(t *testing.T) {
	graph := firstPartyImports(t)

	const (
		white = 0 // unvisited
		grey  = 1 // on the current path
		black = 2 // done
	)
	state := map[string]int{}

	var walk func(string, []string)
	walk = func(node string, path []string) {
		switch state[node] {
		case grey:
			t.Errorf("import cycle: %s -> %s", strings.Join(path, " -> "), node)
			return
		case black:
			return
		}
		state[node] = grey
		for _, dep := range graph[node] {
			walk(dep, append(path, node))
		}
		state[node] = black
	}

	// Sorted, so a failure names the same cycle every run.
	nodes := make([]string, 0, len(graph))
	for n := range graph {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)
	for _, n := range nodes {
		walk(n, nil)
	}
}
