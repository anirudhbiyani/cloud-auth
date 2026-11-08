// Command apidoc renders the exported API of cloud-auth's public packages as Markdown pages for the docs site, straight from the source: every page is regenerated at docs build time, so the inventory cannot drift from the code.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/doc"
	"go/format"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const module = "github.com/anirudhbiyani/cloud-auth"

// pages lists the packages in the order the reference shows them, with the curated SDK page that shows each one in use.
var pages = []struct{ dir, title, examples string }{
	{"core", "core", "control-plane.md"},
	{"broker", "broker", "runtime.md"},
	{"adapters", "adapters", "runtime.md#plug-into-the-cloud-sdks"},
	{"source", "source", "runtime.md#restrict-which-runtime-may-be-detected"},
	{"target", "target", "runtime.md#lower-level-mint-and-exchange-yourself"},
	{"config", "config", "runtime.md#reuse-the-clis-config-file"},
	{"state", "state", "control-plane.md#state-stores"},
	{"provider/aws", "provider/aws", "control-plane.md"},
	{"provider/gcp", "provider/gcp", "control-plane.md"},
	{"provider/azure", "provider/azure", "control-plane.md"},
	{"provider/vault", "provider/vault", "control-plane.md"},
	{"provider/anthropic", "provider/anthropic", "control-plane.md"},
}

func main() {
	root := flag.String("root", ".", "module root")
	out := flag.String("out", "docs/sdk/reference", "output directory")
	flag.Parse()
	if err := os.MkdirAll(*out, 0o750); err != nil {
		log.Fatal(err)
	}
	var index bytes.Buffer
	index.WriteString("# API reference\n\nEvery exported identifier in the public packages, generated from the source at build time by `go run ./internal/apidoc`. Signatures and doc comments are the code's own; the *Examples* link on each page is the curated walkthrough that shows the package in use.\n\n| Package | Exported | Shown in |\n|---|---:|---|\n")
	for _, p := range pages {
		md, n, err := render(filepath.Join(*root, p.dir), p.dir, p.examples)
		if err != nil {
			log.Fatalf("%s: %v", p.dir, err)
		}
		name := strings.ReplaceAll(p.dir, "/", "-") + ".md"
		if err := os.WriteFile(filepath.Join(*out, name), md, 0o600); err != nil {
			log.Fatal(err)
		}
		fmt.Fprintf(&index, "| [`%s`](%s) | %d | [%s](../%s) |\n", module+"/"+p.dir, name, n, strings.SplitN(p.examples, "#", 2)[0], p.examples)
	}
	if err := os.WriteFile(filepath.Join(*out, "index.md"), index.Bytes(), 0o600); err != nil {
		log.Fatal(err)
	}
}

// parseGoFiles parses the package's files (or its _test files) in one directory; build tags are irrelevant here because every public package of this module is tag-free.
func parseGoFiles(fset *token.FileSet, dir string, tests bool) ([]*ast.File, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") != tests {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ParseComments)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	return files, nil
}

// render documents one package: overview, constants, variables, functions, then each type with its constructors and methods, then Example functions from _test files.
func render(dir, importPath, examples string) ([]byte, int, error) {
	fset := token.NewFileSet()
	files, err := parseGoFiles(fset, dir, false)
	if err != nil {
		return nil, 0, err
	}
	testFiles, err := parseGoFiles(fset, dir, true)
	if err != nil {
		return nil, 0, err
	}
	d, err := doc.NewFromFiles(fset, append(files, testFiles...), module+"/"+importPath)
	if err != nil {
		return nil, 0, err
	}

	var b bytes.Buffer
	pr := d.Printer()
	md := func(text string) string { return string(pr.Markdown(d.Parser().Parse(text))) }
	sig := func(node ast.Node) string {
		var sb bytes.Buffer
		_ = format.Node(&sb, fset, node)
		return sb.String()
	}
	count := 0

	fmt.Fprintf(&b, "# `%s`\n\n```go\nimport \"%s/%s\"\n```\n\n%s\n", importPath, module, importPath, md(d.Doc))
	fmt.Fprintf(&b, "**Examples:** see [%s](../%s). **Source:** [`%s/`](https://github.com/anirudhbiyani/cloud-auth/tree/main/%s).\n\n", strings.SplitN(examples, "#", 2)[0], examples, importPath, importPath)

	values := func(title string, vs []*doc.Value) {
		if len(vs) == 0 {
			return
		}
		fmt.Fprintf(&b, "## %s\n\n", title)
		for _, v := range vs {
			count += len(v.Names)
			fmt.Fprintf(&b, "```go\n%s\n```\n\n%s\n", sig(v.Decl), md(v.Doc))
		}
	}
	values("Constants", d.Consts)
	values("Variables", d.Vars)

	if len(d.Funcs) > 0 {
		b.WriteString("## Functions\n\n")
		for _, f := range d.Funcs {
			count++
			f.Decl.Body = nil
			fmt.Fprintf(&b, "### `%s`\n\n```go\n%s\n```\n\n%s\n", f.Name, sig(f.Decl), md(f.Doc))
		}
	}

	if len(d.Types) > 0 {
		b.WriteString("## Types\n\n")
		for _, t := range d.Types {
			count++
			fmt.Fprintf(&b, "### `%s`\n\n```go\n%s\n```\n\n%s\n", t.Name, sig(t.Decl), md(t.Doc))
			values("", nil)
			for _, v := range append(t.Consts, t.Vars...) {
				count += len(v.Names)
				fmt.Fprintf(&b, "```go\n%s\n```\n\n%s\n", sig(v.Decl), md(v.Doc))
			}
			for _, f := range t.Funcs { // constructors
				count++
				f.Decl.Body = nil
				fmt.Fprintf(&b, "#### `%s`\n\n```go\n%s\n```\n\n%s\n", f.Name, sig(f.Decl), md(f.Doc))
			}
			ms := append([]*doc.Func(nil), t.Methods...)
			sort.Slice(ms, func(i, j int) bool { return ms[i].Name < ms[j].Name })
			for _, m := range ms {
				count++
				m.Decl.Body = nil
				fmt.Fprintf(&b, "#### `%s.%s`\n\n```go\n%s\n```\n\n%s\n", t.Name, m.Name, sig(m.Decl), md(m.Doc))
			}
		}
	}

	if len(d.Examples) > 0 {
		b.WriteString("## Examples\n\nFrom the package's `example_test.go`, run by `go test`.\n\n")
		for _, ex := range d.Examples {
			name := "Example"
			if ex.Name != "" {
				name += "_" + ex.Name
			}
			var code bytes.Buffer
			_ = format.Node(&code, fset, ex.Code)
			fmt.Fprintf(&b, "### `%s`\n\n%s\n```go\n%s\n```\n\n", name, md(ex.Doc), strings.TrimSpace(code.String()))
			if ex.Output != "" {
				fmt.Fprintf(&b, "Output:\n\n```text\n%s\n```\n\n", strings.TrimSpace(ex.Output))
			}
		}
	}
	return b.Bytes(), count, nil
}
