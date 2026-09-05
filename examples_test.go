package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Every shipped example must load and validate.
func TestShippedExamplesValidate(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("examples", "*.json"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("no examples found; this test is meant to cover them")
	}

	for _, path := range paths {
		name := filepath.Base(path)
		t.Run(name, func(t *testing.T) {
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("stat: %v", err)
			}
			spec, err := loadSpec(path)
			if err != nil {
				t.Fatalf("loadSpec: %v", err)
			}
			if err := spec.Validate(); err != nil {
				t.Fatalf("%s does not validate: %v", path, err)
			}
		})
	}
}
