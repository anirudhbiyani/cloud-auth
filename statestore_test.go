package main

import (
	"strings"
	"testing"
)

// A malformed s3:// location must be refused, not fallen through to a file path.
func TestMalformedS3LocationIsRefused(t *testing.T) {
	for _, location := range []string{
		"s3://nobucket",
		"s3://nobucket/",
		"s3://",
	} {
		t.Run(location, func(t *testing.T) {
			_, err := openStateStore(t.Context(), location)
			if err == nil {
				t.Fatal("a malformed s3 location was accepted")
			}
			if !strings.Contains(err.Error(), "s3://<bucket>/<key>") {
				t.Errorf("the error does not say what shape is needed: %v", err)
			}
		})
	}
}

// An ordinary path still opens a file store.
func TestFilePathOpensAFileStore(t *testing.T) {
	store, err := openStateStore(t.Context(), t.TempDir()+"/state.json")
	if err != nil {
		t.Fatalf("openStateStore: %v", err)
	}
	if store == nil {
		t.Fatal("no store returned")
	}
}
