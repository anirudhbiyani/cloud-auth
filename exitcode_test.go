package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// A validation failure is deliberately a different exit code from an operational
// one, so a pipeline can tell "the trust is misconfigured" from "the run itself
// broke" without parsing stderr.
//
// That promise used to be kept by calling os.Exit(2) inside cmdValidate, which
// skipped every deferred cleanup on the way out and made the function impossible
// to test: invoking it from a test killed the test binary rather than returning.

func TestValidationFailureIsDistinguishable(t *testing.T) {
	for _, tc := range []struct {
		name       string
		err        error
		wantIsVF   bool
		wantSubstr string
	}{
		{
			name:       "a validation failure",
			err:        errValidationFailed(errors.New("2 of 5 checks failed")),
			wantIsVF:   true,
			wantSubstr: "2 of 5 checks failed",
		},
		{
			name:     "an operational error",
			err:      errors.New("failed to list mechanisms"),
			wantIsVF: false,
		},
		{
			name:       "a validation failure wrapped further up",
			err:        fmt.Errorf("validate: %w", errValidationFailed(errors.New("unverified"))),
			wantIsVF:   true,
			wantSubstr: "unverified",
		},
		{
			name:     "an operational error wrapping a validation-shaped message",
			err:      fmt.Errorf("checks failed: %w", errors.New("network unreachable")),
			wantIsVF: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var vf validationFailure
			got := errors.As(tc.err, &vf)
			if got != tc.wantIsVF {
				t.Fatalf("errors.As = %v, want %v (exit code would be %d, want %d)",
					got, tc.wantIsVF, exitCodeFor(got), exitCodeFor(tc.wantIsVF))
			}
			// The cause must survive: a caller reading stderr still needs to know
			// what failed, not just that something did.
			if tc.wantSubstr != "" {
				if msg := tc.err.Error(); !strings.Contains(msg, tc.wantSubstr) {
					t.Errorf("message %q lost the cause %q", msg, tc.wantSubstr)
				}
			}
		})
	}
}

// The two codes must actually differ, or the distinction is decorative.
func TestExitCodesAreDistinct(t *testing.T) {
	if exitError == exitValidationError {
		t.Fatalf("exitError and exitValidationError are both %d", exitError)
	}
	if exitError == 0 || exitValidationError == 0 {
		t.Error("a failure exit code must not be 0")
	}
}

func exitCodeFor(isValidationFailure bool) int {
	if isValidationFailure {
		return exitValidationError
	}
	return exitError
}
