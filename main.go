// Command cloud-auth establishes cross-cloud trust relationships and obtains short-lived credentials at workload run time, with no static secrets.
package main

import (
	"errors"
	"fmt"
	"os"
)

// Exit codes.
const (
	exitError           = 1
	exitValidationError = 2
)

// errValidationFailed marks a validation outcome, as opposed to an operational failure.
type validationFailure struct{ error }

// errValidationFailed wraps err as a validation failure.
func errValidationFailed(err error) error { return validationFailure{err} }

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)

		var vf validationFailure
		if errors.As(err, &vf) {
			os.Exit(exitValidationError)
		}
		os.Exit(exitError)
	}
}
