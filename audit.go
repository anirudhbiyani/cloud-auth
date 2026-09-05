package main

import (
	"io"
	"os"
	"time"

	"github.com/anirudhbiyani/cloud-auth/internal/audit"
)

// Audit wiring for the CLI.

// auditDest is where audit records go.
func auditDest() io.Writer { return os.Stderr }

// auditor accumulates one event and emits it exactly once.
type auditor struct {
	log      *audit.Logger
	event    audit.Event
	start    time.Time
	finished bool
}

// newAuditor starts recording an operation.
func newAuditor(op audit.Operation) *auditor {
	start := time.Now()
	return &auditor{
		log:   audit.New(auditDest()),
		start: start,
		event: audit.Event{
			Timestamp: start.UTC(),
			Operation: op,
			// Assume failure.
			Outcome: audit.OutcomeFailure,
		},
	}
}

// with mutates the pending event.
func (a *auditor) with(fn func(*audit.Event)) *auditor {
	fn(&a.event)
	return a
}

// finish emits the record. Safe to call more than once; only the first counts.
func (a *auditor) finish(err error) error {
	if a.finished {
		return err
	}
	a.finished = true

	a.event.LatencyMS = time.Since(a.start).Milliseconds()
	if err != nil {
		a.event.Outcome, a.event.Error = audit.OutcomeFailure, err.Error()
	} else {
		a.event.Outcome, a.event.Error = audit.OutcomeSuccess, ""
	}
	a.log.Emit(a.event)
	return err
}
