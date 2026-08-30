package main

import (
	"io"
	"os"
	"time"

	"github.com/anirudhbiyani/cloud-auth/internal/audit"
)

// Audit wiring for the CLI.
//
// audit.Emit had exactly one call site — the exchange command — which left the
// mutating control-plane operations, setup and delete, as the ones with no
// record at all, along with exec, which injects live credentials into a child
// process. This file gives every audited command the same shape and makes
// "exactly one record per operation" a property of the type rather than
// something each call site has to remember.

// auditDest is where audit records go.
//
// stderr, deliberately: the record must not land in the middle of a command's
// stdout, which for `exchange --format json` and `credential-process` is a
// document another program parses. A caller who wants the records in a file
// redirects stderr; a caller who wants them in a SIEM pipes it.
func auditDest() io.Writer { return os.Stderr }

// auditor accumulates one event and emits it exactly once.
//
// The guarantee matters on the error paths. An operation that returns early
// used to skip the record entirely, so the failures — the ones worth reviewing
// — were the ones least likely to be logged. finish() is idempotent, so it can
// be deferred and also called explicitly without producing two records.
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
			// Assume failure. An operation that dies in a way this file did not
			// anticipate is recorded as a failure rather than silently as a
			// success, which is the safe direction for a security record.
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
