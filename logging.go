package main

import (
	"io"
	"log/slog"
	"os"
)

// Diagnostic logging for the CLI.
//
// The split this file exists to enforce: RESULTS go to stdout, DIAGNOSTICS go to
// stderr. A result is the thing the user asked for — a validation report, a
// credential document, a table of mechanisms — and something downstream may be
// parsing it. A diagnostic is commentary about producing it.
//
// Before this, both went to stdout through fmt.Printf, so progress lines and
// warnings were mixed into output another program reads. core/redaction.go
// already implemented slog.LogValuer so that credentials redact themselves IF
// anyone logged them; nothing ever did, because there was no logger.

// logDest is where diagnostics go.
func logDest() io.Writer { return os.Stderr }

// newLogger returns the diagnostic logger.
//
// Without --verbose the level is Warn, so a normal run says nothing unless
// something is worth saying — the previous behaviour for the noisy setup
// preamble, which was already gated behind a verbose check, generalized to
// every command.
func newLogger(verbose bool) *slog.Logger {
	level := slog.LevelWarn
	if verbose {
		level = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(logDest(), &slog.HandlerOptions{
		Level: level,
		// Timestamps are dropped: these are interactive diagnostics on a
		// terminal, not a log stream, and the audit record — which IS the log
		// stream — carries its own timestamp.
		ReplaceAttr: dropTime,
	}))
}

// dropTime removes the time attribute from top-level records.
func dropTime(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 && a.Key == slog.TimeKey {
		return slog.Attr{}
	}
	return a
}
