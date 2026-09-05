package main

import (
	"io"
	"log/slog"
	"os"
)

// Diagnostic logging for the CLI.

// logDest is where diagnostics go.
func logDest() io.Writer { return os.Stderr }

// newLogger returns the diagnostic logger.
func newLogger(verbose bool) *slog.Logger {
	level := slog.LevelWarn
	if verbose {
		level = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(logDest(), &slog.HandlerOptions{
		Level: level,
		// Timestamps are dropped: these are interactive diagnostics on a terminal, not a log stream, and the audit record — which IS the log stream — carries its own timestamp.
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
