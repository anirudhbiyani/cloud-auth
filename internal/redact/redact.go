// Package redact removes credential material from text that is about to leave
// the process — an error string, an audit record, a diagnostic report.
//
// It combines two passes. The literal pass replaces exact values the caller has
// registered, which is precise and catches secrets of any shape. The pattern
// pass replaces secret-shaped runs the caller never held, which is imprecise but
// catches the case that actually bites: an upstream error body echoing back
// material we never saw and therefore could not register.
//
// This package has no dependencies, deliberately. It is imported by the packages
// that format errors and records, and it must never be the reason one of them
// gains a dependency edge.
package redact

import (
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Marker replaces any value that is, or merely looks like, a secret.
const Marker = "[REDACTED]"

// minSecretLen guards the literal pass: registering a very short "secret" would
// turn redaction into a censor that mangles ordinary text.
const minSecretLen = 8

// tokenPatterns catch secret-shaped text the caller never registered — an STS
// error body echoing back the assertion, a probe quoting a header, and so on.
//
// Each pattern is deliberately narrow enough that identity metadata survives:
// role ARNs, issuer URLs, `system:serviceaccount:...` subjects and
// `//iam.googleapis.com/projects/.../providers/...` pool paths must stay
// readable, because they are what makes an error actionable.
var tokenPatterns = []*regexp.Regexp{
	// Compact JWT / client assertion: three base64url segments.
	regexp.MustCompile(`\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
	// Google OAuth access tokens.
	regexp.MustCompile(`\bya29\.[A-Za-z0-9._~+/-]{10,}={0,2}`),
	// Authorization headers of any scheme.
	regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/-]{8,}={0,2}`),
	// AWS access key ids (long-lived AKIA and session ASIA alike).
	regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{8,}\b`),
	// Long opaque blobs. '/' and '.' are excluded from the class so resource
	// paths and hostnames are never swallowed whole.
	regexp.MustCompile(`\b[A-Za-z0-9+_-]{40,}={0,2}`),
}

// String applies the pattern pass only. Use it where there is no scrubber to
// carry registered literals — an error being formatted deep in a call stack.
func String(in string) string {
	if in == "" {
		return in
	}
	out := in
	for _, re := range tokenPatterns {
		out = re.ReplaceAllString(out, Marker)
	}
	return out
}

// Truncate caps a string at max bytes, marking that it was cut. Upstream error
// bodies are unbounded, and an error is a diagnostic, not a transcript.
func Truncate(in string, max int) string {
	if max <= 0 || len(in) <= max {
		return in
	}
	return in[:max] + "…[truncated]"
}

// Body prepares an upstream response body for inclusion in an error: pattern
// redaction, then a length cap.
func Body(in string, max int) string { return Truncate(String(in), max) }

// Scrubber applies the literal pass as well, for callers that hold the secrets
// and can register them. Safe for concurrent use.
type Scrubber struct {
	mu       sync.RWMutex
	literals []string
}

// NewScrubber returns an empty Scrubber. Pattern redaction applies immediately;
// literals accumulate as secrets are observed.
func NewScrubber() *Scrubber { return &Scrubber{} }

// AddSecret registers an exact value that must never appear in output.
func (s *Scrubber) AddSecret(v string) {
	if len(v) < minSecretLen {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.literals {
		if existing == v {
			return
		}
	}
	s.literals = append(s.literals, v)
	// Longest first, so a secret that contains another is redacted whole.
	sort.Slice(s.literals, func(i, j int) bool { return len(s.literals[i]) > len(s.literals[j]) })
}

// Scrub returns in with every registered secret and every secret-shaped run
// replaced.
func (s *Scrubber) Scrub(in string) string {
	if in == "" {
		return in
	}
	// Copy the CONTENTS, not the slice header. The header alone still points at
	// the backing array that AddSecret sorts in place, so releasing the lock and
	// then ranging over it raced with a concurrent registration — and the race
	// was not benign here: re-ordering the array mid-iteration can move a
	// literal past the cursor, so a secret that was registered is never
	// substituted and reaches the output intact.
	//
	// The copy is a handful of strings; the alternative is holding the lock
	// across every ReplaceAll, which serializes redaction on the slowest caller.
	s.mu.RLock()
	literals := make([]string, len(s.literals))
	copy(literals, s.literals)
	s.mu.RUnlock()

	out := in
	for _, lit := range literals {
		out = strings.ReplaceAll(out, lit, Marker)
	}
	return String(out)
}

// ScrubBytes applies Scrub to a serialized document.
func (s *Scrubber) ScrubBytes(b []byte) []byte { return []byte(s.Scrub(string(b))) }
