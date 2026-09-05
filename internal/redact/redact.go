// Package redact removes credential material from text that is about to leave the process — an error string, an audit record, a diagnostic report.
package redact

import (
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Marker replaces any value that is, or merely looks like, a secret.
const Marker = "[REDACTED]"

// minSecretLen guards the literal pass: registering a very short "secret" would turn redaction into a censor that mangles ordinary text.
const minSecretLen = 8

// tokenPatterns catch secret-shaped text the caller never registered — an STS error body echoing back the assertion, a probe quoting a header, and so on.
var tokenPatterns = []*regexp.Regexp{
	// Compact JWT / client assertion: three base64url segments.
	regexp.MustCompile(`\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
	// Google OAuth access tokens.
	regexp.MustCompile(`\bya29\.[A-Za-z0-9._~+/-]{10,}={0,2}`),
	// Authorization headers of any scheme.
	regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/-]{8,}={0,2}`),
	// AWS access key ids (long-lived AKIA and session ASIA alike).
	regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{8,}\b`),
	// Long opaque blobs.
	regexp.MustCompile(`\b[A-Za-z0-9+_-]{40,}={0,2}`),
}

// String applies the pattern pass only.
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

// Truncate caps a string at max bytes, marking that it was cut.
func Truncate(in string, max int) string {
	if max <= 0 || len(in) <= max {
		return in
	}
	return in[:max] + "…[truncated]"
}

// Body prepares an upstream response body for inclusion in an error: pattern redaction, then a length cap.
func Body(in string, max int) string { return Truncate(String(in), max) }

// Scrubber applies the literal pass as well, for callers that hold the secrets and can register them.
type Scrubber struct {
	mu       sync.RWMutex
	literals []string
}

// NewScrubber returns an empty Scrubber.
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

// Scrub returns in with every registered secret and every secret-shaped run replaced.
func (s *Scrubber) Scrub(in string) string {
	if in == "" {
		return in
	}
	// Copy the CONTENTS, not the slice header.
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
