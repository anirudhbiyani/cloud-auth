package verify

import (
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
)

// redactedMarker replaces any value that is, or merely looks like, a secret.
const redactedMarker = "[REDACTED]"

// minSecretLen guards the literal pass: registering a very short "secret" would
// turn redaction into a censor that mangles ordinary text.
const minSecretLen = 8

// tokenPatterns catch secret-shaped text the verifier never registered — an STS
// error body echoing back the assertion, a probe quoting a header, and so on.
// They are defense in depth behind the exact-literal pass in Scrubber.
//
// Each pattern is deliberately narrow enough that identity metadata survives:
// role ARNs, issuer URLs, `system:serviceaccount:...` subjects and
// `//iam.googleapis.com/projects/.../providers/...` pool paths must remain
// readable, because they are the whole point of the report.
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

// Scrubber removes credential material from anything the verifier prints. It
// combines an exact-literal pass (every credential value the run has seen) with
// shape-based patterns for values it never held.
//
// It is safe for concurrent use: cases may run in sequence today, but the
// scrubber is shared with the report writer.
type Scrubber struct {
	mu       sync.RWMutex
	literals []string
}

// NewScrubber returns an empty Scrubber. Shape-based patterns apply immediately;
// literals accumulate as credentials are observed.
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

// AddCredentials registers every secret-bearing field of a credential set. It
// deliberately does NOT register the request id or expiry: those are the
// identity metadata the report exists to carry.
func (s *Scrubber) AddCredentials(c *cloudauth.Credentials) {
	if c == nil {
		return
	}
	s.AddSecret(c.AccessKeyID)
	s.AddSecret(c.SecretAccessKey)
	s.AddSecret(c.SessionToken)
	s.AddSecret(c.AccessToken)
}

// AddToken registers a source proof's value, should one ever be handled.
func (s *Scrubber) AddToken(t *cloudauth.SourceToken) {
	if t != nil {
		s.AddSecret(t.Value)
	}
}

// Scrub returns in with every known secret and every secret-shaped run replaced.
func (s *Scrubber) Scrub(in string) string {
	if in == "" {
		return in
	}
	s.mu.RLock()
	literals := s.literals
	s.mu.RUnlock()

	out := in
	for _, lit := range literals {
		out = strings.ReplaceAll(out, lit, redactedMarker)
	}
	for _, re := range tokenPatterns {
		out = re.ReplaceAllString(out, redactedMarker)
	}
	return out
}

// ScrubBytes applies Scrub to a serialized document. The report is scrubbed
// twice — once per field as it is built, once over the rendered bytes — so a
// field added later without thinking still cannot leak.
func (s *Scrubber) ScrubBytes(b []byte) []byte { return []byte(s.Scrub(string(b))) }
