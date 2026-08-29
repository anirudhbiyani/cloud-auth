package verify

import (
	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/internal/redact"
)

// redactedMarker replaces any value that is, or merely looks like, a secret.
const redactedMarker = redact.Marker

// Scrubber removes credential material from anything the verifier prints.
//
// The redaction itself lives in internal/redact, which the SDK's own error and
// audit paths use: one implementation, so a pattern added because it leaked in
// production also protects the harness, and vice versa. What stays here is the
// harness-shaped convenience of registering whole cloud-auth values.
//
// Safe for concurrent use: cases may run in sequence today, but the scrubber is
// shared with the report writer.
type Scrubber struct {
	*redact.Scrubber
}

// NewScrubber returns an empty Scrubber. Shape-based patterns apply immediately;
// literals accumulate as credentials are observed.
func NewScrubber() *Scrubber { return &Scrubber{Scrubber: redact.NewScrubber()} }

// AddCredentials registers every secret-bearing field of a credential set. It
// deliberately does NOT register the request id or expiry: those are the
// identity metadata the report exists to carry.
func (s *Scrubber) AddCredentials(c *core.Credentials) {
	if c == nil {
		return
	}
	plain := c.Reveal()
	s.AddSecret(plain.AccessKeyID)
	s.AddSecret(plain.SecretAccessKey)
	s.AddSecret(plain.SessionToken)
	s.AddSecret(plain.AccessToken)
}

// AddToken registers a source proof's value, should one ever be handled.
func (s *Scrubber) AddToken(t *core.SourceToken) {
	if t != nil {
		s.AddSecret(t.Reveal())
	}
}
