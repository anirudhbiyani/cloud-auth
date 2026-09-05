package verify

import (
	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/internal/redact"
)

// redactedMarker replaces any value that is, or merely looks like, a secret.
const redactedMarker = redact.Marker

// Scrubber removes credential material from anything the verifier prints.
type Scrubber struct {
	*redact.Scrubber
}

// NewScrubber returns an empty Scrubber.
func NewScrubber() *Scrubber { return &Scrubber{Scrubber: redact.NewScrubber()} }

// AddCredentials registers every secret-bearing field of a credential set.
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
