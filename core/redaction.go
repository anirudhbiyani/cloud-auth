package core

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strconv"
)

// This file makes the two secret-bearing types safe to hand to a logger.

// redactedTail returns a short, non-reversible hint of a secret: enough to correlate two log lines or match against a cloud console, not enough to use.
func redactedTail(s string) string {
	const keep = 4
	if s == "" {
		return ""
	}
	if len(s) <= keep*2 {
		return "[REDACTED]"
	}
	return "[REDACTED…" + s[len(s)-keep:] + "]"
}

func nonEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// String implements fmt.Stringer with every secret field redacted.
func (c Credentials) String() string {
	return fmt.Sprintf("Credentials{Cloud:%s AccessKeyID:%s SecretAccessKey:%s SessionToken:%s "+
		"AccessToken:%s Expiry:%s STSRequestID:%s}",
		nonEmpty(string(c.Cloud)),
		nonEmpty(redactedTail(c.AccessKeyID)),
		nonEmpty(redactedTail(c.SecretAccessKey)),
		nonEmpty(redactedTail(c.SessionToken)),
		nonEmpty(redactedTail(c.AccessToken)),
		c.expiryString(),
		nonEmpty(c.STSRequestID))
}

func (c Credentials) expiryString() string {
	if c.Expiry.IsZero() {
		return "unknown"
	}
	return c.Expiry.UTC().Format("2006-01-02T15:04:05Z")
}

// Format routes %v, %s, %q, %+v and %#v through String.
func (c Credentials) Format(f fmt.State, verb rune) {
	writeRedacted(f, verb, c.String())
}

// LogValue implements slog.LogValuer.
func (c Credentials) LogValue() slog.Value { return slog.StringValue(c.String()) }

// MarshalJSON emits the redacted form.
func (c Credentials) MarshalJSON() ([]byte, error) { return json.Marshal(c.String()) }

// RevealedCredentials is the plaintext view of a Credentials, returned only by Reveal.
type RevealedCredentials struct {
	Cloud           Cloud
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	AccessToken     string
}

// Reveal returns the plaintext secrets.
func (c Credentials) Reveal() RevealedCredentials {
	return RevealedCredentials{
		Cloud:           c.Cloud,
		AccessKeyID:     c.AccessKeyID,
		SecretAccessKey: c.SecretAccessKey,
		SessionToken:    c.SessionToken,
		AccessToken:     c.AccessToken,
	}
}

// String implements fmt.Stringer with the proof value redacted.
func (t SourceToken) String() string {
	return fmt.Sprintf("SourceToken{Kind:%s Value:%s Issuer:%s Subject:%s Audience:%s Expiry:%s}",
		t.Kind,
		nonEmpty(redactedTail(t.Value)),
		nonEmpty(t.Issuer),
		nonEmpty(t.Subject),
		nonEmpty(t.Audience),
		t.expiryString())
}

func (t SourceToken) expiryString() string {
	if t.Expiry.IsZero() {
		return "n/a"
	}
	return t.Expiry.UTC().Format("2006-01-02T15:04:05Z")
}

// Format routes every verb through String, for the same reason as Credentials.
func (t SourceToken) Format(f fmt.State, verb rune) {
	writeRedacted(f, verb, t.String())
}

// writeRedacted emits the redacted string for any verb.
func writeRedacted(f fmt.State, verb rune, s string) {
	if verb == 'q' {
		_, _ = io.WriteString(f, strconv.Quote(s))
		return
	}
	_, _ = io.WriteString(f, s)
}

// LogValue implements slog.LogValuer.
func (t SourceToken) LogValue() slog.Value { return slog.StringValue(t.String()) }

// MarshalJSON emits the redacted form.
func (t SourceToken) MarshalJSON() ([]byte, error) { return json.Marshal(t.String()) }

// Reveal returns the raw proof — the JWT compact form, or the serialized pre-signed request — for handing to a target STS.
func (t SourceToken) Reveal() string { return t.Value }
