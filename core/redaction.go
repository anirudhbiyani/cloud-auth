package core

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strconv"
)

// This file makes the two secret-bearing types safe to hand to a logger.
//
// Credentials and SourceToken have exported secret fields because callers need
// them — that is the point of the SDK. But the same shape means one
// log.Printf("%+v", creds) or slog.Info("got creds", "c", creds) anywhere in a
// consuming application writes a live secret access key to disk. A consumer
// cannot reasonably be expected to remember that; the type can carry the rule
// instead.
//
// Every formatting path is covered, because covering only some of them is worse
// than covering none: it teaches people the type is safe, and then one
// uncovered path surprises them. String for fmt %s and %v, Format for %+v and
// %#v which otherwise bypass Stringer, LogValue for slog, and MarshalJSON for
// anything that serializes a struct into a log line or an HTTP response.
//
// Reveal is the one way to get the plaintext, named so it is obvious in review
// and greppable in an audit.

// redactedTail returns a short, non-reversible hint of a secret: enough to
// correlate two log lines or match against a cloud console, not enough to use.
// Short values are replaced wholesale, because a hint of a short secret is the
// secret.
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

// Format routes %v, %s, %q, %+v and %#v through String. Without it, %+v walks
// the struct fields directly and prints the secrets that String exists to hide.
func (c Credentials) Format(f fmt.State, verb rune) {
	writeRedacted(f, verb, c.String())
}

// LogValue implements slog.LogValuer.
func (c Credentials) LogValue() slog.Value { return slog.StringValue(c.String()) }

// MarshalJSON emits the redacted form. Credentials are not a wire type: anything
// that needs to transmit them (the credential_process contract, an env block)
// reads the fields explicitly via Reveal.
func (c Credentials) MarshalJSON() ([]byte, error) { return json.Marshal(c.String()) }

// RevealedCredentials is the plaintext view of a Credentials, returned only by
// Reveal. It has no String, Format, LogValue or MarshalJSON of its own, so a
// value of this type is visibly a value you are responsible for.
type RevealedCredentials struct {
	Cloud           Cloud
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	AccessToken     string
}

// Reveal returns the plaintext secrets. Call it at the boundary that genuinely
// needs them — signing a request, writing the credential_process JSON, building
// an env block — and do not hold the result any longer than that.
func (c Credentials) Reveal() RevealedCredentials {
	return RevealedCredentials{
		Cloud:           c.Cloud,
		AccessKeyID:     c.AccessKeyID,
		SecretAccessKey: c.SecretAccessKey,
		SessionToken:    c.SessionToken,
		AccessToken:     c.AccessToken,
	}
}

// String implements fmt.Stringer with the proof value redacted. Issuer, subject
// and audience are kept: they are the identity metadata that makes a federation
// error diagnosable, and none of them is a secret.
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
//
// %q quotes it; every other verb writes it plainly. The switch used to have two
// identical arms, so %q silently produced an unquoted string — which is only
// cosmetic, but a caller who wrote %q to get a safely-delimited value in a log
// line did not get one, and the code read as though they had.
//
// The default arm is the load-bearing half: without Format at all, %+v and %#v
// walk the struct fields directly and print exactly the secrets String exists to
// hide. Every verb therefore lands on the redacted form, including ones that do
// not exist yet.
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

// Reveal returns the raw proof — the JWT compact form, or the serialized
// pre-signed request — for handing to a target STS.
func (t SourceToken) Reveal() string { return t.Value }
