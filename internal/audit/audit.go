// Package audit emits one structured JSON event per exchange, suitable for
// ingestion into a SIEM. Events carry the source identity, target, role, STS
// request-id, and outcome so every cross-cloud exchange is traceable.
package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/anirudhbiyani/cloud-auth/internal/redact"
)

// Event is a single audited exchange.
type Event struct {
	Timestamp      time.Time `json:"timestamp"`
	SourceIdentity string    `json:"source_identity"`
	TargetCloud    string    `json:"target_cloud"`
	Role           string    `json:"role"`
	STSRequestID   string    `json:"sts_request_id"`
	Outcome        string    `json:"outcome"` // "success" | "failure"
	Error          string    `json:"error,omitempty"`
	LatencyMS      int64     `json:"latency_ms"`
}

// Logger writes audit events as JSON lines.
//
// The mutex is not optional: an io.Writer makes no atomicity promise, so
// concurrent exchanges would interleave their JSON and, on a bufio.Writer or a
// bytes.Buffer, race outright. The audit log is the only record of who assumed
// what, so a torn line is a lost record.
type Logger struct {
	mu sync.Mutex
	w  io.Writer
}

// New builds a Logger writing to w.
func New(w io.Writer) *Logger { return &Logger{w: w} }

// Emit writes one event as a JSON line. Emission failures are ignored so
// auditing never blocks the exchange path.
//
// The Error field is redacted first. It carries whatever the exchange failed
// with, and upstream token endpoints echo request material into their error
// descriptions — so the record of a failure is exactly where a leaked assertion
// would come to rest, in the one file built for long-term retention.
func (l *Logger) Emit(e Event) {
	e.Error = redact.String(e.Error)
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(b)
}
