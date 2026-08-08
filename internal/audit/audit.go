// Package audit emits one structured JSON event per exchange, suitable for
// ingestion into a SIEM. Events carry the source identity, target, role, STS
// request-id, and outcome so every cross-cloud exchange is traceable.
package audit

import (
	"encoding/json"
	"io"
	"time"
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
type Logger struct {
	w io.Writer
}

// New builds a Logger writing to w.
func New(w io.Writer) *Logger { return &Logger{w: w} }

// Emit writes one event as a JSON line. Emission failures are ignored so
// auditing never blocks the exchange path.
func (l *Logger) Emit(e Event) {
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')
	_, _ = l.w.Write(b)
}
