// Package audit emits one structured JSON event per audited operation, suitable
// for ingestion into a SIEM. Events carry the source identity, target, role, STS
// request-id and outcome, so every credential issued and every trust
// relationship created or destroyed is traceable.
//
// "Audited operation" originally meant an exchange, and for a while that was the
// only call site — which left the MUTATING control-plane operations, setup and
// delete, as precisely the ones with no record. Operation now names which one
// produced the event.
package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/anirudhbiyani/cloud-auth/internal/redact"
)

// Operation names the audited action.
type Operation string

const (
	// OpExchange issued short-lived target credentials.
	OpExchange Operation = "exchange"
	// OpExec issued credentials and injected them into a child process.
	OpExec Operation = "exec"
	// OpCredentialProcess issued credentials via the AWS credential_process
	// contract.
	OpCredentialProcess Operation = "credential-process"
	// OpSetup created or updated a trust relationship.
	OpSetup Operation = "setup"
	// OpDelete destroyed a trust relationship.
	OpDelete Operation = "delete"
)

// Outcomes.
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
)

// Event is a single audited operation.
//
// The exchange fields and the control-plane fields are both omitempty because
// no single operation fills all of them: an exchange has an STS request id and
// no mechanism, a setup has a mechanism and no STS request id. Operation says
// which shape to expect.
type Event struct {
	Timestamp time.Time `json:"timestamp"`
	Operation Operation `json:"operation"`

	// Exchange fields.
	SourceIdentity string `json:"source_identity,omitempty"`
	TargetCloud    string `json:"target_cloud,omitempty"`
	Role           string `json:"role,omitempty"`
	STSRequestID   string `json:"sts_request_id,omitempty"`

	// Control-plane fields.
	MechanismID   string `json:"mechanism_id,omitempty"`
	MechanismType string `json:"mechanism_type,omitempty"`
	Provider      string `json:"provider,omitempty"`
	DryRun        bool   `json:"dry_run,omitempty"`

	Outcome   string `json:"outcome"` // "success" | "failure"
	Error     string `json:"error,omitempty"`
	LatencyMS int64  `json:"latency_ms"`
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
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(b)
}
