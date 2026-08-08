package audit

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestEmitWritesStructuredJSONLine(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	l.Emit(Event{
		Timestamp:      time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC),
		SourceIdentity: "sa@proj.iam",
		TargetCloud:    "aws",
		Role:           "arn:aws:iam::123:role/r",
		STSRequestID:   "req-1",
		Outcome:        "success",
		LatencyMS:      42,
	})

	line := buf.Bytes()
	if line[len(line)-1] != '\n' {
		t.Error("audit event must end with a newline (JSON-lines)")
	}
	var got map[string]any
	if err := json.Unmarshal(line, &got); err != nil {
		t.Fatalf("event is not valid JSON: %v", err)
	}
	for _, k := range []string{"timestamp", "source_identity", "target_cloud", "role", "sts_request_id", "outcome", "latency_ms"} {
		if _, ok := got[k]; !ok {
			t.Errorf("audit event missing field %q", k)
		}
	}
	if got["outcome"] != "success" {
		t.Errorf("outcome = %v", got["outcome"])
	}
}
