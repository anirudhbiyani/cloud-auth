package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `list --output json` is what a script reads. It printed the prose
// "No mechanisms found" whenever the state file was empty — the one case a
// script is most likely to hit — because the empty check returned before the
// output switch. And the table separator was fmt.Println(string(make([]byte,
// 100))): 100 NUL bytes, not a rule.

// captureStdout runs fn with os.Stdout redirected and returns what it wrote.
// cmdList writes with fmt.Println, so there is no writer to inject.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	saved := os.Stdout
	os.Stdout = w
	runErr := fn()
	os.Stdout = saved
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return sb.String(), runErr
}

// stateFile writes a state document and returns its path.
func stateFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}
	return path
}

func TestListJSONIsAlwaysValidJSON(t *testing.T) {
	populated := `{
	  "version": 1,
	  "mechanisms": {
	    "aws_role_trust_oidc-aws-abc123": {
	      "id": "aws_role_trust_oidc-aws-abc123",
	      "type": "aws_role_trust_oidc",
	      "provider": "aws",
	      "owned": true,
	      "created_at": "2026-08-01T00:00:00Z"
	    }
	  }
	}`

	for _, tc := range []struct {
		name  string
		state string
		want  int
	}{
		{"empty state", `{"version":1,"mechanisms":{}}`, 0},
		{"one mechanism", populated, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := stateFile(t, tc.state)
			out, err := captureStdout(t, func() error {
				return cmdList(context.Background(), []string{"--state", path, "--output", "json"})
			})
			if err != nil {
				t.Fatalf("cmdList: %v", err)
			}

			var refs []map[string]any
			if err := json.Unmarshal([]byte(out), &refs); err != nil {
				t.Fatalf("output is not valid JSON (%v):\n%s", err, out)
			}
			if len(refs) != tc.want {
				t.Errorf("got %d mechanisms, want %d", len(refs), tc.want)
			}
			// Empty must marshal as [], never null: a consumer doing
			// `for _, m := range parsed` should not have to special-case it.
			if tc.want == 0 && !strings.Contains(out, "[]") {
				t.Errorf("empty list should render as [], got:\n%s", out)
			}
		})
	}
}

func TestListTablePrintsAVisibleRule(t *testing.T) {
	path := stateFile(t, `{
	  "version": 1,
	  "mechanisms": {
	    "aws_role_trust_oidc-aws-abc123": {
	      "id": "aws_role_trust_oidc-aws-abc123",
	      "type": "aws_role_trust_oidc",
	      "provider": "aws",
	      "owned": true,
	      "created_at": "2026-08-01T00:00:00Z"
	    }
	  }
	}`)

	out, err := captureStdout(t, func() error {
		return cmdList(context.Background(), []string{"--state", path, "--output", "table"})
	})
	if err != nil {
		t.Fatalf("cmdList: %v", err)
	}
	if strings.ContainsRune(out, '\x00') {
		t.Error("table output contains NUL bytes; the separator is not a rule")
	}
	if !strings.Contains(out, strings.Repeat("-", 100)) {
		t.Errorf("no 100-character rule in table output:\n%q", out)
	}
}

// The empty case still reads well for a human.
func TestListTableSaysSoWhenEmpty(t *testing.T) {
	path := stateFile(t, `{"version":1,"mechanisms":{}}`)
	out, err := captureStdout(t, func() error {
		return cmdList(context.Background(), []string{"--state", path, "--output", "table"})
	})
	if err != nil {
		t.Fatalf("cmdList: %v", err)
	}
	if !strings.Contains(out, "No mechanisms found") {
		t.Errorf("want the human-readable empty message, got:\n%q", out)
	}
}
