package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

const (
	fakeAccessKey = "ASIAIOSFODNN7EXAMPLE"
	fakeSecret    = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	fakeSession   = "FwoGZXIvYXdzEBYaDNOTAREALSESSIONTOKENVALUE"
	fakeBearer    = "ya29.a0AfB_NOTAREALGOOGLEACCESSTOKENVALUE"
	fakeJWT       = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzeXN0ZW06c2EifQ.NOTAREALSIGNATURE"
)

func sampleCredentials() Credentials {
	return Credentials{
		Cloud:           AWS,
		AccessKeyID:     fakeAccessKey,
		SecretAccessKey: fakeSecret,
		SessionToken:    fakeSession,
		AccessToken:     fakeBearer,
		Expiry:          time.Date(2026, 8, 22, 13, 0, 0, 0, time.UTC),
		STSRequestID:    "req-abc-123",
	}
}

// Every formatting path must be covered.
func TestCredentialsNeverRenderSecrets(t *testing.T) {
	c := sampleCredentials()
	secrets := []string{fakeAccessKey, fakeSecret, fakeSession, fakeBearer}

	jsonBytes, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var logBuf bytes.Buffer
	slog.New(slog.NewTextHandler(&logBuf, nil)).Info("creds", "c", c)

	renders := map[string]string{
		"%v":            fmt.Sprintf("%v", c),
		"%+v":           fmt.Sprintf("%+v", c),
		"%#v":           fmt.Sprintf("%#v", c),
		"%s":            fmt.Sprintf("%s", c),
		"%q":            fmt.Sprintf("%q", c),
		"String()":      c.String(),
		"Sprint":        fmt.Sprint(c),
		"json.Marshal":  string(jsonBytes),
		"slog":          logBuf.String(),
		"pointer %+v":   fmt.Sprintf("%+v", &c),
		"in a slice":    fmt.Sprintf("%v", []Credentials{c}),
		"in a map":      fmt.Sprintf("%v", map[string]Credentials{"k": c}),
		"wrapped error": fmt.Errorf("exchange failed for %v", c).Error(),
	}

	for path, out := range renders {
		for _, secret := range secrets {
			if strings.Contains(out, secret) {
				t.Errorf("%s leaked a secret:\n  %s", path, out)
			}
		}
		if !strings.Contains(out, "REDACTED") {
			t.Errorf("%s produced no redaction marker, is it going through String()?\n  %s", path, out)
		}
	}
}

// Identity metadata must survive, or the redaction has made errors useless.
func TestCredentialsKeepDiagnosticMetadata(t *testing.T) {
	got := sampleCredentials().String()
	for _, want := range []string{"aws", "req-abc-123", "2026-08-22T13:00:00Z"} {
		if !strings.Contains(got, want) {
			t.Errorf("String() dropped %q, which is what makes an error actionable: %s", want, got)
		}
	}
}

func TestSourceTokenNeverRendersItsProof(t *testing.T) {
	tok := SourceToken{
		Kind:     OIDC,
		Value:    fakeJWT,
		Issuer:   "https://token.actions.githubusercontent.com",
		Subject:  "repo:myorg/myrepo:ref:refs/heads/main",
		Audience: "sts.amazonaws.com",
		Expiry:   time.Date(2026, 8, 22, 13, 0, 0, 0, time.UTC),
	}
	jsonBytes, _ := json.Marshal(tok)
	renders := []string{
		fmt.Sprintf("%v", tok), fmt.Sprintf("%+v", tok), fmt.Sprintf("%s", tok),
		tok.String(), string(jsonBytes), fmt.Sprintf("%v", &tok),
	}
	for _, out := range renders {
		if strings.Contains(out, fakeJWT) {
			t.Errorf("rendered the raw proof: %s", out)
		}
	}
	// Issuer, subject and audience are not secrets, and they are the whole content of a federation diagnosis.
	for _, want := range []string{"token.actions.githubusercontent.com", "repo:myorg/myrepo", "sts.amazonaws.com"} {
		if !strings.Contains(tok.String(), want) {
			t.Errorf("String() dropped %q: %s", want, tok.String())
		}
	}
}

// A short secret must be replaced wholesale: a four-character hint of an eight-character value is most of the value.
func TestRedactedTailDoesNotHintAtShortSecrets(t *testing.T) {
	if got := redactedTail("short"); strings.Contains(got, "short") {
		t.Errorf("redactedTail(%q) = %q, leaks the value", "short", got)
	}
	if got := redactedTail("abcdefgh"); strings.Contains(got, "efgh") {
		t.Errorf("redactedTail of an 8-char value must not show a tail, got %q", got)
	}
}

func TestRevealIsTheOnlyWayToPlaintext(t *testing.T) {
	c := sampleCredentials()
	plain := c.Reveal()
	if plain.SecretAccessKey != fakeSecret || plain.SessionToken != fakeSession {
		t.Fatal("Reveal must return the real values; the plaintext consumers depend on it")
	}
	if tok := (SourceToken{Value: fakeJWT}).Reveal(); tok != fakeJWT {
		t.Fatal("SourceToken.Reveal must return the raw proof")
	}
}
