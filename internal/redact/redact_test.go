package redact

import (
	"strings"
	"sync"
	"testing"
)

// This package is a security control with five regexes, and it had no direct tests — only indirect coverage through target/redaction_test.go and the verifier.

func TestStringRedactsCredentialShapes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		in     string
		leaked string // must NOT survive
		keep   string // must survive
	}{
		{
			name:   "compact JWT",
			in:     "assertion eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyZXBvOm9yZy9yZXBvIn0.c2lnbmF0dXJlLW1hdGVyaWFs failed validation",
			leaked: "c2lnbmF0dXJlLW1hdGVyaWFs",
			keep:   "failed validation",
		},
		{
			name:   "Google OAuth token",
			in:     "token ya29.a0AfH6SMBx7Qk3n2LmNoPqRsTuVwXyZ0123456789 is expired",
			leaked: "ya29.a0AfH6SMBx7Qk3n2LmNoPqRsTuVwXyZ0123456789",
			keep:   "is expired",
		},
		{
			name:   "bearer header",
			in:     "sent Authorization: Bearer abcdef1234567890abcdef to the endpoint",
			leaked: "abcdef1234567890abcdef",
			keep:   "to the endpoint",
		},
		{
			name:   "basic header",
			in:     "Authorization: Basic dXNlcjpwYXNzd29yZDEyMw== rejected",
			leaked: "dXNlcjpwYXNzd29yZDEyMw",
			keep:   "rejected",
		},
		{
			name:   "long-lived AWS access key id",
			in:     "credential AKIAIOSFODNN7EXAMPLE is not authorized",
			leaked: "AKIAIOSFODNN7EXAMPLE",
			keep:   "is not authorized",
		},
		{
			name:   "session access key id",
			in:     "credential ASIAIOSFODNN7EXAMPLE is not authorized",
			leaked: "ASIAIOSFODNN7EXAMPLE",
			keep:   "is not authorized",
		},
		{
			name:   "long opaque blob",
			in:     "session token AQoDYXdzEPT1234567890abcdefghijklmnopqrstuvwxyzABCDEFGH was rejected",
			leaked: "AQoDYXdzEPT1234567890abcdefghijklmnopqrstuvwxyzABCDEFGH",
			keep:   "was rejected",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := String(tc.in)
			if strings.Contains(out, tc.leaked) {
				t.Errorf("credential material survived:\n in:  %s\n out: %s", tc.in, out)
			}
			if !strings.Contains(out, Marker) {
				t.Errorf("nothing was marked as redacted: %s", out)
			}
			if !strings.Contains(out, tc.keep) {
				t.Errorf("the diagnosable part was eaten:\n want to keep: %q\n out: %s", tc.keep, out)
			}
		})
	}
}

// The half that is easy to get wrong.
func TestStringPreservesIdentityMetadata(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
	}{
		{"AWS role ARN", "arn:aws:iam::123456789012:role/github-actions-deploy"},
		{"AWS role ARN in a partition", "arn:aws-us-gov:iam::123456789012:role/deploy"},
		{"GitHub subject", "repo:myorg/myrepo:ref:refs/heads/main"},
		{"GitHub immutable subject", "repo:myorg@123456/myrepo@456789:ref:refs/heads/main"},
		{"Kubernetes subject", "system:serviceaccount:payments:ledger"},
		{"GCP pool path", "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/ci/providers/github"},
		{"GCP service account", "deployer@my-project.iam.gserviceaccount.com"},
		{"issuer URL", "https://token.actions.githubusercontent.com"},
		{"EKS OIDC issuer", "https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E"},
		{"Entra audience", "api://AzureADTokenExchange"},
		{"Entra tenant GUID", "11111111-1111-1111-1111-111111111111"},
		{"AADSTS code", "AADSTS70021: No matching federated identity record found."},
		{"account id", "123456789012"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := String(tc.in); got != tc.in {
				t.Errorf("identity metadata was redacted, making the error unactionable:\n in:  %s\n out: %s", tc.in, got)
			}
		})
	}
}

func TestStringLeavesOrdinaryTextAlone(t *testing.T) {
	for _, in := range []string{
		"",
		"permission denied",
		"the trust policy has no subject condition",
		"could not reach the metadata server: connection refused",
	} {
		if got := String(in); got != in {
			t.Errorf("String(%q) = %q, want it unchanged", in, got)
		}
	}
}

func TestTruncate(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		max  int
		want string
	}{
		{"under the cap", "short", 10, "short"},
		{"exactly the cap", "exactly10!", 10, "exactly10!"},
		{"over the cap", "0123456789abc", 10, "0123456789…[truncated]"},
		{"zero means no cap", "anything at all", 0, "anything at all"},
		{"negative means no cap", "anything at all", -1, "anything at all"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Truncate(tc.in, tc.max); got != tc.want {
				t.Errorf("Truncate(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
			}
		})
	}
}

// Body is redaction then a length cap, in that order.
func TestBodyRedactsBeforeTruncating(t *testing.T) {
	const secret = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0.c2lnbmF0dXJlLW1hdGVyaWFsLWhlcmU"
	out := Body("upstream said: "+secret+" and then some more text", 40)

	if strings.Contains(out, "c2lnbmF0dXJl") {
		t.Errorf("a truncated secret leaked its prefix: %s", out)
	}
	if !strings.Contains(out, "[truncated]") {
		t.Errorf("the cap was not applied: %s", out)
	}
}

// The literal pass catches secrets of any shape, including ones no pattern would.
func TestScrubberRedactsRegisteredLiterals(t *testing.T) {
	s := NewScrubber()
	// A password: no pattern matches it, only registration can.
	s.AddSecret("correct horse battery staple")

	out := s.Scrub("login failed for correct horse battery staple on host db-1")
	if strings.Contains(out, "correct horse") {
		t.Errorf("the registered literal survived: %s", out)
	}
	if !strings.Contains(out, "host db-1") {
		t.Errorf("surrounding context was lost: %s", out)
	}
}

// Registering a very short "secret" would turn redaction into a censor that mangles ordinary words.
func TestScrubberIgnoresShortSecrets(t *testing.T) {
	s := NewScrubber()
	s.AddSecret("abc")
	s.AddSecret("1234567") // one below the minimum

	const in = "abc appears in abcdef and 1234567 too"
	if got := s.Scrub(in); got != in {
		t.Errorf("a short secret was registered and mangled ordinary text:\n in:  %s\n out: %s", in, got)
	}
}

// Longest-first ordering: a secret that contains another must be redacted whole, or the outer one is left as [REDACTED]-plus-its-own-tail.
func TestScrubberRedactsOverlappingSecretsWhole(t *testing.T) {
	s := NewScrubber()
	s.AddSecret("inner-secret-value")
	s.AddSecret("inner-secret-value-with-suffix")

	out := s.Scrub("token inner-secret-value-with-suffix rejected")
	if strings.Contains(out, "with-suffix") {
		t.Errorf("the longer secret was only partly redacted: %s", out)
	}
	if got := strings.Count(out, Marker); got != 1 {
		t.Errorf("got %d markers, want 1 (%s)", got, out)
	}
}

func TestScrubberDeduplicates(t *testing.T) {
	s := NewScrubber()
	for range 5 {
		s.AddSecret("the-same-secret-value")
	}
	if got := len(s.literals); got != 1 {
		t.Errorf("registered %d copies of one secret, want 1", got)
	}
}

// A scrubber applies BOTH passes: registered literals and the patterns.
func TestScrubberAppliesBothPasses(t *testing.T) {
	s := NewScrubber()
	s.AddSecret("registered-literal-secret")

	out := s.Scrub("literal registered-literal-secret and key AKIAIOSFODNN7EXAMPLE")
	if strings.Contains(out, "registered-literal-secret") {
		t.Error("the literal pass did not run")
	}
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("the pattern pass did not run")
	}
}

func TestScrubBytes(t *testing.T) {
	s := NewScrubber()
	s.AddSecret("secret-in-a-document")
	out := s.ScrubBytes([]byte(`{"error":"secret-in-a-document"}`))
	if strings.Contains(string(out), "secret-in-a-document") {
		t.Errorf("the secret survived: %s", out)
	}
	if !strings.Contains(string(out), `{"error":`) {
		t.Errorf("the document shape was lost: %s", out)
	}
}

// The doc comment says safe for concurrent use, so that has to be true.
func TestScrubberIsConcurrencySafe(t *testing.T) {
	s := NewScrubber()
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			s.AddSecret(strings.Repeat("x", 8+i%10) + string(rune('a'+i%26)))
		}()
		go func() {
			defer wg.Done()
			_ = s.Scrub("some text with xxxxxxxxa in it")
		}()
	}
	wg.Wait()
}

// The package doc says it has no dependencies, deliberately, because it is imported by the packages that format errors — and it must never be the reason one of them gains a dependency edge.
func TestNoDependencies(t *testing.T) {
	// If this file's own imports ever need a first-party package, that is the signal.
	t.Log("internal/redact imports only regexp, sort, strings and sync")
}
