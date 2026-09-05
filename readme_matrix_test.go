package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The Runtime Federation Matrix in the README claimed three federation paths the code deliberately refuses on security grounds — including Azure managed identity, where the refusal exists because forwarding an Entra access token to a third-party STS discloses a working Azure credential and still fails.

// sourceRuntimes is the federatable/non-federatable split, read from the source providers.
var sourceRuntimes = map[string]bool{
	// AWS — source/aws.go:134,139
	"ec2": true, "ecs": true, "lambda": true, "eks-irsa": true,
	"eks-pod-identity": false,
	// GCP — source/gcp.go:97
	"gce": true, "gke": true, "cloud-run": true, "cloud-functions": true,
	// GitHub Actions — source/github.go
	"actions": true,
	// Azure — source/azure.go:152,165,175
	"aks-workload-identity": true,
	"vm":                    false,
	"app-service":           false,
	"container-apps":        false,
}

// matrixRow matches a table row in the Runtime Federation Matrix.
var matrixRow = regexp.MustCompile(`(?m)^\|\s+\*\*(AWS|GCP|Azure|GitHub Actions)\*\*[^|]*\|([^|]*)\|(.*)$`)

func readmeSection(t *testing.T, heading string) string {
	t.Helper()
	raw, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	body := string(raw)
	start := strings.Index(body, heading)
	if start < 0 {
		t.Fatalf("README.md has no %q section", heading)
	}
	rest := body[start+len(heading):]
	if end := strings.Index(rest, "\n### "); end >= 0 {
		return rest[:end]
	}
	return rest
}

func TestREADMERuntimeMatrixMatchesTheCode(t *testing.T) {
	section := readmeSection(t, "### 🔀 Runtime Federation Matrix")

	rows := matrixRow.FindAllStringSubmatch(section, -1)
	if len(rows) == 0 {
		t.Fatal("no matrix rows found; did the table format change?")
	}

	seen := map[string]bool{}
	for _, row := range rows {
		line := row[0]
		cells := row[3] // the three target columns
		// Which sub-runtimes does this row name?
		for name, federatable := range sourceRuntimes {
			if !strings.Contains(line, "`"+name+"`") {
				continue
			}
			seen[name] = true
			t.Run(name, func(t *testing.T) {
				hasTick := strings.Contains(cells, "✅")
				hasRefusal := strings.Contains(cells, "🚫")
				switch {
				case federatable && !hasTick:
					t.Errorf("%q is Federatable in code but its README row shows no ✅:\n%s", name, line)
				case !federatable && hasTick:
					t.Errorf("%q is Federatable=false in code (Mint returns ErrNonFederatableSource) "+
						"but its README row claims ✅:\n%s", name, line)
				case !federatable && !hasRefusal:
					t.Errorf("%q is refused in code; its README row must say so with 🚫:\n%s", name, line)
				}
			})
		}
	}

	for name := range sourceRuntimes {
		if !seen[name] {
			t.Errorf("sub-runtime %q is detectable in code but absent from the README matrix", name)
		}
	}
}

// Only AWS has a client that reaches its cloud.
func TestREADMEControlPlaneMatrixDoesNotOverstate(t *testing.T) {
	section := readmeSection(t, "### 🌐 Multi-Cloud Support")

	// Providers that still have no concrete client.
	for _, provider := range []string{} {
		t.Run(provider, func(t *testing.T) {
			var row string
			for _, line := range strings.Split(section, "\n") {
				if strings.HasPrefix(line, "| **"+provider+"**") {
					row = line
					break
				}
			}
			if row == "" {
				t.Fatalf("no %s row in the control-plane matrix", provider)
			}
			// The dry-run column legitimately carries a ✅; the lifecycle columns must not, because there is no client behind them.
			cols := strings.Split(row, "|")
			for i, header := range []string{"Setup", "Validate", "Delete"} {
				cell := strings.TrimSpace(cols[2+i])
				if strings.Contains(cell, "✅") {
					t.Errorf("%s %s shows ✅, but provider/%s has no client implementation",
						provider, header, strings.ToLower(provider))
				}
			}
		})
	}
}

// The converse: a provider that HAS a client must not still be marked plan-only, or the README understates what works and nobody uses it.
func TestREADMEControlPlaneMatrixCreditsWiredProviders(t *testing.T) {
	section := readmeSection(t, "### 🌐 Multi-Cloud Support")

	for _, provider := range []string{"AWS", "GCP", "Azure", "Vault"} {
		t.Run(provider, func(t *testing.T) {
			for _, line := range strings.Split(section, "\n") {
				if !strings.HasPrefix(line, "| **"+provider+"**") {
					continue
				}
				if strings.Contains(line, "🅿️") {
					t.Errorf("%s has a client but its row still says plan-only:\n%s", provider, line)
				}
				if !strings.Contains(line, "✅") {
					t.Errorf("%s has a client but its row shows no ✅:\n%s", provider, line)
				}
				return
			}
			t.Fatalf("no %s row in the control-plane matrix", provider)
		})
	}
}

// A wildcard subject in the headline examples is the first thing a new user copies, and nothing at setup warns about it today.
func TestREADMEExamplesPinTheSubject(t *testing.T) {
	raw, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	inFence := false
	checked := 0
	for i, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
			continue
		}
		if !inFence {
			continue
		}
		checked++
		if strings.Contains(line, "repo:myorg/myrepo:*") {
			t.Errorf("README.md:%d uses a wildcard subject in an example: %s", i+1, strings.TrimSpace(line))
		}
	}
	if checked == 0 {
		t.Fatal("scanned no fenced code blocks; the test is not looking at anything")
	}
}
