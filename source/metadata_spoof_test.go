package source

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// metadata.google.internal is a DNS name, and a name can be hijacked. The
// documented defence is that the real metadata server echoes Metadata-Flavor
// back; a plain HTTP server answering on that name will not.
func TestGCPRefusesAServerThatDoesNotEchoMetadataFlavor(t *testing.T) {
	spoof := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serves plausible content, but is not the metadata server.
		switch {
		case strings.HasSuffix(r.URL.Path, "/identity"):
			_, _ = w.Write([]byte(gcpJWT("sts.amazonaws.com")))
		default:
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer spoof.Close()

	g := NewGCP(WithGCPMetadataURL(spoof.URL), WithGCPHTTPClient(spoof.Client()),
		WithGCPEnv(envFunc(nil)))

	if _, err := g.Detect(context.Background()); err == nil {
		t.Fatal("Detect accepted a server that is not the metadata service")
	}

	_, err := g.Mint(context.Background(), "sts.amazonaws.com")
	if err == nil {
		t.Fatal("Mint accepted a token from a server that is not the metadata service")
	}
	if !strings.Contains(err.Error(), "Metadata-Flavor") {
		t.Errorf("error should name the failed check, got %v", err)
	}
}
