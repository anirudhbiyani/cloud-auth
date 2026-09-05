package httpx

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Go strips only Authorization, Cookie and Www-Authenticate on a cross-domain redirect.
func TestClientsRefuseRedirects(t *testing.T) {
	var leaked []string
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, h := range []string{
			"X-aws-ec2-metadata-token", "Metadata-Flavor", "Metadata", "X-IDENTITY-HEADER",
		} {
			if v := r.Header.Get(h); v != "" {
				leaked = append(leaked, h+": "+v)
			}
		}
	}))
	defer attacker.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL+"/steal", http.StatusFound)
	}))
	defer redirector.Close()

	for name, client := range map[string]*http.Client{
		"metadata": NewMetadataClient(2 * time.Second),
		"sts":      NewSTSClient(2 * time.Second),
	} {
		t.Run(name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, redirector.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("X-aws-ec2-metadata-token", "session-token-value")
			req.Header.Set("Metadata", "true")
			req.Header.Set("X-IDENTITY-HEADER", "the-secret")

			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
				t.Fatal("the redirect was followed")
			}
			if !errors.Is(err, ErrRedirect) {
				t.Errorf("want ErrRedirect, got %v", err)
			}
		})
	}

	if len(leaked) > 0 {
		t.Errorf("credentials reached the redirect target: %v", leaked)
	}
}

// A proxy in the environment must not see metadata traffic.
func TestMetadataClientIgnoresProxyEnvironment(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://proxy.invalid:3128")
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:3128")

	transport, ok := NewMetadataClient(time.Second).Transport.(*http.Transport)
	if !ok {
		t.Fatal("metadata client should carry its own transport, not the shared default")
	}
	if transport.Proxy != nil {
		t.Error("metadata transport has a Proxy func; IMDS traffic could be routed through it")
	}

	// End to end: a request to a local server must succeed despite the bogus proxy, because the proxy is not consulted.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	resp, err := NewMetadataClient(2 * time.Second).Get(srv.URL)
	if err != nil {
		t.Fatalf("request went through the proxy: %v", err)
	}
	defer resp.Body.Close()
}

// The STS client deliberately does honour a proxy: those are ordinary internet calls a corporate egress proxy legitimately handles.
func TestSTSClientHonoursProxyEnvironment(t *testing.T) {
	transport, ok := NewSTSClient(time.Second).Transport.(*http.Transport)
	if !ok {
		t.Fatal("sts client should carry its own transport")
	}
	if transport.Proxy == nil {
		t.Error("sts transport has no Proxy func; an egress-proxied environment could not reach STS")
	}
}
