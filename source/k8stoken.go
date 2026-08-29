package source

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/anirudhbiyani/cloud-auth/internal/jwt"
	"github.com/anirudhbiyani/cloud-auth/internal/k8stoken"
)

// k8sTokenMinter is the subset of *k8stoken.Client used by the source providers.
// It exists so tests can inject a fake, though the concrete client is already
// httptest-friendly.
type k8sTokenMinter interface {
	Mint(ctx context.Context, audience string) (string, error)
}

// mintDynamicAudienceToken attempts to mint a fresh projected service-account
// token bound to the requested audience via the Kubernetes TokenRequest API.
//
// It is used as a fallback by the EKS-IRSA and AKS-Workload-Identity mint paths
// when the on-disk projected token's aud does not include the requested
// audience. `injected` is the client wired for tests; when nil, a client is
// derived from the in-cluster environment (env host/port, mounted CA cert, pod
// SA token, and namespace). It returns (token, true, nil) on success. The bool
// is false when no TokenRequest client is available (not in-cluster and none
// injected), signaling the caller to keep its existing fail-closed behavior.
func mintDynamicAudienceToken(
	ctx context.Context,
	injected k8sTokenMinter,
	getenv func(string) string,
	readFile func(string) ([]byte, error),
	claims jwt.Claims,
	audience string,
) (string, bool, error) {
	minter := injected
	if minter == nil {
		c, ok := inClusterClient(getenv, readFile, claims)
		if !ok {
			return "", false, nil
		}
		minter = c
	}

	token, err := minter.Mint(ctx, audience)
	if err != nil {
		return "", true, fmt.Errorf("minting projected token via Kubernetes TokenRequest: %w", err)
	}
	// The freshly-minted token must actually carry the requested audience.
	minted, err := jwt.ParseUnverified(token)
	if err != nil {
		return "", true, fmt.Errorf("parsing TokenRequest-minted token: %w", err)
	}
	if !minted.HasAudience(audience) {
		return "", true, fmt.Errorf(
			"TokenRequest-minted token audience %v does not include the requested audience %q",
			minted.Audiences, audience)
	}
	return token, true, nil
}

// inClusterClient builds a k8stoken client from the mounted service-account
// volume and the in-cluster API server env vars. It returns (nil, false) when
// the process is not running in a Kubernetes pod (no API host, or missing
// mounted credentials), so the caller can fall back to fail-closed behavior.
func inClusterClient(
	getenv func(string) string,
	readFile func(string) ([]byte, error),
	claims jwt.Claims,
) (*k8stoken.Client, bool) {
	host := getenv("KUBERNETES_SERVICE_HOST")
	port := getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, false
	}
	bearer, err := readFile(k8stoken.TokenFile)
	if err != nil {
		return nil, false
	}
	ns, sa, ok := namespaceAndServiceAccount(getenv, readFile, claims)
	if !ok {
		return nil, false
	}

	// Build an HTTP client trusting the in-cluster CA.
	//
	// A malformed CA is an error rather than a silent fall-through to the system
	// roots: the API server's certificate is issued by the cluster CA, so
	// ignoring an unparseable ca.crt just moves the failure to an opaque TLS
	// error later.
	httpClient, err := inClusterHTTPClient(readFile)
	if err != nil {
		return nil, false
	}

	baseURL := "https://" + net.JoinHostPort(host, port)
	return k8stoken.New(
		k8stoken.WithBaseURL(baseURL),
		k8stoken.WithHTTPClient(httpClient),
		k8stoken.WithBearerToken(strings.TrimSpace(string(bearer))),
		k8stoken.WithServiceAccount(ns, sa),
	), true
}

// namespaceAndServiceAccount resolves the pod's namespace and service-account
// name. It prefers the projected token's sub claim
// ("system:serviceaccount:<ns>:<sa>") and falls back to the mounted namespace
// file paired with the sub claim's SA component.
func namespaceAndServiceAccount(
	getenv func(string) string,
	readFile func(string) ([]byte, error),
	claims jwt.Claims,
) (ns, sa string, ok bool) {
	const prefix = "system:serviceaccount:"
	if strings.HasPrefix(claims.Subject, prefix) {
		rest := strings.TrimPrefix(claims.Subject, prefix)
		if i := strings.IndexByte(rest, ':'); i > 0 && i < len(rest)-1 {
			ns, sa = rest[:i], rest[i+1:]
			// The subject comes from a JWT read at an env-supplied path and both
			// halves are interpolated into an API-server URL. Real Kubernetes names
			// are DNS labels, so requiring that costs nothing and closes the path.
			if !isDNSLabel(ns) || !isDNSLabel(sa) {
				return "", "", false
			}
			return ns, sa, true
		}
		// sub had the prefix but no SA component; fall through to try the file.
	}
	// Fall back to the mounted namespace file for ns; sub (post-prefix) for sa.
	if b, err := readFile(k8stoken.NamespaceFile); err == nil {
		fileNS := strings.TrimSpace(string(b))
		saName := strings.TrimPrefix(claims.Subject, prefix)
		if isDNSLabel(fileNS) && isDNSLabel(saName) && saName != claims.Subject {
			return fileNS, saName, true
		}
	}
	return "", "", false
}

// dnsLabel matches a Kubernetes namespace or service-account name.
var dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

func isDNSLabel(s string) bool { return dnsLabel.MatchString(s) }

// inClusterClientOnce caches the derived client. inClusterClient used to build a
// fresh http.Transport per mint and never close it, so each dynamic-audience
// token leaked a connection pool for the default 90-second idle window.
var (
	inClusterClientOnce sync.Once
	inClusterHTTP       *http.Client
	inClusterHTTPErr    error
)

func inClusterHTTPClient(readFile func(string) ([]byte, error)) (*http.Client, error) {
	inClusterClientOnce.Do(func() {
		ca, err := readFile(k8stoken.CACertFile)
		if err != nil {
			inClusterHTTPErr = fmt.Errorf("reading in-cluster CA: %w", err)
			return
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			inClusterHTTPErr = fmt.Errorf("in-cluster CA at %s is not valid PEM", k8stoken.CACertFile)
			return
		}
		transport := &http.Transport{
			// No proxy: the API server is reached in-cluster.
			Proxy:               nil,
			TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			MaxIdleConns:        4,
			IdleConnTimeout:     30 * time.Second,
			TLSHandshakeTimeout: 5 * time.Second,
			ForceAttemptHTTP2:   true,
		}
		inClusterHTTP = &http.Client{
			Timeout:   5 * time.Second,
			Transport: transport,
			// The API server has no reason to redirect a TokenRequest, and the
			// request carries the pod's own bearer token.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return fmt.Errorf("kubernetes API server attempted a redirect; refusing to " +
					"forward the pod's service-account token")
			},
		}
	})
	return inClusterHTTP, inClusterHTTPErr
}
