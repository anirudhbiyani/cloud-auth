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

	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/internal/jwt"
	"github.com/anirudhbiyani/cloud-auth/internal/k8stoken"
)

// k8sTokenMinter is the subset of *k8stoken.Client used by the source providers.
type k8sTokenMinter interface {
	Mint(ctx context.Context, audience string) (string, error)
}

// oidcToken is the SourceToken every OIDC minter returns: the raw JWT, plus the identity the token's own claims assert.
func oidcToken(value string, claims jwt.Claims, audience string) *core.SourceToken {
	return &core.SourceToken{
		Kind:     core.OIDC,
		Value:    value,
		Issuer:   claims.Issuer,
		Subject:  claims.Subject,
		Audience: audience,
		Expiry:   claims.Expiry,
	}
}

// mintDynamicAudienceToken attempts to mint a fresh projected service-account token bound to the requested audience via the Kubernetes TokenRequest API.
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

// inClusterClient builds a k8stoken client from the mounted service-account volume and the in-cluster API server env vars.
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

// namespaceAndServiceAccount resolves the pod's namespace and service-account name.
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
			// The subject comes from a JWT read at an env-supplied path and both halves are interpolated into an API-server URL.
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

// inClusterClientOnce caches the derived client.
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
			// The API server has no reason to redirect a TokenRequest, and the request carries the pod's own bearer token.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return fmt.Errorf("kubernetes API server attempted a redirect; refusing to " +
					"forward the pod's service-account token")
			},
		}
	})
	return inClusterHTTP, inClusterHTTPErr
}
