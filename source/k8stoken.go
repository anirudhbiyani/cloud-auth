package source

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
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

	// Build an HTTP client trusting the in-cluster CA if present.
	transport := &http.Transport{}
	if ca, err := readFile(k8stoken.CACertFile); err == nil && len(ca) > 0 {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(ca) {
			transport.TLSClientConfig = &tls.Config{RootCAs: pool}
		}
	}
	httpClient := &http.Client{Timeout: 5 * time.Second, Transport: transport}

	baseURL := fmt.Sprintf("https://%s:%s", host, port)
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
			return ns, sa, true
		}
		// sub had the prefix but no SA component; fall through to try the file.
	}
	// Fall back to the mounted namespace file for ns; sub (post-prefix) for sa.
	if b, err := readFile(k8stoken.NamespaceFile); err == nil {
		fileNS := strings.TrimSpace(string(b))
		saName := strings.TrimPrefix(claims.Subject, prefix)
		if fileNS != "" && saName != "" && saName != claims.Subject {
			return fileNS, saName, true
		}
	}
	return "", "", false
}
