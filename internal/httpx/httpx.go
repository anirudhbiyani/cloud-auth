// Package httpx builds the HTTP clients cloud-auth uses to talk to identity endpoints: instance metadata services, local token services, and cloud STS.
package httpx

import (
	"errors"
	"net/http"
	"time"
)

// ErrRedirect is returned when an identity endpoint attempts a redirect.
var ErrRedirect = errors.New("cloud-auth: identity endpoint attempted a redirect; " +
	"refusing to forward credentials to another host")

// refuseRedirects is the CheckRedirect for every client here.
func refuseRedirects(_ *http.Request, _ []*http.Request) error { return ErrRedirect }

// NewMetadataClient returns a client for a link-local or loopback identity endpoint: no proxy, no redirects, short timeout.
func NewMetadataClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: refuseRedirects,
		Transport: &http.Transport{
			// Proxy is deliberately nil, not ProxyFromEnvironment.
			Proxy:                 nil,
			MaxIdleConns:          4,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: time.Second,
			ForceAttemptHTTP2:     true,
		},
	}
}

// NewSTSClient returns a client for a cloud STS or token endpoint.
func NewSTSClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSHandshakeTimeout = 10 * time.Second
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: refuseRedirects,
		Transport:     transport,
	}
}
