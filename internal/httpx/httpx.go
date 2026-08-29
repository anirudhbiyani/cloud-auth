// Package httpx builds the HTTP clients cloud-auth uses to talk to identity
// endpoints: instance metadata services, local token services, and cloud STS.
//
// These are not ordinary HTTP calls, and the standard library's defaults are
// wrong for them in two specific ways.
//
// Redirects. http.Client follows up to ten by default, and on a cross-domain
// redirect Go strips only Authorization, Cookie and Www-Authenticate. Every
// header that authenticates a metadata request is a custom one —
// X-aws-ec2-metadata-token, Metadata-Flavor, Metadata, X-IDENTITY-HEADER — so
// they are forwarded intact to wherever the redirect points. An identity
// endpoint has no legitimate reason to redirect, so a redirect is refused.
//
// Proxies. http.DefaultTransport honours HTTP_PROXY, and a proxy in the
// environment would route IMDS and metadata traffic — session tokens, identity
// tokens, managed-identity tokens — through it. AWS's own guidance is to exclude
// 169.254.169.254 from proxying; a client that talks to link-local addresses
// should not depend on the operator having remembered.
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

// NewMetadataClient returns a client for a link-local or loopback identity
// endpoint: no proxy, no redirects, short timeout.
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
//
// Proxies are honoured here, because these are ordinary internet calls that a
// corporate egress proxy legitimately handles. Redirects are still refused: a
// token endpoint redirecting is either a misconfiguration or an attack, and the
// request body carries the assertion.
func NewSTSClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSHandshakeTimeout = 10 * time.Second
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: refuseRedirects,
		Transport:     transport,
	}
}
