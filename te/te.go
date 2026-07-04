// Package te contains the Target Exchangers: one per target cloud. Each takes a
// normalized source proof plus a target binding and performs the target STS
// call, returning native short-lived credentials.
//
// Retry policy is uniform across exchangers: transient transport errors and 5xx
// responses are retried with bounded backoff; 4xx responses are configuration
// or trust errors and are surfaced immediately, never retried. This keeps
// misconfiguration fast and honest (supporting the >99%-success and
// <30-min-to-first-exchange goals) instead of masking it behind retries.
package te

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
)

// httpError carries the status and body of a non-2xx STS response.
type httpError struct {
	status int
	body   []byte
}

func (e *httpError) Error() string { return fmt.Sprintf("status %d: %s", e.status, e.body) }

// asHTTPError unwraps err into an *httpError if present.
func asHTTPError(err error, target **httpError) bool { return errors.As(err, target) }

// retryable reports whether an error should be retried: transport errors and
// 5xx are retryable; 4xx (client/trust errors) are not.
func retryable(err error) bool {
	var he *httpError
	if errors.As(err, &he) {
		return he.status >= 500
	}
	// Nil means success; any non-httpError (transport/timeout) is retryable.
	return err != nil
}

// doWithRetry issues req-producing calls with bounded exponential-ish backoff.
// The request is rebuilt per attempt via newReq because a body may be consumed.
func doWithRetry(ctx context.Context, client *http.Client, maxRetries int, backoff time.Duration, newReq func() (*http.Request, error)) ([]byte, int, error) {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			case <-time.After(backoff * time.Duration(attempt)):
			}
		}
		req, err := newReq()
		if err != nil {
			return nil, 0, err
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue // transport error: retryable
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return body, resp.StatusCode, nil
		}
		he := &httpError{status: resp.StatusCode, body: body}
		if !retryable(he) {
			return nil, resp.StatusCode, he // 4xx: fail fast
		}
		lastErr = he
	}
	return nil, 0, fmt.Errorf("exhausted retries: %w", lastErr)
}

// For returns the default Exchanger for a target cloud.
func For(c cloudauth.Cloud) (cloudauth.Exchanger, error) {
	switch c {
	case cloudauth.AWS:
		return NewAWSExchanger(), nil
	case cloudauth.GCP:
		return NewGCPExchanger(), nil
	case cloudauth.Azure:
		return NewAzureExchanger(), nil
	default:
		return nil, fmt.Errorf("cloud-auth/te: unsupported target cloud %q", c)
	}
}
