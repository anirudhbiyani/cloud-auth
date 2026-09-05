// Package target contains the Target Exchangers: one per target cloud.
package target

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/internal/redact"
)

// maxErrorBody caps how much of an upstream response an error carries.
const maxErrorBody = 512

// maxBackoff caps a single wait, so an upstream asking for patience cannot stall a caller indefinitely through the exponential schedule.
const maxBackoff = 5 * time.Second

// Defaults every exchanger starts from.
const (
	defaultExchangeTimeout = 10 * time.Second
	defaultMaxRetries      = 2
	defaultBackoff         = 100 * time.Millisecond
)

// httpError carries the status, body and headers of a non-2xx STS response.
type httpError struct {
	status int
	body   []byte
	header http.Header
}

// Error redacts before formatting.
func (e *httpError) Error() string {
	return fmt.Sprintf("status %d: %s", e.status, redact.Body(string(e.body), maxErrorBody))
}

// asHTTPError unwraps err into an *httpError if present.
func asHTTPError(err error, target **httpError) bool { return errors.As(err, target) }

// throttleCodes are the error codes cloud STS endpoints use for rate limiting, which arrive with a 4xx status and are therefore invisible to a status-code-only rule.
var throttleCodes = []string{"Throttling", "ThrottlingException", "SlowDown",
	"TooManyRequestsException", "RequestLimitExceeded", "rateLimitExceeded"}

// propagationCodes are 4xx answers meaning "the trust is right, it is not replicated yet" — as opposed to "the trust is wrong", which is what every other 4xx here means.
var propagationCodes = []string{"AADSTS70021"}

// retryable reports whether an error should be retried.
func retryable(err error) bool {
	var he *httpError
	if errors.As(err, &he) {
		if he.status >= 500 || he.status == http.StatusTooManyRequests {
			return true
		}
		if he.status >= 400 && he.status < 500 {
			body := string(he.body)
			for _, code := range throttleCodes {
				if strings.Contains(body, code) {
					return true
				}
			}
			for _, code := range propagationCodes {
				if containsErrorCode(body, code) {
					return true
				}
			}
		}
		return false
	}
	// Nil means success; any non-httpError (transport/timeout) is retryable.
	return err != nil
}

// containsErrorCode reports whether body carries code as a whole identifier.
func containsErrorCode(body, code string) bool {
	for i := 0; ; {
		j := strings.Index(body[i:], code)
		if j < 0 {
			return false
		}
		end := i + j + len(code)
		if end >= len(body) || body[end] < '0' || body[end] > '9' {
			return true
		}
		i = end
	}
}

// retryAfter returns the delay an upstream asked for, if any.
func retryAfter(he *httpError) (time.Duration, bool) {
	if he == nil || he.header == nil {
		return 0, false
	}
	raw := he.header.Get("Retry-After")
	if raw == "" {
		return 0, false
	}
	// Either delay-seconds or an HTTP date.
	if secs, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second, true
	}
	if when, err := http.ParseTime(raw); err == nil {
		if d := time.Until(when); d > 0 {
			return d, true
		}
		return 0, true
	}
	return 0, false
}

// backoffFor returns how long to wait before attempt n (1-based).
func backoffFor(base time.Duration, attempt int, he *httpError) time.Duration {
	if d, ok := retryAfter(he); ok {
		return d
	}
	if base <= 0 {
		return 0
	}
	// Cap the exponent so a large maxRetries cannot produce an absurd delay.
	shift := attempt - 1
	if shift > 6 {
		shift = 6
	}
	window := base << shift
	if window > maxBackoff {
		window = maxBackoff
	}
	// Full jitter: uniform in [0, window).
	return time.Duration(rand.Int63n(int64(window) + 1)) // #nosec G404 -- load spreading, not a secret
}

// doWithRetry issues req-producing calls with bounded exponential-ish backoff.
func doWithRetry(ctx context.Context, client *http.Client, maxRetries int, backoff time.Duration, newReq func() (*http.Request, error)) ([]byte, int, error) {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			var last *httpError
			errors.As(lastErr, &last)
			select {
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			case <-time.After(backoffFor(backoff, attempt, last)):
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
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return body, resp.StatusCode, nil
		}
		he := &httpError{status: resp.StatusCode, body: body, header: resp.Header.Clone()}
		if !retryable(he) {
			return nil, resp.StatusCode, he // 4xx: fail fast
		}
		lastErr = he
	}
	return nil, 0, fmt.Errorf("exhausted retries: %w", lastErr)
}

// checkAudienceBinding verifies the proof we are about to transmit was minted for the target we are about to transmit it to.
func checkAudienceBinding(tok *core.SourceToken, want string) error {
	if tok.Audience == "" || want == "" || tok.Audience == want {
		return nil
	}
	return fmt.Errorf("audience binding violation: the proof was minted for %q but this exchange "+
		"presents it to a target expecting %q; refusing to disclose it. Mint the proof with the "+
		"target's audience", tok.Audience, want)
}

// categorize maps an exchange failure onto the shared taxonomy, so a caller of broker.Exchange can branch on core.CategoryOf(err) instead of matching on message text.
func categorize(raw error, classified error) error {
	if classified == nil {
		return nil
	}
	err := classified
	var he *httpError
	if !errors.As(raw, &he) {
		// No HTTP response at all: DNS, dial, TLS, timeout, cancellation.
		if errors.Is(raw, context.Canceled) || errors.Is(raw, context.DeadlineExceeded) {
			return core.Categorize(err, core.ErrCategoryTimeout, false)
		}
		return core.Categorize(err, core.ErrCategoryNetwork, true)
	}

	switch {
	case he.status == http.StatusTooManyRequests, retryable(he) && he.status < 500:
		return core.Categorize(err, core.ErrCategoryRateLimit, true)
	case he.status >= 500:
		return core.Categorize(err, core.ErrCategoryNetwork, true)
	case he.status == http.StatusUnauthorized, he.status == http.StatusForbidden:
		return core.Categorize(err, core.ErrCategoryAuth, false)
	case he.status == http.StatusNotFound:
		return core.Categorize(err, core.ErrCategoryNotFound, false)
	case he.status >= 400:
		// A 400 from a token endpoint is a rejected assertion or a malformed request: configuration, not transport.
		return core.Categorize(err, core.ErrCategoryValidation, false)
	default:
		return core.Categorize(err, core.ErrCategoryInternal, false)
	}
}

// For returns the default Exchanger for a target cloud.
func For(c core.Cloud) (core.Exchanger, error) {
	switch c {
	case core.AWS:
		return NewAWSExchanger(), nil
	case core.GCP:
		return NewGCPExchanger(), nil
	case core.Azure:
		return NewAzureExchanger(), nil
	case core.Anthropic:
		return NewAnthropicExchanger(), nil
	default:
		return nil, fmt.Errorf("cloud-auth/target: unsupported target cloud %q", c)
	}
}
