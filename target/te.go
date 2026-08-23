// Package target contains the Target Exchangers: one per target cloud. Each takes a
// normalized source proof plus a target binding and performs the target STS
// call, returning native short-lived credentials.
//
// Retry policy is uniform across exchangers: transient transport errors and 5xx
// responses are retried with bounded backoff; 4xx responses are configuration
// or trust errors and are surfaced immediately, never retried. This keeps
// misconfiguration fast and honest (supporting the >99%-success and
// <30-min-to-first-exchange goals) instead of masking it behind retries.
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

// maxErrorBody caps how much of an upstream response an error carries. An error
// is a diagnostic, not a transcript, and these bodies are unbounded.
const maxErrorBody = 512

// maxBackoff caps a single wait, so an upstream asking for patience cannot stall
// a caller indefinitely through the exponential schedule.
const maxBackoff = 5 * time.Second

// httpError carries the status, body and headers of a non-2xx STS response.
// The headers are kept for Retry-After, which is the only reliable signal for
// how long a throttled caller should wait.
type httpError struct {
	status int
	body   []byte
	header http.Header
}

// Error redacts before formatting. Token endpoints echo request material into
// error descriptions, and this string travels: into the exchanger's wrapped
// error, out of Exchange, and into the audit record the CLI writes to stderr.
func (e *httpError) Error() string {
	return fmt.Sprintf("status %d: %s", e.status, redact.Body(string(e.body), maxErrorBody))
}

// asHTTPError unwraps err into an *httpError if present.
func asHTTPError(err error, target **httpError) bool { return errors.As(err, target) }

// throttleCodes are the error codes cloud STS endpoints use for rate limiting,
// which arrive with a 4xx status and are therefore invisible to a
// status-code-only rule.
var throttleCodes = []string{"Throttling", "ThrottlingException", "SlowDown",
	"TooManyRequestsException", "RequestLimitExceeded", "rateLimitExceeded"}

// retryable reports whether an error should be retried.
//
// Transport errors and 5xx are retryable. 4xx generally is not — a rejected
// trust does not become accepted on the third attempt, and retrying it turns a
// clear misconfiguration into a slow one.
//
// The exceptions are throttles. 429 is the obvious one and was previously
// treated as a permanent failure, so a brief rate limit surfaced as what looked
// like a trust error. AWS additionally returns 400 with a Throttling code in the
// body, which no status-code rule can see, so the body is checked for the known
// codes.
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
		}
		return false
	}
	// Nil means success; any non-httpError (transport/timeout) is retryable.
	return err != nil
}

// retryAfter returns the delay an upstream asked for, if any. Honouring it is
// both politer and more effective than guessing.
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
//
// Exponential with full jitter. The previous schedule was backoff*attempt with
// no jitter at all, so every instance of a fleet that hit the same throttle
// retried in lockstep and re-created the burst that caused it.
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
	// Full jitter: uniform in [0, window). Spreads a fleet rather than merely
	// delaying it in unison.
	return time.Duration(rand.Int63n(int64(window) + 1)) // #nosec G404 -- load spreading, not a secret
}

// doWithRetry issues req-producing calls with bounded exponential-ish backoff.
// The request is rebuilt per attempt via newReq because a body may be consumed.
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
		resp.Body.Close()
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

// checkAudienceBinding verifies the proof we are about to transmit was minted
// for the target we are about to transmit it to.
//
// The target STS validates this too, and will reject a mismatch — but only after
// the proof has been disclosed to it. A source token is a bearer assertion about
// our identity, so sending one to the wrong endpoint is a disclosure whether or
// not the exchange succeeds: presenting a GCP-signed token for audience A to
// some other cloud's STS hands that party a usable assertion for its lifetime.
// The one check that has to happen locally is therefore this one.
//
// An empty token audience is not treated as a mismatch. Callers may construct a
// SourceToken directly without one, and there is nothing to compare against;
// we cannot verify, so we do not claim to.
func checkAudienceBinding(tok *core.SourceToken, want string) error {
	if tok.Audience == "" || want == "" || tok.Audience == want {
		return nil
	}
	return fmt.Errorf("audience binding violation: the proof was minted for %q but this exchange "+
		"presents it to a target expecting %q; refusing to disclose it. Mint the proof with the "+
		"target's audience", tok.Audience, want)
}

// categorize maps an exchange failure onto the shared taxonomy, so a caller of
// broker.Exchange can branch on core.CategoryOf(err) instead of matching on
// message text.
//
// The taxonomy existed for exactly this and was wired to nothing: the data plane
// returned fmt.Errorf strings plus four sentinels, which told a caller whether
// trust was missing but not whether the failure was worth retrying, whether the
// network was down, or whether it was being throttled.
// raw carries the transport/HTTP shape; classified carries the provider's
// message and sentinel. The category has to come from raw, because classify
// deliberately unwraps the *httpError to build a readable message and the status
// would otherwise be lost.
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
		// A 400 from a token endpoint is a rejected assertion or a malformed
		// request: configuration, not transport.
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
	default:
		return nil, fmt.Errorf("cloud-auth/target: unsupported target cloud %q", c)
	}
}
