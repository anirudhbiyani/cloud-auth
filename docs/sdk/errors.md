# Errors and redaction

## Error categories

Every error that crosses a package boundary can be classified, so a caller decides
retry-or-fail without string matching.

```go
package main

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/anirudhbiyani/cloud-auth/broker"
	"github.com/anirudhbiyani/cloud-auth/core"
)

func main() {
	ctx := context.Background()
	tgt := core.AWSTarget{RoleARN: "arn:aws:iam::123456789012:role/x"}

	for attempt := 0; attempt < 3; attempt++ {
		_, _, err := broker.New().Exchange(ctx, tgt)
		switch {
		case err == nil:
			return
		case errors.Is(err, core.ErrNoFirstClassPath):
			// This source/target pair is a documented gap (e.g. AWS SigV4 -> Azure). Reconfigure; retrying cannot help.
			log.Fatal(err)
		case errors.Is(err, core.ErrRuntimeMismatch), errors.Is(err, core.ErrNonFederatableSource):
			log.Fatal(err) // configuration, not transport
		case core.IsRetryable(err):
			time.Sleep(time.Second << attempt) // rate limit or 5xx at the token service
			continue
		default:
			log.Fatalf("%s: %v", core.CategoryOf(err), err)
		}
	}
}
```

Categories from `core.CategoryOf`: `auth`, `permission`, `validation`, `not_found`,
`conflict`, `rate_limit`, `network`, `timeout`, `internal`. `core.IsRetryable` is true only for rate limits and transient
network or server failures; a rejected assertion is never retried, because retrying
a single-use token is how `jti_reused` happens.

Most control-plane errors are `*core.CloudAuthError` carrying a category, a provider,
the underlying cause, and an operation where the caller set one; `errors.As` gets you
the structured form and `errors.Is` still works on the wrapped cause. A few paths
(state-record cleanup after delete, some Vault and Anthropic archive failures) return
plain wrapped errors, so fall back to the message when `errors.As` fails.

## Redaction

`core.Credentials` and `core.SourceToken` are safe to log by default:

```go
package main

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
)

func main() {
	creds := &core.Credentials{Cloud: core.GCP, AccessToken: "ya29.secret", Expiry: time.Now().Add(time.Hour)}

	fmt.Println(creds)                       // redacted
	fmt.Printf("%+v\n", creds)               // still redacted: Format ignores the verb
	slog.Info("got credentials", "c", creds) // LogValue is redacted
	b, _ := creds.MarshalJSON()              // a JSON string of the redacted form; the expiry appears inside it
	fmt.Println(string(b))

	plain := creds.Reveal() // the one explicit path to the bytes
	_ = plain.AccessToken
}
```

Grep your codebase for `.Reveal()` and you have the complete list of places a secret
can leave the process. That is the design intent, and the reason there is no
`Credentials.Token()` convenience accessor.
