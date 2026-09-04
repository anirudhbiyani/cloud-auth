# Decisions

Things deliberately not built, and why. Recorded so they are not re-litigated
from the same starting assumptions.

## Snowflake is not a source provider

**Decided 2026-09-04. Reversal of an earlier recommendation in this repository's
own planning.**

Snowflake shipped outbound workload identity federation
([GA 1 July 2026](https://docs.snowflake.com/en/release-notes/2026/other/2026-07-01-wif-snowflake-workloads-external-services)):
a Snowflake workload can obtain an OIDC token asserting its own identity, which
an external service verifies against Snowflake's issuer.

That was recommended here as a `source/snowflake.go`, on the reasoning that it
is structurally the same as `source/aws_outbound.go` — a platform vending an
OIDC proof of the caller's own identity, exactly like `sts:GetWebIdentityToken`.

**The analogy does not hold, and reading the protocol is what showed it.** The
token is minted by a SQL function:

```sql
CREATE SECRET my_db.auth.my_workload TYPE = WORKLOAD_IDENTITY_FEDERATION;

SELECT SYSTEM$ISSUE_WORKLOAD_IDENTITY_FEDERATION_TOKEN(
    'my_db.auth.my_workload',
    '{"aud": "example-cloud-service.com"}');
```

Three things follow, and each on its own is disqualifying:

**It is not ambient.** Every source in this package mints from something the
workload already has by virtue of where it runs — an IMDS response, a projected
token file, two environment variables the runner injected. Minting here needs an
authenticated Snowflake *session*, which means cloud-auth would have to be
configured with a Snowflake credential in order to obtain a credential. That is
the shape this project exists to remove, not a path through it.

**`Detect()` could not work.** Detection is defined as resolving the runtime
*with no credential input* (`core.SourceProvider`). There is no environment
signal that says "you are a Snowflake workload" and also yields a session, so
this provider would have to be selected by configuration rather than detected —
a different contract from every other source, in the one package whose
correctness rests on not silently picking the wrong identity.

**The cost is a SQL driver.** `gosnowflake` is a large dependency to add to a
tree whose entire runtime half currently needs `net/http`.

And the plausible user is thin. A workload running *inside* Snowflake — a stored
procedure, a Snowpark container — is writing SQL or Python in Snowflake, not
invoking a Go CLI's `exec`; and outside Snowflake there is no Snowflake identity
to assert.

**What would change this:** a Snowflake runtime that exposes its identity token
through a file or an endpoint the way every other platform does, or a concrete
user running cloud-auth inside Snowflake. Demand beats symmetry; absent either,
this is speculative breadth.

## Snowflake and Databricks are not exchange targets

Both accept cloud OIDC directly
([Databricks](https://docs.databricks.com/aws/en/dev-tools/auth/oauth-federation),
[Snowflake inbound WIF, GA 14 Aug 2025](https://docs.snowflake.com/en/release-notes/2025/other/2025-08-14-wif)),
so a workload presents its own AWS or GCP token and receives a platform
credential. There is no exchange for cloud-auth to broker, and building one
would be building the layer that is commoditizing.

Where they would earn a place is as `InventorySource` implementations and
`--explain` detectors: each has a trust configuration — issuer, subject, claims
— misconfigurable in exactly the ways `doctor --explain` and `audit` already
diagnose. That is small work, since normalization, scoring and liveness are
cloud-neutral. It is not the next work: `audit` should cover Vault, and Azure
user-assigned managed identities, before it covers a fifth platform.

## Cloudflare was removed

Cloudflare Access has no workload identity federation — only service tokens and
mTLS, which are shared secrets. Its 2026 change was prefixing those secrets with
checksums so scanners can spot them: a mitigation, not an elimination. A client
for it would have meant this project vending the thing it exists to remove.
