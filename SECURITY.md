# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
discussions, or pull requests.**

Report privately through [GitHub Security Advisories][advisory] — "Report a
vulnerability" on the Security tab. That creates a private thread with the
maintainer and, if a fix is warranted, a CVE.

[advisory]: https://github.com/anirudhbiyani/cloud-auth/security/advisories/new

Please include:

- What the issue is, and which component (`core`, `provider/*`, `source`,
  `target`, `broker`, `adapters`, or the CLI).
- How to reproduce it, ideally as a failing test.
- What an attacker gets: which trust boundary is crossed, and what they must
  already have in order to try.

## What to expect

| | |
|---|---|
| Acknowledgement | within **3 business days** |
| Initial assessment | within **10 business days** |
| Fix or mitigation for a confirmed high-severity issue | target **30 days** from confirmation |
| Public disclosure | coordinated with you, after a fix is available |

This is a single-maintainer project. Those are the targets it is run to; if one
slips, you will be told rather than left waiting.

## Supported versions

Only the latest released version is supported. While the major version is 0,
fixes land in a new minor or patch release rather than being backported.

## Scope

In scope — anything that lets an identity obtain credentials it should not, or
that leaks credential material:

- A trust relationship created more broadly than the spec asked for.
- Credential material reaching stdout, an error string, a log line or the audit
  record. `internal/redact` and `core/redaction.go` exist to prevent this, and a
  gap in either is a real finding.
- A validator reporting a pass for a check that did not run.
- A source proof transmitted to a target it was not audience-pinned for.
- Bypassing `source.detect`, which exists to let an operator constrain which
  identity a workload may authenticate as.
- Any panic reachable from the public Go API or the CLI.

Out of scope:

- Missing hardening in a cloud provider's own service, or a cloud's documented
  behaviour that you disagree with. Report those to the cloud.
- Findings that require an attacker to already hold the credentials the tool is
  configured with. If they have your `VAULT_TOKEN` or your AWS credentials, they
  do not need this tool.
- Scanner output without a demonstrated call path. `govulncheck` gates CI
  precisely because it reports only advisories whose vulnerable symbols this
  code reaches.
- Anything requiring physical access to the machine or root on it.

## What this tool is for

cloud-auth removes long-lived credentials from cross-cloud authentication. If
you find a path where it produces, stores, or encourages a long-lived secret,
that is worth reporting even if it is not exploitable on its own — it is
contrary to the point of the project.
