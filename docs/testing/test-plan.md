# Test plan: open items

Everything cloud-auth claims has been proven live against real clouds, except the four
items below. This is the plan to close them. Each item lists what it needs, the exact
steps, what "pass" means, and what it costs, so any one of them can be picked up
independently.

| # | Item | Status today | Needs |
|---|---|---|---|
| 1 | AWS Lambda as a source (SigV4 to GCP, negative to Azure) | implemented, unit-tested, never run live | AWS dev account, GCP dev project |
| 2 | Anthropic control plane: `setup` / `validate` / `delete` of federation rules | fake-API tested only | Anthropic org with an `org:admin` login |
| 3 | OpenAI runtime exchange | fake-API tested only | OpenAI org with a Workload Identity Provider |
| 4 | GitHub Actions as a source, end to end | workflow exists, never triggered | the `AWS_SMOKE_ROLE_ARN` repository variable, or the `role-arn` dispatch input |

Items 2 and 3 share a sub-task: the harness verifier does not yet know the `anthropic`
and `openai` target clouds. Adding them is a small change to `verifier/verify/plan.go`
(two cases in the target switch) and is step 0 for both.

---

## 1. Lambda source

**Why it matters.** Lambda is the one AWS runtime with no instance metadata service and
no projected token. If detection or the SigV4 proof misbehaves anywhere, it is here.

**Preconditions**

- `aws sso login` to a dev account; `gcloud auth login` to a dev project (the GCP WIF
  pool and bucket are created there).
- Existing EKS, AKS, GKE clusters are optional for this item. The run below uses only
  the Lambda runtime.

**Steps**

```bash
cd test/harness
LAMBDA=1 GOOGLE_PROJECT=<gcp-project> AWS_PROFILE=<profile> AWS_REGION=<region> \
  ./run-harness.sh --yes --clouds aws,gcp,azure --existing aws,azure \
  --runtimes aws-lambda 2>&1 | tee state/run.log
```

`--existing aws,azure` with no clusters needed: write minimal facts files first with
`scripts/existing.sh` pointed at any cluster you can read, or let stage1 run without
`--existing` and accept the EKS/AKS cost (about 40 minutes, under a dollar).

**Pass criteria**

- `state/results-aws-lambda.json` has `aws-lambda-sigv4-to-gcp` with `status: pass`. This
  means the exchange succeeded; the verifier has no GCS probe yet, so adding one that
  reads the harness bucket object is part of closing this item.
- `aws-lambda-to-azure-gap` has `status: pass` with `expect: error` and the error names
  `ErrNoFirstClassPath`: the refusal is correct and actionable.
- `harness fully destroyed` in the log; `aws lambda list-functions` and
  `aws iam list-roles` show nothing prefixed `cloud-auth-test`.

**What the first run found (2026-11-09).** Both Lambda rows failed with `AccessDenied` on
`sts:GetWebIdentityToken`: the account has outbound federation disabled, but IAM refuses the
call for a role without the permission before the feature check, so cloud-auth's `auto` never
reached its SigV4 fallback. Fixed in cloud-auth (`auto` now falls back on `AccessDenied` too)
and in the harness (SigV4 rows pin `aws_proof: sigv4`). Re-run to close.

**Likely failure to watch for.** The Lambda's CloudWatch log (tail is appended to
`state/results-aws-lambda.log`) saying `no supported runtime detected` means detection
did not see `AWS_LAMBDA_FUNCTION_NAME`; that is a cloud-auth bug, not a harness one.

**Cost.** A handful of 256 MB invocations plus the GCP WIF pool and a bucket: cents.

---

## 2. Anthropic control plane

**Why it matters.** The provider was written from the Admin API documentation. Field
names, archive semantics (400 while referenced), pagination, and the OAuth-caller
scope restriction are all assumptions until one real round trip confirms them.

**Preconditions**

- A sandbox Anthropic organization. Do not use the production org for the first run:
  a mistake in `delete` archives a service account other rules may target.
- `ant auth login --profile admin --scope org:admin`, then
  `export ANTHROPIC_AUTH_TOKEN=$(ant auth print-credentials --profile admin --access-token)`.
  Unset `ANTHROPIC_API_KEY` in the same shell.
- A workspace id (`wrkspc_...`) in that org, and the org UUID.
- A source that can mint an OIDC token you control: GitHub Actions on a repo you own is
  simplest; a GKE pod via the harness is the other option.

**Steps**

1. Copy `examples/anthropic-federation.json`, fill `organization_id`, `workspace_id`,
   and a `subject_prefix` matching your source (for GitHub Actions
   `repo:<owner>/<repo>:ref:refs/heads/main`). Keep `oauth_scope: workspace:inference`.
2. `cloud-auth setup -f spec.json --dry-run` prints the plan with no token needed.
3. `cloud-auth setup -f spec.json`. Record the three ids it prints.
4. In the Claude Console, Workload identity page: confirm one issuer, one service
   account, one rule, with the match block exactly as the spec.
5. `cloud-auth setup -f spec.json` again. Must succeed and print the **same** three ids.
6. `cloud-auth validate <mechanism-id>`: three checks, all passed.
7. Edit the rule's subject prefix in the Console. `validate` again: the rule check must
   fail and name the edited value. Restore it.
8. Exchange from the source: `cloud-auth exec --to anthropic --federation-rule <fdrl>
   --organization <uuid> --service-account-id <svac> --workspace <wrkspc>
   --audience <aud> -- curl -sS https://api.anthropic.com/v1/models
   -H "anthropic-version: 2023-06-01" -H "authorization: Bearer $ANTHROPIC_AUTH_TOKEN"`.
   Expect a model list. Run it twice: the second exchange must also succeed, which
   proves cloud-auth mints a fresh proof each time (GitHub tokens carry `jti`).
9. Create a second rule in the Console that targets the same service account.
   `cloud-auth delete <mechanism-id>`: the rule is archived, the service account and
   issuer are **kept** (shared). Archive the Console rule, re-run `setup` and `delete`:
   now all three are archived.

**Pass criteria.** Steps 5, 6, 7, 8 (twice), and 9 behave as written. The Console's
authentication history shows the exchanges with no `jti_reused` entries.

**Cost.** None beyond the model-list calls.

---

## 3. OpenAI runtime exchange

**Why it matters.** The exchanger was written from the token-exchange reference. The
default audience, the error body shape, and whether `expires_at` is always present are
documentation facts that one live exchange confirms.

**Preconditions**

- An OpenAI organization where you can manage Workload Identity Providers
  (Organization Settings, Security, Workload Identity Provider). This is dashboard only;
  OpenAI publishes no API for it, which is why cloud-auth has no `setup` for OpenAI.
- A source OIDC issuer. For GitHub Actions the issuer is
  `https://token.actions.githubusercontent.com`; for GKE Workload Identity it is
  `https://accounts.google.com` with `sub` = the service account's unique id.

**Steps**

1. In the dashboard create a provider: issuer URL as above, audience
   `https://api.openai.com/v1`. Add a service account mapping with key `sub` and the
   exact subject your source will present; create a new service account; grant
   `api.model.read` only.
2. From the source:
   `cloud-auth exec --to openai --identity-provider <provider-id> --service-account-id
   <sa-id> -- curl -sS https://api.openai.com/v1/models -H "Authorization: Bearer
   $OPENAI_API_KEY"`. Expect a model list.
3. Change the mapping's subject to a value that does not match. Run again. Expect
   cloud-auth to fail with the `invalid_grant` explanation naming the mapping.
4. `cloud-auth doctor --to openai --identity-provider <id> --service-account-id <id>`
   from the source: preflight passes, audience shows `https://api.openai.com/v1`.

**Pass criteria.** Steps 2, 3, 4 as written. Note whether the response carried
`expires_at`; if it ever does not, the exchanger falls back to `expires_in`, and the
docs should say which one OpenAI actually sends.

**Cost.** None.

---

## 4. GitHub Actions source, end to end

**Why it matters.** GitHub Actions is the most common source and the only one with
zero live coverage: the three live lifecycle tests used GitHub OIDC as the *configured*
source but never minted a GitHub token. `.github/workflows/federation-smoke.yml`
already does `doctor` plus `exchange` from a runner; it has never been run.

**Preconditions.** A target role in a dev AWS account whose trust accepts
`repo:<owner>/cloud-auth:ref:refs/heads/main`. Create it with the tool itself:
`cloud-auth setup -f examples/aws-github-oidc.json` with the subject edited.

**Steps**

1. Set the repository variable `AWS_SMOKE_ROLE_ARN` to the role ARN, or pass it as the
   `role-arn` input on `gh workflow run`.
2. `gh workflow run federation-smoke.yml` and `gh run watch`.
3. Read the job: `doctor` exits 0, `exchange` prints an assumed-role ARN.
4. `cloud-auth delete` the role afterwards.

**Pass criteria.** Green run with the assumed-role ARN in the log.

---

## Adding the AI targets to the harness verifier (step 0 for items 2 and 3)

The verifier's `TargetSpec` has fields for AWS, GCP, and Azure only. Two additions make
items 2 and 3 repeatable instead of manual:

- `TargetSpec` gains `federation_rule_id`, `organization_id`, `service_account_id`,
  `workspace_id` (Anthropic) and `identity_provider_id` (OpenAI); `Target()` returns
  `core.AnthropicTarget` / `core.OpenAITarget`.
- A probe per platform: `GET /v1/models` with the bearer token, pass on 200.
- `build-targets.sh` reads `state/anthropic.json` and `state/openai.json`, hand-written
  since neither has a tofu provider, and emits one case per source runtime.

With that in place, items 2 and 3 become two more rows in the pair matrix and run
on every harness cycle. Estimated size: about 80 lines of Go and 20 of shell.

---

## Housekeeping

The harness leaves a `cloud-auth-test` namespace with a service account and a Role on
each cluster it has used. They cost nothing and make the next run faster. To remove:

```bash
kubectl --context <ctx> delete namespace cloud-auth-test
```
