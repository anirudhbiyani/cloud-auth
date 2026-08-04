# cloud-auth cloud integration harness

Provisions real infrastructure across AWS, GCP, and Azure; runs cloud-auth's
detect → mint → exchange flow **inside** each source runtime; asserts every
first-class cross-cloud pair works; then destroys everything.

Unit tests prove the mechanics against fakes. This proves them against the real
STS endpoints, real IMDS, real projected tokens, and real IAM trust — the part
no amount of `httptest` can cover.

> **This creates real, billable cloud resources.** Read [Cost](#cost) first.
> Tooling is **OpenTofu** (`tofu`), not Terraform.

## Quick start

This is a **local bash harness** — you run it from your own shell. One command
does the whole loop, and tears everything down even if verification fails or you
Ctrl-C:

```bash
cd test/harness
./run-harness.sh
```

Useful variations:

```bash
./run-harness.sh --check                    # static checks only — no cloud, no cost
./run-harness.sh --clouds aws,gcp           # subset of clouds
./run-harness.sh --runtimes aws-ec2         # subset of source runtimes
./run-harness.sh --keep                     # leave it up to debug (REMEMBER to destroy)
./run-harness.sh --yes                      # no prompts
```

Individual phases, if you'd rather drive them yourself:

```bash
./scripts/up.sh        # stage1 compute, then stage2 cross-cloud trust
./scripts/verify.sh    # run the verifier in every source runtime
./scripts/down.sh      # destroy everything
./scripts/sweep.sh     # list orphans by tag if a destroy failed
```

The `Makefile` wraps the same scripts (`make up` / `verify` / `down` / `sweep` /
`cycle` / `check`) if you prefer make.

## Why two stages

The three clouds' trusts are **mutually dependent**: an AWS IAM OIDC provider
needs GCP's and Azure's issuer URLs; a GCP WIF provider needs AWS's EKS OIDC
issuer; Azure's federated credentials need both. That's a cycle — it cannot be
one apply. So:

| Stage | What it does |
|---|---|
| **stage1** | Creates each cloud's *source runtime* and exports its issuer URL + subject. |
| **stage2** | Consumes every other cloud's stage-1 facts and creates the *trust* objects. |
| **verify** | Delivers the verifier into each runtime and runs the pair matrix. |
| **down** | stage2 down, then stage1 down, per cloud. |

`up.sh` wires stage 1 → stage 2 automatically by generating a
`harness.auto.tfvars` for each stage-2 module from the other clouds' outputs.
The exact key names are frozen in [CONTRACT.md](CONTRACT.md) — modules and the
verifier code against that file, not against each other.

## What gets tested

| # | Source | Target | Mechanism |
|---|---|---|---|
| 1 | GCP GCE | AWS | `AssumeRoleWithWebIdentity` |
| 2 | GCP GCE | Azure | Entra FIC client assertion |
| 3 | Azure AKS-WI | AWS | `AssumeRoleWithWebIdentity` |
| 4 | Azure AKS-WI | GCP | WIF (oidc) |
| 5 | AWS EKS-IRSA | GCP | WIF (oidc) |
| 6 | AWS EKS-IRSA | Azure | Entra FIC client assertion |
| 7 | AWS EC2 | GCP | WIF (aws / SigV4 proof) |
| — | AWS EC2 | Azure | **negative test** — must refuse with `ErrNoFirstClassPath` |

Rows 1–6 are the six first-class pairs. Row 7 additionally covers the SigV4
path. The last row is the documented gap (Azure accepts only RS256 OIDC, EC2
produces SigV4): the harness asserts cloud-auth **fails with actionable
guidance** rather than failing obscurely. A gap that fails *correctly* is a
feature, and it's tested like one.

## How the verifier reaches each runtime

No container registry required. One static `linux/amd64` binary is built and
delivered per runtime:

| Runtime | Delivery |
|---|---|
| EKS-IRSA / AKS-WI | A bare `sleep` pod bound to the right service account; `kubectl cp` the binary, `kubectl exec` it. The pod inherits the projected SA token — the exact credential under test. |
| EC2 | AWS SSM `send-command` (no inbound SSH). |
| GCE | `gcloud compute scp` + `ssh`. |

The verifier detects its own runtime and runs only the cases matching it, so the
same binary and the same `targets.json` go everywhere.

## Cost

Ballpark with all three clouds up, **~$0.35–0.60/hour**. Dominated by:

| Item | Approx |
|---|---|
| EKS control plane | ~$0.10/hr (charged even when idle) |
| EKS node (t3.small) | ~$0.02/hr |
| AKS control plane | $0 on the Free tier |
| AKS node (Standard_B2s) | ~$0.05/hr |
| EC2 t3.micro | ~$0.01/hr |
| GCE e2-micro | ~$0.01/hr |
| WIF pools, IAM roles, FICs | free |

Per-cloud itemized estimates live in each `tofu/<cloud>/README.md`. A full
`make cycle` typically runs 25–40 minutes (cluster creation dominates), so a
complete run costs well under a dollar — **provided you tear it down.**

## Safety properties

These are deliberate, and worth preserving if you edit the scripts:

1. **Teardown never depends on success.** `make cycle` runs `down` even when
   `verify` fails, and the CI job's destroy step is `if: always()`. A failing
   test must never strand infrastructure.
2. **Destroy is resilient.** `down.sh` tolerates missing, half-applied, or
   un-initialized modules and keeps going after a per-module failure, so one
   stuck cloud can't strand the other two. It exits non-zero if anything failed.
3. **Everything is tagged** `managed-by=cloud-auth-harness` + `run-id=<id>`, so
   `make sweep` can find orphans even if tofu state is lost. `sweep` **lists by
   default**; deleting is opt-in via `--delete`.
4. **Local only — deliberately not in CI.** You run this from a shell, by hand.
   It is not wired into any GitHub workflow and should not be: it needs
   privileged cloud credentials and creates billable infrastructure, so an
   automated trigger risks leaking credentials and spending money unattended.
   The repo's `ci.yml` runs unit tests only and never touches a cloud.
5. **No credentials in output.** The verifier reports identities and outcomes,
   never raw tokens; a unit test enforces the redaction.
6. **Preflight fails before spending.** Required tools are checked for *runnability*,
   not just presence, and every stage-2 module's required inputs are checked
   before any stage-2 apply — so mistakes fail before resources exist, or at
   worst before the trust stage compounds them.

## Prerequisites

- [OpenTofu](https://opentofu.org/docs/intro/install/) ≥ 1.6 (`tofu`)
- `jq`, plus the CLI for each cloud you enable: `aws`, `gcloud`, `az`, `kubectl`
- Go 1.26.5 (to build the verifier)
- Credentials with enough privilege to create the resources in each
  `tofu/<cloud>/README.md`, and to create IAM/trust objects

Static checks that need **no** cloud access:

```bash
make check     # tofu validate + shellcheck + go vet (incl. -tags integration)
```

## Layout

```
test/harness/
├── CONTRACT.md          # authoritative interface between all the pieces
├── Makefile             # up / verify / down / sweep / cycle / check
├── scripts/
│   ├── lib.sh           # shared helpers, preflight, tofu wrappers
│   ├── up.sh            # stage1 -> wire facts -> stage2
│   ├── build-targets.sh # merge stage2 outputs into the verifier's targets.json
│   ├── verify.sh        # deliver + run the verifier in each runtime
│   ├── down.sh          # stage2 down, then stage1 down
│   └── sweep.sh         # find/delete orphans by tag
├── tofu/{aws,gcp,azure}/{stage1,stage2}/
├── verifier/            # the in-cloud verifier (+ Dockerfile, job.yaml)
└── state/               # run artifacts (gitignored)
```

Build-tagged Go integration tests live in [`../integration/`](../integration)
and skip cleanly when no harness is provisioned.

## Troubleshooting

**A destroy failed and I have orphans.** `make sweep` lists everything tagged
for the harness. Prefer re-running `make down` first; fall back to
`tofu -chdir=tofu/<cloud>/<stage> destroy`.

**GCP: "workload identity pool already exists".** Deleted WIF pools are
soft-deleted for 30 days and the ID can't be reused until purged. The pool ID
includes the `run_id` to avoid this; see `tofu/gcp/README.md`.

**Azure: FIC never matches / exchange refused.** Entra matches issuer, subject,
and audience **case-sensitively and exactly**, including trailing slashes. Run
`cloud-auth doctor --to azure ...` inside the pod — it diffs expected vs. actual
and names the mismatch.

**Everything fails on one runtime only.** Check `state/results-<runtime>.log`.
The verifier's report is JSON on stdout; the human-readable trace is on stderr.
