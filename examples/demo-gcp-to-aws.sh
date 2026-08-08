#!/usr/bin/env bash
#
# Demo: a GCP workload gets AWS credentials with ZERO static secrets —
#       driven entirely by cloud-auth.
#
# A GCE VM asks its metadata server for a Google-signed OIDC token, presents it
# to AWS STS via AssumeRoleWithWebIdentity, and receives short-lived AWS
# credentials. No AWS access key ever exists on the VM.
#
# Every step uses cloud-auth itself — the whole lifecycle:
#   setup    -> create the AWS-side trust        (cloud-auth setup)
#   validate -> prove the trust is correct       (cloud-auth validate)
#   doctor   -> show the workload's identity     (cloud-auth doctor)
#   exchange -> mint AWS credentials             (cloud-auth exchange)
#   exec     -> run a command with them injected (cloud-auth exec)
#   delete   -> tear the trust down              (cloud-auth delete)
#
#   ./demo-gcp-to-aws.sh preflight   # check tooling + read GCP identity facts
#   ./demo-gcp-to-aws.sh setup       # cloud-auth setup (run where AWS admin creds live)
#   ./demo-gcp-to-aws.sh deploy      # build + copy cloud-auth to the VM
#   ./demo-gcp-to-aws.sh demo        # THE DEMO (runs on the VM)
#   ./demo-gcp-to-aws.sh all         # setup + deploy + demo
#   ./demo-gcp-to-aws.sh cleanup     # cloud-auth delete
#
# Config via env vars:
#   GCP_PROJECT, GCP_ZONE, GCP_VM     the GCE VM acting as the source
#   AWS_ROLE_NAME, AWS_ACCOUNT_ID     the AWS role cloud-auth will create
#   DEMO_AUDIENCE                     audience pinned into both token and trust
set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:-$(gcloud config get-value project 2>/dev/null || true)}"
GCP_ZONE="${GCP_ZONE:-us-central1-a}"
GCP_VM="${GCP_VM:-cloud-auth-demo}"
AWS_ROLE_NAME="${AWS_ROLE_NAME:-cloud-auth-demo-from-gcp}"
AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-}"
# Any string works, but it MUST match in the token and the trust policy.
# Audience pinning is what stops this token being replayed at another trust.
DEMO_AUDIENCE="${DEMO_AUDIENCE:-sts.amazonaws.com}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${TMPDIR:-/tmp}/cloud-auth-demo"
CA="$WORK/cloud-auth"           # locally-built binary, used for setup/validate/delete
mkdir -p "$WORK"

if [[ -t 1 ]]; then B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; N=$'\033[0m'
else B=''; G=''; Y=''; R=''; N=''; fi
say()  { printf '\n%s==> %s%s\n' "$B" "$*" "$N"; }
ok()   { printf '%s  ok%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%swarn%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%sfail%s %s\n' "$R" "$N" "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing '$1' in PATH"; }

build_local() {
  [[ -x "$CA" ]] && return
  ( cd "$REPO_ROOT" && go build -o "$CA" ./cmd/cloud-auth )
}

# ---------------------------------------------------------------------------
# The two facts the AWS trust must pin.
#
# sub = the service account's NUMERIC unique id, not its email. Google puts the
# numeric id in the token's sub claim, so pinning the email would never match.
# ---------------------------------------------------------------------------
gcp_facts() {
  [[ -n "$GCP_PROJECT" ]] || die "set GCP_PROJECT (or: gcloud config set project ...)"
  SA_EMAIL="$(gcloud compute instances describe "$GCP_VM" \
      --project "$GCP_PROJECT" --zone "$GCP_ZONE" \
      --format='value(serviceAccounts[0].email)' 2>/dev/null || true)"
  [[ -n "$SA_EMAIL" ]] || die "could not read the service account of VM '$GCP_VM' in $GCP_ZONE.
     Check GCP_VM / GCP_ZONE / GCP_PROJECT, and that the VM has a service account."
  SA_UNIQUE_ID="$(gcloud iam service-accounts describe "$SA_EMAIL" \
      --project "$GCP_PROJECT" --format='value(uniqueId)')"
  [[ -n "$SA_UNIQUE_ID" ]] || die "could not read the unique id of $SA_EMAIL"

  ok "VM            $GCP_VM ($GCP_ZONE)"
  ok "service acct  $SA_EMAIL"
  ok "sub (uid)     $SA_UNIQUE_ID"
  ok "audience      $DEMO_AUDIENCE"
}

cmd_preflight() {
  say "Preflight"
  need gcloud; need go
  build_local; ok "built cloud-auth"
  gcloud auth list --filter=status:ACTIVE --format='value(account)' | head -1 | grep -q . \
    && ok "gcloud authenticated" || die "run: gcloud auth login"
  [[ -n "$AWS_ACCOUNT_ID" ]] || warn "AWS_ACCOUNT_ID not set — required for 'setup'"
  gcp_facts
  ok "preflight passed"
}

# ---------------------------------------------------------------------------
# cloud-auth creates the AWS-side trust. Run this where AWS admin credentials
# live (your laptop / a bastion) — NOT on the VM. The VM never needs them.
#
# cloud-auth handles two AWS subtleties itself:
#   * Google is a BUILT-IN AWS identity provider, so no iam:OpenIDConnectProvider
#     resource is created and the trust principal is the bare "accounts.google.com".
#   * The audience is pinned with :oaud, not :aud — for accounts.google.com AWS
#     maps :aud to the token's azp claim whenever azp is set, and GCE service
#     account tokens do set it.
# ---------------------------------------------------------------------------
cmd_setup() {
  say "cloud-auth setup — create the AWS role + trust policy"
  build_local; gcp_facts
  [[ -n "$AWS_ACCOUNT_ID" ]] || die "set AWS_ACCOUNT_ID=<12-digit account>"

  echo "  dry run first (shows the plan, changes nothing):"
  "$CA" setup --type aws-oidc \
      --role-name "$AWS_ROLE_NAME" \
      --account-id "$AWS_ACCOUNT_ID" \
      --oidc-url https://accounts.google.com \
      --audience "$DEMO_AUDIENCE" \
      --subject "$SA_UNIQUE_ID" \
      --source gcp \
      --policy-arns arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess \
      --dry-run 2>&1 | sed 's/^/    /'

  echo
  echo "  applying:"
  "$CA" setup --type aws-oidc \
      --role-name "$AWS_ROLE_NAME" \
      --account-id "$AWS_ACCOUNT_ID" \
      --oidc-url https://accounts.google.com \
      --audience "$DEMO_AUDIENCE" \
      --subject "$SA_UNIQUE_ID" \
      --source gcp \
      --policy-arns arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess 2>&1 | tee "$WORK/setup.out" | sed 's/^/    /'

  # cloud-auth records the mechanism in its state file; grab the ref for later.
  MECH_REF="$("$CA" list 2>/dev/null | awk '/aws_role_trust_oidc/ {print $1; exit}')"
  [[ -n "$MECH_REF" ]] && { echo "$MECH_REF" > "$WORK/mech_ref"; ok "mechanism $MECH_REF"; } \
    || warn "could not determine the mechanism ref from 'cloud-auth list'"

  ROLE_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:role/${AWS_ROLE_NAME}"
  echo "$ROLE_ARN" > "$WORK/role_arn"
  ok "role ARN      $ROLE_ARN"

  say "cloud-auth validate — is the trust actually correct?"
  if [[ -n "$MECH_REF" ]]; then
    "$CA" validate --ref "$MECH_REF" 2>&1 | sed 's/^/    /' || true
  else
    warn "skipping validate (no mechanism ref)"
  fi
  warn "IAM changes take a few seconds to propagate. If the first exchange is"
  warn "denied, wait ~10s and retry before debugging."
}

cmd_deploy() {
  say "Build cloud-auth for the VM and copy it over"
  ( cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      go build -trimpath -ldflags='-s -w' -o "$WORK/cloud-auth-linux" ./cmd/cloud-auth )
  ok "built $(du -h "$WORK/cloud-auth-linux" | cut -f1) static linux/amd64 binary"
  gcloud compute scp "$WORK/cloud-auth-linux" "$GCP_VM:~/cloud-auth" \
      --project "$GCP_PROJECT" --zone "$GCP_ZONE" --quiet
  gcloud compute ssh "$GCP_VM" --project "$GCP_PROJECT" --zone "$GCP_ZONE" --quiet \
      --command 'chmod +x ~/cloud-auth'
  ok "deployed to $GCP_VM"
}

# ---------------------------------------------------------------------------
# The demo. Everything below runs ON THE VM, using only cloud-auth.
# ---------------------------------------------------------------------------
cmd_demo() {
  say "THE DEMO — a GCP workload using AWS, with no AWS key anywhere"
  [[ -f "$WORK/role_arn" ]] || die "run '$0 setup' first (no role ARN recorded)"
  ROLE_ARN="$(cat "$WORK/role_arn")"

  local remote
  remote=$(cat <<REMOTE
set -e
echo
echo "=== 1. There are no AWS credentials on this machine ==="
echo -n "AWS_* env vars: "; env | grep -c '^AWS_' || true
[ -d ~/.aws ] && echo "~/.aws exists" || echo "no ~/.aws directory"

echo
echo "=== 2. cloud-auth doctor — what identity does this workload have? ==="
~/cloud-auth doctor --to aws --role '$ROLE_ARN' --audience '$DEMO_AUDIENCE' || true

echo
echo "=== 3. cloud-auth exchange — turn that identity into AWS credentials ==="
~/cloud-auth exchange --to aws --role '$ROLE_ARN' --audience '$DEMO_AUDIENCE' --format json \
  | sed -E 's/("(SecretAccessKey|SessionToken)": ")[^"]*/\1<redacted>/g'

echo
echo "=== 4. cloud-auth exec — run a command with those credentials injected ==="
echo "(the child process sees AWS_* env vars; this parent shell never did)"
~/cloud-auth exec --to aws --role '$ROLE_ARN' --audience '$DEMO_AUDIENCE' -- \\
  sh -c 'echo "inside the child:"; env | grep -o "^AWS_[A-Z_]*" | sed "s/^/  /"'
REMOTE
)
  gcloud compute ssh "$GCP_VM" --project "$GCP_PROJECT" --zone "$GCP_ZONE" --quiet --command "$remote"
  echo
  ok "demo complete — zero static secrets involved"
}

cmd_cleanup() {
  say "cloud-auth delete — tear the trust down"
  build_local
  if [[ -f "$WORK/mech_ref" ]]; then
    "$CA" delete --ref "$(cat "$WORK/mech_ref")" 2>&1 | sed 's/^/    /' \
      && ok "deleted mechanism" || warn "delete reported a problem — check 'cloud-auth list'"
  else
    warn "no mechanism ref recorded; list what remains with: $CA list"
  fi
  rm -rf "$WORK"
}

case "${1:-}" in
  preflight) cmd_preflight ;;
  setup)     cmd_setup ;;
  deploy)    cmd_deploy ;;
  demo)      cmd_demo ;;
  all)       cmd_preflight; cmd_setup; cmd_deploy; cmd_demo ;;
  cleanup)   cmd_cleanup ;;
  *) sed -n '2,29p' "$0"; exit 1 ;;
esac
