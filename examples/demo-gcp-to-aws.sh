#!/usr/bin/env bash
#
# Demo: a GCP workload gets AWS credentials with ZERO static secrets.
#
# A GCE VM asks its metadata server for a Google-signed OIDC token, presents it
# to AWS STS via AssumeRoleWithWebIdentity, and receives short-lived AWS
# credentials. No AWS access key ever exists.
#
#   ./demo-gcp-to-aws.sh preflight    # check tooling and auth
#   ./demo-gcp-to-aws.sh aws-setup    # create the AWS role + trust (AWS admin)
#   ./demo-gcp-to-aws.sh deploy       # build + copy cloud-auth to the VM
#   ./demo-gcp-to-aws.sh demo         # THE DEMO: doctor + exchange + proof
#   ./demo-gcp-to-aws.sh all          # aws-setup + deploy + demo
#   ./demo-gcp-to-aws.sh cleanup      # delete the AWS role
#
# Configure with env vars (or edit the defaults below):
#   GCP_PROJECT, GCP_ZONE, GCP_VM          the GCE VM acting as the source
#   AWS_ROLE_NAME, AWS_REGION              the AWS role to create/assume
#   DEMO_AUDIENCE                          audience pinned into the token+trust
set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:-$(gcloud config get-value project 2>/dev/null || true)}"
GCP_ZONE="${GCP_ZONE:-us-central1-a}"
GCP_VM="${GCP_VM:-cloud-auth-demo}"
AWS_ROLE_NAME="${AWS_ROLE_NAME:-cloud-auth-demo-from-gcp}"
AWS_REGION="${AWS_REGION:-us-east-1}"
# Any string works, but it MUST be identical in the token and the trust policy.
# Audience pinning is what stops this token being replayed at another trust.
DEMO_AUDIENCE="${DEMO_AUDIENCE:-sts.amazonaws.com}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${TMPDIR:-/tmp}/cloud-auth-demo"
mkdir -p "$WORK"

if [[ -t 1 ]]; then B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; N=$'\033[0m'
else B=''; G=''; Y=''; R=''; N=''; fi
say()  { printf '\n%s==> %s%s\n' "$B" "$*" "$N"; }
ok()   { printf '%s  ok%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%swarn%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%sfail%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "missing '$1' in PATH"; }

# ---------------------------------------------------------------------------
# The two facts the AWS trust policy must pin.
#
# sub = the service account's NUMERIC unique id, not its email. Google puts the
# numeric id in the token's sub claim; pinning the email would never match.
# ---------------------------------------------------------------------------
gcp_facts() {
  [[ -n "$GCP_PROJECT" ]] || die "set GCP_PROJECT (or run: gcloud config set project ...)"

  SA_EMAIL="$(gcloud compute instances describe "$GCP_VM" \
      --project "$GCP_PROJECT" --zone "$GCP_ZONE" \
      --format='value(serviceAccounts[0].email)' 2>/dev/null || true)"
  [[ -n "$SA_EMAIL" ]] || die "could not read the service account of VM '$GCP_VM' in $GCP_ZONE.
     Check GCP_VM/GCP_ZONE/GCP_PROJECT, and that the VM has a service account attached."

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
  need gcloud; need aws; need go
  gcloud auth list --filter=status:ACTIVE --format='value(account)' | head -1 \
    | grep -q . && ok "gcloud authenticated" || die "run: gcloud auth login"
  aws sts get-caller-identity >/dev/null 2>&1 \
    && ok "aws authenticated as $(aws sts get-caller-identity --query Arn --output text)" \
    || die "AWS credentials not working. These are only needed on YOUR machine to
     create the role — the VM itself never gets an AWS key."
  gcp_facts
  ok "preflight passed"
}

# ---------------------------------------------------------------------------
# AWS side. Note two things that trip people up:
#
#  1. NO IAM OIDC provider resource is created. Google (like Facebook/Cognito)
#     is a BUILT-IN AWS identity provider, so the principal is the bare string
#     "accounts.google.com", not a provider ARN.
#
#  2. The audience is pinned with :oaud, NOT :aud. For accounts.google.com AWS
#     maps the :aud condition key to the token's azp claim whenever azp is set
#     — and a GCE service-account token DOES set azp (to the SA's unique id).
#     Pinning :aud to the audience would therefore never match, and the demo
#     would fail with an opaque AccessDenied. :oaud always maps to the real aud.
#     Ref: AWS IAM condition-key reference, "Available keys for AWS OIDC federation".
# ---------------------------------------------------------------------------
cmd_aws_setup() {
  say "AWS setup — role + trust policy"
  gcp_facts

  cat > "$WORK/trust.json" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "accounts.google.com" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "accounts.google.com:oaud": "$DEMO_AUDIENCE",
        "accounts.google.com:sub": "$SA_UNIQUE_ID"
      }
    }
  }]
}
EOF
  echo "  trust policy:"; sed 's/^/    /' "$WORK/trust.json"

  if aws iam get-role --role-name "$AWS_ROLE_NAME" >/dev/null 2>&1; then
    aws iam update-assume-role-policy --role-name "$AWS_ROLE_NAME" \
        --policy-document "file://$WORK/trust.json"
    ok "updated existing role $AWS_ROLE_NAME"
  else
    aws iam create-role --role-name "$AWS_ROLE_NAME" \
        --assume-role-policy-document "file://$WORK/trust.json" \
        --description "cloud-auth demo: GCP -> AWS keyless federation" \
        --tags Key=managed-by,Value=cloud-auth-demo >/dev/null
    ok "created role $AWS_ROLE_NAME"
  fi

  # Read-only, so the demo can show the credentials actually doing something.
  aws iam attach-role-policy --role-name "$AWS_ROLE_NAME" \
      --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess >/dev/null 2>&1 \
    && ok "attached AmazonS3ReadOnlyAccess" || warn "could not attach S3 read-only (demo still works)"

  ROLE_ARN="$(aws iam get-role --role-name "$AWS_ROLE_NAME" --query 'Role.Arn' --output text)"
  echo "$ROLE_ARN" > "$WORK/role_arn"
  ok "role ARN      $ROLE_ARN"
  warn "IAM trust changes take a few seconds to propagate. If the first exchange"
  warn "returns AccessDenied, wait ~10s and retry before debugging anything."
}

cmd_deploy() {
  say "Build cloud-auth for the VM and copy it over"
  ( cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      go build -trimpath -ldflags='-s -w' -o "$WORK/cloud-auth" ./cmd/cloud-auth )
  ok "built $(du -h "$WORK/cloud-auth" | cut -f1) static linux/amd64 binary"
  gcloud compute scp "$WORK/cloud-auth" "$GCP_VM:~/cloud-auth" \
      --project "$GCP_PROJECT" --zone "$GCP_ZONE" --quiet
  gcloud compute ssh "$GCP_VM" --project "$GCP_PROJECT" --zone "$GCP_ZONE" --quiet \
      --command 'chmod +x ~/cloud-auth && ~/cloud-auth version 2>/dev/null || true'
  ok "deployed to $GCP_VM"
}

# ---------------------------------------------------------------------------
# The demo itself. Everything below runs ON THE VM.
# ---------------------------------------------------------------------------
cmd_demo() {
  say "THE DEMO — GCP workload obtaining AWS credentials, no static secrets"
  [[ -f "$WORK/role_arn" ]] || { gcp_facts; ROLE_ARN="$(aws iam get-role --role-name "$AWS_ROLE_NAME" --query 'Role.Arn' --output text)"; echo "$ROLE_ARN" > "$WORK/role_arn"; }
  ROLE_ARN="$(cat "$WORK/role_arn")"

  local remote
  remote=$(cat <<REMOTE
set -e
echo
echo "--- 1. Who am I? (no AWS credentials exist on this box) ---"
env | grep -c '^AWS_' | xargs -I{} echo "AWS_* env vars present: {}"
ls ~/.aws 2>/dev/null && echo "(~/.aws exists)" || echo "no ~/.aws directory"

echo
echo "--- 2. cloud-auth doctor: what identity does this workload have? ---"
~/cloud-auth doctor --to aws --role '$ROLE_ARN' --audience '$DEMO_AUDIENCE' || true

echo
echo "--- 3. Exchange the Google identity for AWS credentials ---"
~/cloud-auth exchange --to aws --role '$ROLE_ARN' --audience '$DEMO_AUDIENCE' --format env > /tmp/creds.env
echo "got credentials:"
sed 's/=.*/=<redacted>/' /tmp/creds.env

echo
echo "--- 4. Prove they work: call AWS as the assumed role ---"
set -a; . /tmp/creds.env; set +a
if command -v aws >/dev/null 2>&1; then
  aws sts get-caller-identity
else
  echo "(aws CLI not installed on the VM; credentials above are live and usable)"
fi
rm -f /tmp/creds.env
REMOTE
)
  gcloud compute ssh "$GCP_VM" --project "$GCP_PROJECT" --zone "$GCP_ZONE" --quiet --command "$remote"
  echo
  ok "demo complete — a GCE VM just used AWS with no AWS key anywhere"
}

cmd_cleanup() {
  say "Cleanup"
  aws iam detach-role-policy --role-name "$AWS_ROLE_NAME" \
      --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess >/dev/null 2>&1 || true
  aws iam delete-role --role-name "$AWS_ROLE_NAME" >/dev/null 2>&1 \
    && ok "deleted role $AWS_ROLE_NAME" || warn "role $AWS_ROLE_NAME not found (already gone?)"
  rm -rf "$WORK"
  ok "cleaned up"
}

case "${1:-}" in
  preflight) cmd_preflight ;;
  aws-setup) cmd_aws_setup ;;
  deploy)    cmd_deploy ;;
  demo)      cmd_demo ;;
  all)       cmd_preflight; cmd_aws_setup; cmd_deploy; cmd_demo ;;
  cleanup)   cmd_cleanup ;;
  *) sed -n '2,26p' "$0"; exit 1 ;;
esac
