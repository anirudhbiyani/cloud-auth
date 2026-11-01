#!/usr/bin/env bash
# Provision the cloud-auth integration harness: stage1 (compute) across all
# clouds, then stage2 (cross-cloud trust) wired from stage1's facts.
#
#   ./up.sh [--yes] [--clouds aws,gcp,azure] [--existing aws,azure]
#
# --existing <clouds>: skip stage1 for those clouds and use a hand-written
#   state/<cloud>-stage1.json instead (scripts/existing.sh writes it)
# GKE_CLUSTER=<name> GKE_LOCATION=<zone|region>: GCP source is a pod on that
#   existing cluster instead of a new GCE VM (Workload Identity must be enabled).
#   GKE_PROJECT=<id> when the cluster lives in a different project than the SA.
# LAMBDA=1: also deploy the verifier as a Lambda function (AWS source without an
#   instance); region from AWS_REGION. Facts land in state/aws-lambda.json.
# Extra module inputs (e.g. aws/stage2 azure_oidc_provider_arn + audience when the
#   AKS issuer is already federated into the account) go in
#   tofu/<cloud>/<stage>/local.auto.tfvars, which tofu picks up and git ignores.
#   state/<cloud>-stage1.json instead (keys in CONTRACT.md, tofu-output shape
#   {"key":{"value":...}}). For pointing the harness at clusters you already run.
#
# This creates REAL, BILLABLE cloud resources. See README.md for the estimate.
# Always pair with ./down.sh — see also `make sweep` if a destroy fails.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

SELECTED="aws,gcp,azure"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes|-y)  ASSUME_YES=1; shift ;;
    --clouds)  SELECTED="$2"; shift 2 ;;
    --existing) EXISTING="$2"; shift 2 ;;   # clouds whose stage1 runtime already exists
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) die "unknown flag: $1" ;;
  esac
done
IFS=',' read -r -a ACTIVE <<< "$SELECTED"

require_tofu; require_jq
RUN_ID="$(resolve_run_id)"; export RUN_ID

cat <<BANNER

  cloud-auth integration harness
  run-id : $RUN_ID
  clouds : ${ACTIVE[*]}

  ${C_YEL}This provisions REAL, BILLABLE infrastructure${C_OFF} — EKS + AKS clusters,
  a GCE VM, an EC2 instance, and the cross-cloud trust objects.
  Rough order of magnitude: ~\$0.35-0.60/hour with all three clouds active
  (EKS control plane ~\$0.10/hr, AKS node pool, EC2 + GCE instances).
  Per-cloud itemized estimates are in each tofu/<cloud>/README.md.

  Tear down with ./down.sh as soon as verification finishes.

BANNER

confirm "Provision now?" || die "aborted (nothing was created)"

mkdir -p "$STATE_DIR"

# ---- stage 1: compute / source runtimes (independent, could be parallel) ----
info "STAGE 1 — source runtimes"
for c in "${ACTIVE[@]}"; do
  if [[ ",${EXISTING:-}," == *",$c,"* ]]; then
    [[ -f "$STATE_DIR/$c-stage1.json" ]] || die "--existing $c: write state/$c-stage1.json first (see CONTRACT.md)"
    ok "$c stage1: using existing runtime from state/$c-stage1.json"; continue
  fi
  if [[ "$c" == gcp && -n "${GKE_CLUSTER:-}" ]]; then
    [[ -n "${GKE_LOCATION:-}" ]] || die "GKE_CLUSTER is set; GKE_LOCATION (zone or region) is required too"
    tofu_apply gcp stage1 -var "gke_cluster=$GKE_CLUSTER" -var "gke_location=$GKE_LOCATION" -var "gke_project=${GKE_PROJECT:-}"; continue
  fi
  tofu_apply "$c" stage1
done

# ---- optional serverless AWS source ----------------------------------------
# LAMBDA=1 adds a Lambda function running the verifier: the SigV4 (EC2-style) proof
# without any instance. The zip is the static verifier as `bootstrap`.
if [[ -n "${LAMBDA:-}" && " ${ACTIVE[*]} " == *" aws "* ]]; then
  info "building verifier for Lambda (linux/amd64 bootstrap)"
  ( cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      go build -trimpath -ldflags='-s -w' -o "$STATE_DIR/bootstrap" ./test/harness/verifier )
  ( cd "$STATE_DIR" && rm -f verifier-lambda.zip && zip -q -j verifier-lambda.zip bootstrap )
  tofu_apply aws lambda -var "zip_path=$STATE_DIR/verifier-lambda.zip" -var "region=${AWS_REGION:-us-east-1}"
fi

# ---- assemble cross-cloud facts -------------------------------------------
# stage2 for each cloud needs the OTHER clouds' stage1 outputs. We flatten and
# re-namespace them so every stage2 module sees a predictable variable name.
info "assembling cross-cloud facts"
declare -A S1
for c in "${ACTIVE[@]}"; do
  S1[$c]="$(flatten_outputs "$STATE_DIR/$c-stage1.json")"
done

fact() { # fact <cloud> <key> -> value or empty
  jq -r --arg k "$2" '.[$k] // empty' <<<"${S1[$1]:-{\}}"
}

# AWS stage2 consumes GCP + Azure identity facts.
if [[ -n "${S1[aws]:-}" ]]; then
  write_tfvars "$(module_dir aws stage2)/harness.auto.tfvars" "$(jq -n \
    --arg gcp_issuer_url             "$(fact gcp issuer_url)" \
    --arg gcp_source_sa_unique_id    "$(fact gcp source_sa_unique_id)" \
    --arg azure_aks_oidc_issuer_url  "$(fact azure aks_oidc_issuer_url)" \
    --arg azure_subject              "$(fact azure subject)" \
    '$ARGS.named | with_entries(select(.value != ""))')"
fi

# The SigV4 provider trusts ONE role: the Lambda's when present, else the EC2 instance's, else a
# placeholder that matches nothing (the module requires a non-empty name).
# ponytail: single role; make gcp/stage2 take a list if both runtimes must pass in one run.
sigv4_role="$(jq -r '.lambda_role_name.value // empty' "$STATE_DIR/aws-lambda.json" 2>/dev/null)"
[[ -n "$sigv4_role" ]] || sigv4_role="$(fact aws ec2_role_name)"
[[ -n "$sigv4_role" ]] || sigv4_role="cloud-auth-test-no-sigv4-source"

# GCP stage2 consumes AWS + Azure identity facts.
# aws_ec2_role_name is the bare role NAME (not the ARN): the SigV4 provider binds
# principalSet://.../attribute.aws_role/<name>, because the EC2 assertion ARN's
# trailing component is the instance id and so can't be matched as a fixed subject.
if [[ -n "${S1[gcp]:-}" ]]; then
  write_tfvars "$(module_dir gcp stage2)/harness.auto.tfvars" "$(jq -n \
    --arg aws_account_id             "$(fact aws account_id)" \
    --arg aws_eks_oidc_issuer_url    "$(fact aws eks_oidc_issuer_url)" \
    --arg aws_irsa_subject           "$(fact aws irsa_subject)" \
    --arg aws_ec2_role_name          "$sigv4_role" \
    --arg azure_aks_oidc_issuer_url  "$(fact azure aks_oidc_issuer_url)" \
    --arg azure_subject              "$(fact azure subject)" \
    '$ARGS.named | with_entries(select(.value != ""))')"
fi

# Azure stage2 consumes GCP + AWS identity facts.
if [[ -n "${S1[azure]:-}" ]]; then
  write_tfvars "$(module_dir azure stage2)/harness.auto.tfvars" "$(jq -n \
    --arg gcp_issuer_url           "$(fact gcp issuer_url)" \
    --arg gcp_source_sa_unique_id  "$(fact gcp source_sa_unique_id)" \
    --arg aws_eks_oidc_issuer_url  "$(fact aws eks_oidc_issuer_url)" \
    --arg aws_irsa_subject         "$(fact aws irsa_subject)" \
    '$ARGS.named | with_entries(select(.value != ""))')"
fi

# ---- stage 2: cross-cloud trust -------------------------------------------
# Check every module's required inputs are covered BEFORE applying any of them,
# so a drift bug fails the whole batch cleanly instead of half-wiring the trust.
for c in "${ACTIVE[@]}"; do
  assert_required_vars_supplied "$c" stage2 "$(module_dir "$c" stage2)/harness.auto.tfvars"
done
ok "stage2 inputs complete for: ${ACTIVE[*]}"

info "STAGE 2 — cross-cloud trust"
for c in "${ACTIVE[@]}"; do
  tofu_apply "$c" stage2
done

# ---- merge into the verifier's input --------------------------------------
info "building state/targets.json"
"$HARNESS_DIR/scripts/build-targets.sh"

ok "harness up (run-id $RUN_ID). Next: ./verify.sh   then: ./down.sh"
