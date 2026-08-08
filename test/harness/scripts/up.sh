#!/usr/bin/env bash
# Provision the cloud-auth integration harness: stage1 (compute) across all
# clouds, then stage2 (cross-cloud trust) wired from stage1's facts.
#
#   ./up.sh [--yes] [--clouds aws,gcp,azure]
#
# This creates REAL, BILLABLE cloud resources. See README.md for the estimate.
# Always pair with ./down.sh — see also `make sweep` if a destroy fails.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

SELECTED="aws,gcp,azure"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes|-y)  ASSUME_YES=1; shift ;;
    --clouds)  SELECTED="$2"; shift 2 ;;
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
  tofu_apply "$c" stage1
done

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

# GCP stage2 consumes AWS + Azure identity facts.
# aws_ec2_role_name is the bare role NAME (not the ARN): the SigV4 provider binds
# principalSet://.../attribute.aws_role/<name>, because the EC2 assertion ARN's
# trailing component is the instance id and so can't be matched as a fixed subject.
if [[ -n "${S1[gcp]:-}" ]]; then
  write_tfvars "$(module_dir gcp stage2)/harness.auto.tfvars" "$(jq -n \
    --arg aws_account_id             "$(fact aws account_id)" \
    --arg aws_eks_oidc_issuer_url    "$(fact aws eks_oidc_issuer_url)" \
    --arg aws_irsa_subject           "$(fact aws irsa_subject)" \
    --arg aws_ec2_role_name          "$(fact aws ec2_role_name)" \
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
