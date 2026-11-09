#!/usr/bin/env bash
# Merge the per-cloud stage2 outputs into state/targets.json — the single input
# the in-cloud verifier reads. Shape is defined in CONTRACT.md.
#
# Emits one case per row of the pair matrix, including the negative case for the
# documented AWS-EC2 -> Azure gap (which must fail with ErrNoFirstClassPath).
# A case is only emitted when the facts it needs are present, so a partial run
# (e.g. --clouds aws,gcp) produces a correspondingly partial matrix.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
require_jq

RUN_ID="$(resolve_run_id)"

read_stage() { # read_stage <cloud> <stage> -> flattened object, or {}
  local f="$STATE_DIR/$1-$2.json"
  [[ -f "$f" ]] && flatten_outputs "$f" || echo '{}'
}

GCP1="$(read_stage gcp stage1)"
AWS1="$(read_stage aws stage1)"
AWSL="$(read_stage aws lambda)"
AWS2="$(read_stage aws stage2)"
GCP2="$(read_stage gcp stage2)"
AZ2="$(read_stage azure stage2)"

g() { jq -r --arg k "$2" '.[$k] // empty' <<<"$1"; }   # g <obj> <key>

cases='[]'
add() { cases="$(jq -c --argjson c "$1" '. + [$c]' <<<"$cases")"; }

# 1. GCP GCE -> AWS (GKE mode has no VM, so these two rows drop out)
if [[ -n "$(g "$GCP1" gce_instance_name)" && -n "$(g "$AWS2" role_arn_for_gcp_source)" ]]; then
  add "$(jq -n --arg r "$(g "$AWS2" role_arn_for_gcp_source)" --arg a "$(g "$AWS2" audience)" '{
    name:"gcp-gce-to-aws", expect:"success", source_runtime:"gcp-gce",
    target:{cloud:"aws", role:$r, audience:$a}, probe:"sts-get-caller-identity"}')"
fi

# 2. GCP GCE -> Azure
if [[ -n "$(g "$GCP1" gce_instance_name)" && -n "$(g "$AZ2" client_id_for_gcp_source)" ]]; then
  add "$(jq -n --arg t "$(g "$AZ2" tenant_id)" --arg c "$(g "$AZ2" client_id_for_gcp_source)" --arg a "$(g "$AZ2" audience)" '{
    name:"gcp-gce-to-azure", expect:"success", source_runtime:"gcp-gce",
    target:{cloud:"azure", tenant:$t, client_id:$c, audience:$a, scope:"https://management.azure.com/.default"}}')"
fi

# 1b/2b. GCP GKE -> AWS / Azure: same token shape as GCE (accounts.google.com, sub = SA unique id), so the same trust objects.
if [[ -n "$(g "$GCP1" gke_cluster_name)" ]]; then
  [[ -n "$(g "$AWS2" role_arn_for_gcp_source)" ]] && add "$(jq -n --arg r "$(g "$AWS2" role_arn_for_gcp_source)" --arg a "$(g "$AWS2" audience)" '{
    name:"gcp-gke-to-aws", expect:"success", source_runtime:"gcp-gke",
    target:{cloud:"aws", role:$r, audience:$a}, probe:"sts-get-caller-identity"}')"
  [[ -n "$(g "$AZ2" client_id_for_gcp_source)" ]] && add "$(jq -n --arg t "$(g "$AZ2" tenant_id)" --arg c "$(g "$AZ2" client_id_for_gcp_source)" --arg a "$(g "$AZ2" audience)" '{
    name:"gcp-gke-to-azure", expect:"success", source_runtime:"gcp-gke",
    target:{cloud:"azure", tenant:$t, client_id:$c, audience:$a, scope:"https://management.azure.com/.default"}}')"
fi

# 3. Azure AKS workload identity -> AWS
if [[ -n "$(g "$AWS2" role_arn_for_azure_source)" ]]; then
  add "$(jq -n --arg r "$(g "$AWS2" role_arn_for_azure_source)" --arg a "$(g "$AWS2" audience)" '{
    name:"azure-aks-to-aws", expect:"success", source_runtime:"azure-aks-workload-identity",
    target:{cloud:"aws", role:$r, audience:$a}, probe:"sts-get-caller-identity"}')"
fi

# 4. Azure AKS workload identity -> GCP
if [[ -n "$(g "$GCP2" provider_for_azure_oidc)" ]]; then
  add "$(jq -n --arg p "$(g "$GCP2" provider_for_azure_oidc)" --arg a "$(g "$GCP2" audience_for_azure_oidc)" '{
    name:"azure-aks-to-gcp", expect:"success", source_runtime:"azure-aks-workload-identity",
    target:{cloud:"gcp", workload_identity_pool:$p, audience:$a}}')"
fi

# 5. AWS EKS IRSA -> GCP
if [[ -n "$(g "$GCP2" provider_for_aws_oidc)" ]]; then
  add "$(jq -n --arg p "$(g "$GCP2" provider_for_aws_oidc)" --arg a "$(g "$GCP2" audience_for_aws_oidc)" '{
    name:"aws-irsa-to-gcp", expect:"success", source_runtime:"aws-eks-irsa",
    target:{cloud:"gcp", workload_identity_pool:$p, audience:$a}}')"
fi

# 6. AWS EKS IRSA -> Azure
if [[ -n "$(g "$AZ2" client_id_for_aws_source)" ]]; then
  add "$(jq -n --arg t "$(g "$AZ2" tenant_id)" --arg c "$(g "$AZ2" client_id_for_aws_source)" --arg a "$(g "$AZ2" audience)" '{
    name:"aws-irsa-to-azure", expect:"success", source_runtime:"aws-eks-irsa",
    target:{cloud:"azure", tenant:$t, client_id:$c, audience:$a, scope:"https://management.azure.com/.default"}}')"
fi

# 7. AWS EC2 (SigV4) -> GCP
if [[ -n "$(g "$AWS1" ec2_instance_id)" && -n "$(g "$GCP2" provider_for_aws_sigv4)" ]]; then
  add "$(jq -n --arg p "$(g "$GCP2" provider_for_aws_sigv4)" --arg a "$(g "$GCP2" audience_for_aws_sigv4)" '{
    name:"aws-ec2-sigv4-to-gcp", expect:"success", aws_proof:"sigv4", source_runtime:"aws-ec2",
    target:{cloud:"gcp", workload_identity_pool:$p, audience:$a}}')"
fi

# Negative: AWS EC2 -> Azure is the documented gap (SigV4 proof, Azure wants
# RS256 OIDC). cloud-auth must refuse with actionable guidance, not fail obscurely.
if [[ -n "$(g "$AWS1" ec2_instance_id)" && -n "$(g "$AZ2" client_id_for_gcp_source)" ]]; then
  add "$(jq -n --arg t "$(g "$AZ2" tenant_id)" --arg c "$(g "$AZ2" client_id_for_gcp_source)" --arg a "$(g "$AZ2" audience)" '{
    name:"aws-ec2-to-azure-gap", expect:"error", expect_error:"ErrNoFirstClassPath", aws_proof:"sigv4",
    source_runtime:"aws-ec2",
    target:{cloud:"azure", tenant:$t, client_id:$c, audience:$a, scope:"https://management.azure.com/.default"}}')"
fi

# 7b/8b. AWS Lambda: same SigV4 proof as EC2, no instance. Success to GCP, documented gap to Azure.
if [[ -n "$(g "$AWSL" lambda_function_name)" ]]; then
  [[ -n "$(g "$GCP2" provider_for_aws_sigv4)" ]] && add "$(jq -n --arg p "$(g "$GCP2" provider_for_aws_sigv4)" --arg a "$(g "$GCP2" audience_for_aws_sigv4)" '{
    name:"aws-lambda-sigv4-to-gcp", expect:"success", aws_proof:"sigv4", source_runtime:"aws-lambda",
    target:{cloud:"gcp", workload_identity_pool:$p, audience:$a}}')"
  [[ -n "$(g "$AZ2" client_id_for_gcp_source)" ]] && add "$(jq -n --arg t "$(g "$AZ2" tenant_id)" --arg c "$(g "$AZ2" client_id_for_gcp_source)" --arg a "$(g "$AZ2" audience)" '{
    name:"aws-lambda-to-azure-gap", expect:"error", expect_error:"ErrNoFirstClassPath", aws_proof:"sigv4", source_runtime:"aws-lambda",
    target:{cloud:"azure", tenant:$t, client_id:$c, audience:$a, scope:"https://management.azure.com/.default"}}')"
fi

jq -n --arg r "$RUN_ID" --argjson c "$cases" '{run_id:$r, cases:$c}' > "$STATE_DIR/targets.json"
ok "state/targets.json — $(jq '.cases|length' "$STATE_DIR/targets.json") case(s)"
jq -r '.cases[] | "     \(.name)  [\(.expect)]  \(.source_runtime) -> \(.target.cloud)"' "$STATE_DIR/targets.json"
