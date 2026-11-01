#!/usr/bin/env bash
# Write state/<cloud>-stage1.json for a cluster you ALREADY run, so
# `./up.sh --existing <cloud>` skips stage1 and only creates the trust objects.
#
#   ./existing.sh aws   <eks-cluster-name> <region>
#   ./existing.sh azure <resource-group> <aks-cluster-name>
#
# Keys follow CONTRACT.md. Only reads from the cloud; writes one local file.
# GCP: set GKE_CLUSTER / GKE_LOCATION for ./up.sh instead. Its stage1 still runs
# (it creates the source SA + Workload Identity binding), just without the VM.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
require_jq
mkdir -p "$STATE_DIR"
NS=cloud-auth-test; SA=verifier
wrap() { jq 'with_entries(.value = {value: .value})'; }   # tofu-output shape
mark() { touch "$STATE_DIR/$1-stage1.existing"; }          # tells down.sh this file is hand-written

case "${1:-}" in
  aws)
    [[ $# -eq 3 ]] || die "usage: existing.sh aws <eks-cluster-name> <region>"
    cluster="$2" region="$3"
    issuer="$(aws eks describe-cluster --name "$cluster" --region "$region" --query cluster.identity.oidc.issuer --output text)"
    acct="$(aws sts get-caller-identity --query Account --output text)"
    jq -n --arg a "$acct" --arg r "$region" --arg c "$cluster" --arg i "$issuer" --arg ns "$NS" --arg sa "$SA" '{
      account_id:$a, region:$r, eks_cluster_name:$c,
      eks_oidc_issuer_url:$i, eks_oidc_issuer_host_path:($i|sub("^https://";"")),
      irsa_namespace:$ns, irsa_service_account:$sa, irsa_subject:("system:serviceaccount:"+$ns+":"+$sa)}' | wrap > "$STATE_DIR/aws-stage1.json"
    mark aws
    ok "wrote state/aws-stage1.json for EKS $cluster ($region, account $acct)" ;;
  azure)
    [[ $# -eq 3 ]] || die "usage: existing.sh azure <resource-group> <aks-cluster-name>"
    rg="$2" cluster="$3"
    aks="$(az aks show -g "$rg" -n "$cluster" --query '{loc:location,issuer:oidcIssuerProfile.issuerUrl,wi:securityProfile.workloadIdentity.enabled}' -o json)"
    [[ "$(jq -r .wi <<<"$aks")" == "true" ]] || die "$cluster: workload identity is not enabled"
    acct="$(az account show --query '{tenant:tenantId,sub:id}' -o json)"
    jq -n --argjson aks "$aks" --argjson acct "$acct" --arg rg "$rg" --arg c "$cluster" --arg ns "$NS" --arg sa "$SA" '{
      tenant_id:$acct.tenant, subscription_id:$acct.sub, location:$aks.loc, resource_group:$rg,
      aks_cluster_name:$c, aks_oidc_issuer_url:$aks.issuer,
      namespace:$ns, service_account:$sa, subject:("system:serviceaccount:"+$ns+":"+$sa)}' | wrap > "$STATE_DIR/azure-stage1.json"
    mark azure
    ok "wrote state/azure-stage1.json for AKS $cluster ($rg)" ;;
  *) sed -n '2,10p' "$0"; exit 1 ;;
esac
