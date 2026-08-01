#!/usr/bin/env bash
# Find (and optionally delete) harness resources left behind by a failed destroy.
#
#   ./sweep.sh            # list only — safe, read-only, the default
#   ./sweep.sh --delete   # actually delete what it finds
#
# Everything the harness creates carries managed-by=cloud-auth-harness, so this
# can find orphans even when tofu state is lost. Listing is the default because
# deleting cloud resources from a tag query is exactly the kind of thing that
# should never happen by accident.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

DELETE=0
RUN_ID_FILTER="${CLOUD_AUTH_RUN_ID:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --delete)  DELETE=1; shift ;;
    --run-id)  RUN_ID_FILTER="$2"; shift 2 ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) die "unknown flag: $1" ;;
  esac
done

TAG_K="managed-by"; TAG_V="cloud-auth-harness"
[[ -n "$RUN_ID_FILTER" ]] && info "filtering to run-id=$RUN_ID_FILTER" || info "scanning ALL harness runs"

# ---------------- AWS ----------------
if command -v aws >/dev/null 2>&1; then
  info "AWS — tagged resources"
  filters=(--tag-filters "Key=$TAG_K,Values=$TAG_V")
  [[ -n "$RUN_ID_FILTER" ]] && filters+=(--tag-filters "Key=run-id,Values=$RUN_ID_FILTER")
  aws resourcegroupstaggingapi get-resources "${filters[@]}" \
      --query 'ResourceTagMappingList[].ResourceARN' --output table 2>/dev/null \
    || warn "AWS scan failed (credentials? region?)"
  if (( DELETE )); then
    warn "AWS: no bulk delete — resource types differ too much to delete safely."
    warn "     Prefer: tofu -chdir=test/harness/tofu/aws/<stage> destroy"
  fi
else
  warn "aws CLI not found, skipping AWS scan"
fi

# ---------------- GCP ----------------
if command -v gcloud >/dev/null 2>&1; then
  info "GCP — labelled resources"
  proj="$(gcloud config get-value project 2>/dev/null)"
  if [[ -n "$proj" && "$proj" != "(unset)" ]]; then
    gcloud compute instances list --project "$proj" \
        --filter="labels.$TAG_K=$TAG_V" --format='table(name,zone,status)' 2>/dev/null || true
    gcloud iam workload-identity-pools list --project "$proj" --location global \
        --format='table(name,state)' 2>/dev/null \
      | grep -i "$TAG_V" || true
    warn "GCP: deleted WIF pools are SOFT-DELETED for 30 days and the id cannot be"
    warn "     reused until purged — see tofu/gcp/README.md."
  else
    warn "no gcloud project configured, skipping GCP scan"
  fi
else
  warn "gcloud not found, skipping GCP scan"
fi

# ---------------- Azure ----------------
if command -v az >/dev/null 2>&1; then
  info "Azure — tagged resources"
  q="[?tags.\"$TAG_K\"=='$TAG_V'"
  [[ -n "$RUN_ID_FILTER" ]] && q+=" && tags.\"run-id\"=='$RUN_ID_FILTER'"
  q+="].{name:name,type:type,rg:resourceGroup}"
  az resource list --query "$q" --output table 2>/dev/null || warn "Azure scan failed (az login?)"
  if (( DELETE )); then
    rgs="$(az group list --query "[?tags.\"$TAG_K\"=='$TAG_V'].name" -o tsv 2>/dev/null || true)"
    for rg in $rgs; do
      confirm "delete Azure resource group '$rg' and everything in it?" \
        && az group delete --name "$rg" --yes --no-wait && ok "deleting $rg (async)"
    done
  fi
else
  warn "az CLI not found, skipping Azure scan"
fi

echo
if (( DELETE )); then
  ok "sweep --delete finished (AWS/GCP still need per-module destroy)"
else
  info "listing only. Re-run with --delete to remove, or prefer 'make down'."
fi
