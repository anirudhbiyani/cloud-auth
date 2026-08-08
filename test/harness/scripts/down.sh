#!/usr/bin/env bash
# Tear the harness down: stage2 (trust) first, then stage1 (compute).
#
#   ./down.sh [--yes] [--clouds aws,gcp,azure]
#
# Destroy is deliberately resilient: it NEVER depends on verify having passed,
# tolerates half-applied or missing modules, and keeps going after a per-module
# failure so one stuck cloud can't strand the other two. Exits non-zero if any
# module failed so CI notices, and points at `make sweep` for the leftovers.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

SELECTED="aws,gcp,azure"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes|-y)  ASSUME_YES=1; shift ;;
    --clouds)  SELECTED="$2"; shift 2 ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) die "unknown flag: $1" ;;
  esac
done
IFS=',' read -r -a ACTIVE <<< "$SELECTED"

require_tofu
RUN_ID="$(resolve_run_id)"; export RUN_ID
DESTROY_FAILURES=0

info "tearing down run-id $RUN_ID (clouds: ${ACTIVE[*]})"
confirm "Destroy all harness infrastructure?" || die "aborted (nothing destroyed)"

# Trust objects reference the compute identities, so stage2 must go first.
info "STAGE 2 — trust"
for c in "${ACTIVE[@]}"; do tofu_destroy "$c" stage2; done

info "STAGE 1 — compute"
for c in "${ACTIVE[@]}"; do tofu_destroy "$c" stage1; done

# Generated tfvars are derived artifacts; drop them so a later run can't pick up
# stale cross-cloud facts.
for c in "${ACTIVE[@]}"; do rm -f "$(module_dir "$c" stage2)/harness.auto.tfvars"; done
rm -f "$STATE_DIR/targets.json"

if (( DESTROY_FAILURES > 0 )); then
  warn "$DESTROY_FAILURES module(s) failed to destroy."
  warn "Resources are tagged managed-by=cloud-auth-harness run-id=$RUN_ID."
  warn "List what remains with:  make sweep"
  exit 1
fi

rm -f "$STATE_DIR/run-id"
ok "harness fully destroyed"
