#!/usr/bin/env bash
# Single local entry point for the cloud-auth integration harness.
#
# Runs the whole loop on your machine — provision, verify, destroy — with
# teardown guaranteed even if verification fails or you Ctrl-C mid-run.
# This harness is deliberately LOCAL ONLY: it is not wired into CI, because it
# needs privileged cloud credentials and creates billable infrastructure.
#
#   ./run-harness.sh                          # full cycle, all clouds
#   ./run-harness.sh --clouds aws,gcp         # subset of clouds
#   ./run-harness.sh --runtimes aws-ec2       # subset of source runtimes
#   ./run-harness.sh --keep                   # leave it up for debugging
#   ./run-harness.sh --yes                    # no prompts (unattended)
#   ./run-harness.sh --check                  # static checks only, no cloud calls
#
# Individual phases are still available directly:
#   ./scripts/up.sh   ./scripts/verify.sh   ./scripts/down.sh   ./scripts/sweep.sh

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./scripts/lib.sh

CLOUDS="aws,gcp,azure"
RUNTIMES="gcp-gce,aws-ec2,aws-eks-irsa,azure-aks-workload-identity"
KEEP=0
CHECK_ONLY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --clouds)   CLOUDS="$2"; shift 2 ;;
    --runtimes) RUNTIMES="$2"; shift 2 ;;
    --keep)     KEEP=1; shift ;;
    --yes|-y)   ASSUME_YES=1; export ASSUME_YES; shift ;;
    --check)    CHECK_ONLY=1; shift ;;
    -h|--help)  sed -n '2,18p' "$0"; exit 0 ;;
    *) die "unknown flag: $1 (try --help)" ;;
  esac
done

# ---------- static checks (no cloud access, no cost) ----------
run_static_checks() {
  info "static checks"
  local rc=0
  for f in scripts/*.sh run-harness.sh; do
    bash -n "$f" || { warn "bash syntax: $f"; rc=1; }
  done
  ok "shell syntax"

  if command -v tofu >/dev/null 2>&1 && tofu version >/dev/null 2>&1; then
    for d in tofu/*/stage1 tofu/*/stage2; do
      [[ -d "$d" ]] || continue
      if tofu -chdir="$d" init -backend=false -input=false >/dev/null 2>&1 \
         && tofu -chdir="$d" validate >/dev/null 2>&1; then
        ok "tofu validate $d"
      else
        warn "tofu validate FAILED: $d"; rc=1
      fi
    done
  else
    warn "tofu unavailable — skipping HCL validation"
  fi

  ( cd ../.. && go vet ./test/... >/dev/null 2>&1 ) && ok "go vet" || { warn "go vet failed"; rc=1; }
  return $rc
}

if (( CHECK_ONLY )); then
  run_static_checks
  exit $?
fi

# ---------- teardown guarantee ----------
# Covers every exit path: verify failing, a mid-run error under `set -e`, or
# Ctrl-C. Without this an interrupted run silently leaves clusters billing.
#
# INT/TERM are handled by their OWN handler that exits 130 explicitly, rather
# than sharing the EXIT trap. Bash defers a trapped signal until the running
# foreground command returns, and the signal's status does not reliably surface
# in `$?` afterwards — so inferring "was I interrupted?" from exit codes lets a
# cancelled run report success. That false green is worse than a leak, because
# nobody goes looking. Track it in a flag instead.
TORE_DOWN=0
INTERRUPTED=0

do_teardown() {         # idempotent; honours --keep
  if (( TORE_DOWN )) || (( KEEP )); then return 0; fi
  TORE_DOWN=1
  echo
  info "tearing down"
  ASSUME_YES=1 ./scripts/down.sh --yes --clouds "$CLOUDS" || \
    warn "teardown incomplete — run ./scripts/sweep.sh to find orphans"
}

on_exit() {
  local rc=$?
  if (( TORE_DOWN )) || (( KEEP )); then return; fi
  warn "exiting early (code $rc) — destroying harness infrastructure"
  do_teardown
}

on_signal() {
  INTERRUPTED=1
  echo
  warn "interrupted — destroying harness infrastructure before exit"
  do_teardown
  if (( KEEP )); then
    warn "--keep set: infrastructure is STILL RUNNING. Destroy: ./scripts/down.sh --clouds $CLOUDS"
  fi
  exit 130
}

trap on_exit EXIT
trap on_signal INT TERM

run_static_checks || die "static checks failed — fix before spending money on infrastructure"

# ---------- the cycle ----------
./scripts/up.sh ${ASSUME_YES:+--yes} --clouds "$CLOUDS"

VERIFY_RC=0
./scripts/verify.sh --runtimes "$RUNTIMES" || VERIFY_RC=$?

if (( KEEP )); then
  echo
  warn "--keep set: infrastructure is STILL RUNNING and billing."
  warn "Destroy it when done:  ./scripts/down.sh --clouds $CLOUDS"
else
  do_teardown
fi
trap - EXIT INT TERM

echo
if (( INTERRUPTED )); then
  die "run was interrupted — results are incomplete"
fi
if (( VERIFY_RC != 0 )); then
  die "verification FAILED (exit $VERIFY_RC) — see state/results-*.json"
fi
ok "all pairs verified$( (( KEEP )) || printf ', infrastructure destroyed')"
