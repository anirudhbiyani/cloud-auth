#!/usr/bin/env bash
# Shared helpers for the cloud-auth integration harness.
# Sourced by up.sh / verify.sh / down.sh / sweep.sh — not executed directly.

set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOFU_DIR="$HARNESS_DIR/tofu"
STATE_DIR="$HARNESS_DIR/state"
REPO_ROOT="$(cd "$HARNESS_DIR/../.." && pwd)"

CLOUDS=(aws gcp azure)

# ---------- output ----------
if [[ -t 1 ]]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_BLU=$'\033[34m'; C_OFF=$'\033[0m'
else
  C_RED=''; C_GRN=''; C_YEL=''; C_BLU=''; C_OFF=''
fi
info()  { printf '%s==>%s %s\n' "$C_BLU" "$C_OFF" "$*"; }
ok()    { printf '%s ok %s %s\n' "$C_GRN" "$C_OFF" "$*"; }
warn()  { printf '%swarn%s %s\n' "$C_YEL" "$C_OFF" "$*" >&2; }
die()   { printf '%sfail%s %s\n' "$C_RED" "$C_OFF" "$*" >&2; exit 1; }

# ---------- preflight ----------
# Checks the tool is present AND actually runnable. Presence alone isn't enough:
# a wrong-architecture binary (x86 on arm64 without Rosetta) sits happily in PATH
# and only explodes mid-run with "Bad CPU type in executable" — after we may have
# already created cloud resources. Fail before we spend money, not during.
need_bin() {
  local bin="$1" hint="${2:-}"
  command -v "$bin" >/dev/null 2>&1 || die "required binary '$bin' not found in PATH. $hint"
  if ! "$bin" --version >/dev/null 2>&1 && ! "$bin" version >/dev/null 2>&1; then
    die "'$bin' is present at $(command -v "$bin") but will not execute (wrong architecture, or broken install). $hint"
  fi
}

require_tofu() {
  need_bin tofu "Install OpenTofu: https://opentofu.org/docs/intro/install/ (this harness uses tofu, not terraform)"
}

require_jq() {
  need_bin jq "Install jq: https://jqlang.github.io/jq/download/"
}

# run_id ties every resource in a run together so orphans are sweepable.
# Reuses the existing one when a run is already in flight.
resolve_run_id() {
  local f="$STATE_DIR/run-id"
  if [[ -n "${CLOUD_AUTH_RUN_ID:-}" ]]; then
    printf '%s' "$CLOUD_AUTH_RUN_ID" > "$f"
  elif [[ ! -f "$f" ]]; then
    printf '%s-%s' "$(date -u +%Y%m%d%H%M)" "$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')" > "$f"
  fi
  cat "$f"
}

# ---------- tofu wrappers ----------
# module_dir <cloud> <stage>
module_dir() { echo "$TOFU_DIR/$1/$2"; }

tofu_apply() {          # tofu_apply <cloud> <stage> [extra tofu args...]
  local cloud="$1" stage="$2"; shift 2
  local dir; dir="$(module_dir "$cloud" "$stage")"
  [[ -d "$dir" ]] || die "missing module: $dir"
  info "apply $cloud/$stage"
  tofu -chdir="$dir" init -input=false >/dev/null
  tofu -chdir="$dir" apply -input=false -auto-approve \
      -var "run_id=$RUN_ID" "$@"
  tofu -chdir="$dir" output -json > "$STATE_DIR/$cloud-$stage.json"
  ok "$cloud/$stage -> state/$cloud-$stage.json"
}

# Destroy must never be blocked by a failed apply, so it tolerates a missing
# or partially-initialized module and reports rather than aborting the sweep.
tofu_destroy() {        # tofu_destroy <cloud> <stage> [extra tofu args...]
  local cloud="$1" stage="$2"; shift 2
  local dir; dir="$(module_dir "$cloud" "$stage")"
  if [[ ! -d "$dir" ]]; then warn "no module $cloud/$stage, skipping"; return 0; fi
  if [[ ! -f "$dir/terraform.tfstate" && ! -d "$dir/.terraform" ]]; then
    warn "no state for $cloud/$stage, nothing to destroy"; return 0
  fi
  info "destroy $cloud/$stage"
  tofu -chdir="$dir" init -input=false >/dev/null 2>&1 || true
  if tofu -chdir="$dir" destroy -input=false -auto-approve -var "run_id=$RUN_ID" "$@"; then
    ok "$cloud/$stage destroyed"
    rm -f "$STATE_DIR/$cloud-$stage.json"
  else
    warn "destroy FAILED for $cloud/$stage — resources may remain. Sweep with: make sweep"
    DESTROY_FAILURES=$((${DESTROY_FAILURES:-0} + 1))
  fi
}

# `tofu output -json` wraps values as {"key":{"value":...}}; flatten for consumers.
flatten_outputs() {     # flatten_outputs <file>
  jq 'with_entries(.value = .value.value)' "$1"
}

# Emit a -var-file for a stage2 module from the other clouds' stage1 facts.
# Only writes keys the module actually declares, so an unused fact is harmless.
write_tfvars() {        # write_tfvars <outfile> <json-object>
  local out="$1" obj="$2"
  jq -r 'to_entries[] | "\(.key) = \(.value|tostring|@json)"' <<<"$obj" > "$out"
}

# Guard against driver/module drift: every variable a module declares WITHOUT a
# default must be present in the tfvars we generated. Without this the mistake
# only surfaces at stage2 apply — i.e. after stage1 has already created billable
# infrastructure. Pure text inspection, so it needs no cloud credentials.
assert_required_vars_supplied() {   # <cloud> <stage> <tfvars-file>
  local cloud="$1" stage="$2" tfvars="$3"
  local vars_tf; vars_tf="$(module_dir "$cloud" "$stage")/variables.tf"
  [[ -f "$vars_tf" ]] || return 0
  local missing=()
  while read -r name; do
    [[ -n "$name" ]] || continue
    grep -qE "^[[:space:]]*$name[[:space:]]*=" "$tfvars" 2>/dev/null || missing+=("$name")
  done < <(awk '
    /^variable[[:space:]]/ { v=$2; gsub(/"/,"",v); d=0; depth=1; next }
    v!="" && /default[[:space:]]*=/ { d=1 }
    v!="" && /^}/ { if(!d) print v; v=""; }
  ' "$vars_tf")
  if (( ${#missing[@]} > 0 )); then
    die "$cloud/$stage requires variable(s) the driver did not supply: ${missing[*]}
     The module declares them with no default. Either up.sh's tfvars generator is
     missing a fact, or an upstream stage1 output is empty. Fix before applying —
     stage1 resources are already running and billing."
  fi
}

confirm() {             # confirm <prompt>
  if [[ "${ASSUME_YES:-0}" == "1" ]]; then return 0; fi
  read -r -p "$1 [y/N] " reply
  [[ "$reply" == "y" || "$reply" == "Y" ]]
}
