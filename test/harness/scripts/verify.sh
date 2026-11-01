#!/usr/bin/env bash
# Run the verifier inside every provisioned source runtime and collect results.
#
#   ./verify.sh [--runtimes gcp-gce,gcp-gke,aws-ec2,aws-lambda,aws-eks-irsa,azure-aks-workload-identity]
#
# Design note: rather than requiring a container registry, we build ONE static
# linux/amd64 binary and deliver it to each runtime:
#   * k8s (EKS-IRSA, AKS-WI, GKE-WI) : start a bare sleep pod bound to the right service
#                              account, `kubectl cp` the binary in, `kubectl exec` it.
#                              The pod inherits the projected SA token, which is
#                              exactly the credential under test.
#   * EC2                    : AWS SSM send-command (no inbound SSH needed).
#   * Lambda                 : the binary IS the function (bootstrap); invoke with
#                              targets.json as the event, the report is the response.
#   * GCE                    : gcloud compute scp + ssh.
# The verifier self-selects which cases to run by detecting its own runtime, so
# the same binary and the same targets.json go everywhere.
#
# Results land in state/results-<runtime>.json. Exits non-zero if any case failed.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
require_jq

RUNTIMES="gcp-gce,gcp-gke,aws-ec2,aws-lambda,aws-eks-irsa,azure-aks-workload-identity"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --runtimes) RUNTIMES="$2"; shift 2 ;;
    -h|--help)  sed -n '2,20p' "$0"; exit 0 ;;
    *) die "unknown flag: $1" ;;
  esac
done
IFS=',' read -r -a ACTIVE <<< "$RUNTIMES"

TARGETS="$STATE_DIR/targets.json"
[[ -f "$TARGETS" ]] || die "no state/targets.json — run ./up.sh first"

BIN="$STATE_DIR/verifier-linux-amd64"
NS=cloud-auth-test
SA=verifier
# ponytail: one kube context per k8s runtime via EKS_CONTEXT / AKS_CONTEXT / GKE_CONTEXT; unset = current context.
CTX=""
kubectl() { command kubectl ${CTX:+--context "$CTX"} "$@"; }
FAILED=0

info "building static verifier (linux/amd64)"
( cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags='-s -w' -o "$BIN" ./test/harness/verifier )
ok "$(basename "$BIN") $(wc -c <"$BIN" | tr -d ' ') bytes"

has_cases_for() { # has_cases_for <runtime>
  [[ "$(jq --arg r "$1" '[.cases[]|select(.source_runtime==$r)]|length' "$TARGETS")" -gt 0 ]]
}

record() { # record <runtime> <resultfile>
  local rt="$1" f="$2"
  if [[ ! -s "$f" ]] || ! jq -e . "$f" >/dev/null 2>&1; then
    warn "$rt produced no parseable report"; FAILED=$((FAILED+1)); return
  fi
  # The verifier reports .status = "pass"|"fail" (verify/report.go); the old .passed key never existed, so every case printed FAIL and no failure was ever counted.
  local bad; bad="$(jq '[.results[]?|select(.status!="pass")]|length' "$f" 2>/dev/null || echo 1)"
  jq -r '.results[]? | "     \(if .status=="pass" then "PASS" else "FAIL" end)  \(.name)  \(.error_summary // "")"' "$f"
  if [[ "$bad" != "0" ]]; then FAILED=$((FAILED+bad)); fi
}

# ---------- kubernetes runtimes (EKS-IRSA, AKS workload identity) ----------
run_k8s() { # run_k8s <runtime> <pod-name> [extra pod labels/annotations json]
  local rt="$1" pod="$2" overlay="${3:-{\}}"
  need_bin kubectl "Needed to reach the cluster; point KUBECONFIG at it first."
  info "$rt: launching $pod in ns/$NS"

  kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  # The service account carries the federation wiring (IRSA role annotation /
  # AKS workload-identity labels); stage2 output supplies the values.
  kubectl -n "$NS" get sa "$SA" >/dev/null 2>&1 || kubectl -n "$NS" create sa "$SA" >/dev/null
  # Annotations must land AFTER the SA exists; the first run annotated a not-yet-created SA and every runtime lost its federation wiring.
  for kv in $(jq -r '(.sa_annotations // {}) | to_entries[] | "\(.key)=\(.value)"' <<<"$overlay"); do
    kubectl -n "$NS" annotate sa "$SA" "$kv" --overwrite >/dev/null
  done
  # cloud-auth re-mints the projected token via TokenRequest when the target wants a different audience than the one projected; that needs this RBAC.
  jq -n --arg ns "$NS" --arg sa "$SA" '[
    {apiVersion:"rbac.authorization.k8s.io/v1", kind:"Role", metadata:{name:"cloud-auth-token-request", namespace:$ns},
     rules:[{apiGroups:[""], resources:["serviceaccounts/token"], resourceNames:[$sa], verbs:["create"]}]},
    {apiVersion:"rbac.authorization.k8s.io/v1", kind:"RoleBinding", metadata:{name:"cloud-auth-token-request", namespace:$ns},
     roleRef:{apiGroup:"rbac.authorization.k8s.io", kind:"Role", name:"cloud-auth-token-request"},
     subjects:[{kind:"ServiceAccount", name:$sa, namespace:$ns}]}] | {apiVersion:"v1", kind:"List", items:.}' \
    | kubectl apply -f - >/dev/null

  jq -n --arg pod "$pod" --arg ns "$NS" --arg sa "$SA" --argjson o "$overlay" '
    {apiVersion:"v1", kind:"Pod",
     metadata:{name:$pod, namespace:$ns,
               labels:({"app":"cloud-auth-verifier"} + ($o.labels // {})),
               annotations:($o.annotations // {})},
     spec:{serviceAccountName:$sa, restartPolicy:"Never",
           containers:[{name:"v", image:"alpine:3", command:["sleep","900"]}]}}' \
    | kubectl apply -f - >/dev/null
  kubectl -n "$NS" wait --for=condition=Ready "pod/$pod" --timeout=180s >/dev/null \
    || { warn "$rt: pod never became ready"; kubectl -n "$NS" delete pod "$pod" --now >/dev/null 2>&1 || true; FAILED=$((FAILED+1)); return; }

  kubectl -n "$NS" cp "$BIN" "$pod:/tmp/verifier" >/dev/null
  kubectl -n "$NS" cp "$TARGETS" "$pod:/tmp/targets.json" >/dev/null

  local out="$STATE_DIR/results-$rt.json"
  kubectl -n "$NS" exec "$pod" -- /tmp/verifier --targets /tmp/targets.json >"$out" 2>"$STATE_DIR/results-$rt.log" || true
  kubectl -n "$NS" delete pod "$pod" --now >/dev/null 2>&1 || true
  record "$rt" "$out"
}

# ---------- EC2 via SSM ----------
run_ec2() {
  local rt=aws-ec2
  need_bin aws "AWS CLI is needed for SSM delivery."
  local iid; iid="$(jq -r '.ec2_instance_id.value // empty' "$STATE_DIR/aws-stage1.json" 2>/dev/null)"
  [[ -n "$iid" ]] || { warn "no ec2_instance_id in aws-stage1.json; skipping $rt"; return; }
  info "$rt: delivering to $iid over SSM"

  # SSM can't take a binary inline, so stage it through the harness bucket if one
  # exists; otherwise base64 it in chunks (fine for a ~10MB static binary).
  local b64; b64="$(base64 < "$BIN" | tr -d '\n')"
  local tgt; tgt="$(base64 < "$TARGETS" | tr -d '\n')"
  local cmd="set -e
echo '$b64' | base64 -d > /tmp/verifier && chmod +x /tmp/verifier
echo '$tgt' | base64 -d > /tmp/targets.json
/tmp/verifier --targets /tmp/targets.json"

  local id; id="$(aws ssm send-command --instance-ids "$iid" \
      --document-name AWS-RunShellScript \
      --parameters "commands=[$(jq -Rs . <<<"$cmd")]" \
      --query 'Command.CommandId' --output text)"
  aws ssm wait command-executed --command-id "$id" --instance-id "$iid" 2>/dev/null || true
  local out="$STATE_DIR/results-$rt.json"
  aws ssm get-command-invocation --command-id "$id" --instance-id "$iid" \
      --query StandardOutputContent --output text > "$out" 2>/dev/null || true
  record "$rt" "$out"
}

# ---------- Lambda: invoke, event = targets.json ----------
run_lambda() {
  local rt=aws-lambda
  need_bin aws "AWS CLI is needed to invoke the Lambda source."
  local fn region
  fn="$(jq -r '.lambda_function_name.value // empty' "$STATE_DIR/aws-lambda.json" 2>/dev/null)"
  region="$(jq -r '.region.value // empty' "$STATE_DIR/aws-lambda.json" 2>/dev/null)"
  [[ -n "$fn" ]] || { warn "no aws-lambda.json (set LAMBDA=1 on up.sh); skipping $rt"; return; }
  info "$rt: refreshing code and invoking $fn in $region"
  # up.sh deployed the zip; refresh so a rebuilt verifier is what runs.
  ( cd "$STATE_DIR" && cp "$BIN" bootstrap && rm -f verifier-lambda.zip && zip -q -j verifier-lambda.zip bootstrap )
  aws lambda update-function-code --region "$region" --function-name "$fn" \
      --zip-file "fileb://$STATE_DIR/verifier-lambda.zip" >/dev/null
  aws lambda wait function-updated --region "$region" --function-name "$fn"

  local out="$STATE_DIR/results-$rt.json"
  aws lambda invoke --region "$region" --function-name "$fn" \
      --cli-binary-format raw-in-base64-out --payload "fileb://$TARGETS" \
      --log-type Tail --query 'LogResult' --output text "$out" 2>"$STATE_DIR/results-$rt.log" \
      | base64 -d >> "$STATE_DIR/results-$rt.log" || true
  record "$rt" "$out"
}

# ---------- GCE via gcloud ----------
run_gce() {
  local rt=gcp-gce
  need_bin gcloud "gcloud is needed to reach the GCE source VM."
  local name zone
  name="$(jq -r '.gce_instance_name.value // empty' "$STATE_DIR/gcp-stage1.json" 2>/dev/null)"
  zone="$(jq -r '.zone.value // empty'              "$STATE_DIR/gcp-stage1.json" 2>/dev/null)"
  [[ -n "$name" && -n "$zone" ]] || { warn "no GCE instance in gcp-stage1.json; skipping $rt"; return; }
  info "$rt: delivering to $name ($zone)"

  gcloud compute scp "$BIN" "$name:/tmp/verifier" --zone "$zone" --quiet >/dev/null
  gcloud compute scp "$TARGETS" "$name:/tmp/targets.json" --zone "$zone" --quiet >/dev/null
  local out="$STATE_DIR/results-$rt.json"
  gcloud compute ssh "$name" --zone "$zone" --quiet \
      --command 'chmod +x /tmp/verifier && /tmp/verifier --targets /tmp/targets.json' \
      > "$out" 2>"$STATE_DIR/results-$rt.log" || true
  record "$rt" "$out"
}

for rt in "${ACTIVE[@]}"; do
  if ! has_cases_for "$rt"; then
    warn "no cases for $rt in targets.json, skipping"; continue
  fi
  case "$rt" in
    aws-eks-irsa)
      CTX="${EKS_CONTEXT:-}"
      role="$(jq -r '.role_arn_for_gcp_source.value // empty' "$STATE_DIR/aws-stage2.json" 2>/dev/null)"
      # IRSA: the annotation is what makes the webhook project a web-identity token; any role ARN triggers it.
      run_k8s "$rt" cloud-auth-verify-irsa "$(jq -n --arg r "$role" '{sa_annotations:{"eks.amazonaws.com/role-arn":$r}}')" ;;
    azure-aks-workload-identity)
      CTX="${AKS_CONTEXT:-}"
      cid="$(jq -r '.client_id_for_gcp_source.value // empty' "$STATE_DIR/azure-stage2.json" 2>/dev/null)"
      run_k8s "$rt" cloud-auth-verify-aks "$(jq -n --arg c "$cid" '{labels:{"azure.workload.identity/use":"true"}, sa_annotations:{"azure.workload.identity/client-id":$c}}')" ;;
    gcp-gke)
      CTX="${GKE_CONTEXT:-}"
      gsa="$(jq -r '.source_sa_email.value // empty' "$STATE_DIR/gcp-stage1.json" 2>/dev/null)"
      # GKE Workload Identity: this annotation is what makes the pod's metadata server mint tokens for the source SA.
      run_k8s "$rt" cloud-auth-verify-gke "$(jq -n --arg g "$gsa" '{sa_annotations:{"iam.gke.io/gcp-service-account":$g}}')" ;;
    aws-ec2) run_ec2 ;;
    aws-lambda) run_lambda ;;
    gcp-gce) run_gce ;;
    *) warn "unknown runtime '$rt', skipping" ;;
  esac
done

echo
if (( FAILED > 0 )); then
  die "$FAILED case(s) failed — see state/results-*.json and state/results-*.log"
fi
ok "all verified cases passed"
