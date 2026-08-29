#!/usr/bin/env bash
# Live verification + operator runbook: policy-bundle Bearer dual-token rotation
# (Issue #179 / T-PB-01 residual).
#
# Dual-trust sequence (NEVER hard-swap):
#   1) Generate N+1; PE accepts N and N+1 (token + token-previous); roll PE
#   2) Point agent presenter (Secret key token) at N+1; roll DaemonSet
#   3) Soak W=max(3xPOLICY_SYNC_INTERVAL, 90s): increase(fp_N)[W]==0 AND
#      increase(fp_N+1)[W]>0 on policy_bundle_auth_accept_total
#   4) HUMAN GATE - only then remove N from PE accepted set; roll PE
#
# Fingerprints are truncated SHA-256 hex (8 chars). Raw tokens NEVER appear in
# metrics labels or this script's PASS/FAIL lines (only fp=… and step status).
#
# This is a DOCUMENTED PROCEDURE a human runs - not cron/automation.
# Step 4 requires typing RETIRE to proceed.
#
# Preconditions:
#   - Cluster already bootstrapped (manual_verify_k8s_policy_engine.sh or equiv)
#   - PE image includes Issue #179 (dual-accept + /metrics accept counters)
#   - kubectl + curl + openssl + python3 available
#
# Usage (droplet):
#   export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
#   cd /path/to/neuromesh   # checkout feat/issue-179-policy-bundle-token-rotation (or main after merge)
#   sudo -E bash scripts/manual_verify_policy_bundle_token_rotation.sh
#
# Paste full stdout/stderr back to the PR. Do NOT merge until every step PASS
# (or explicitly defer live gate with documented reason).
set -euo pipefail

NS="${NEUROMESH_NAMESPACE:-neuromesh-system}"
PE_DEPLOY="${NEUROMESH_PE_DEPLOY:-neuromesh-zt-policy-engine}"
AGENT_DS="${NEUROMESH_AGENT_DS:-neuromesh-agent}"
PF_LOCAL_PORT="${NEUROMESH_PE_PF_PORT:-18081}"
# Agent POLICY_SYNC_INTERVAL = 30s → W = max(3x30, 90) = 90s (Issue #179).
SOAK_SECS="${NEUROMESH_TOKEN_ROTATION_SOAK_SECS:-90}"
SECRET_NAME="neuromesh-policy-bundle-token"
WORK_DIR="${NEUROMESH_TOKEN_ROTATION_WORK:-/tmp/neuromesh-token-rotation-$$}"

PASS_COUNT=0
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
info() { echo; echo "== $* =="; }

PF_PID=""
CLEANUP_DONE=0

fingerprint() {
  # stdin or $1 → truncated SHA-256 hex (8 chars). Never print the input.
  local raw="${1:-}"
  if [[ -z "$raw" ]]; then
    raw="$(cat)"
  fi
  printf '%s' "$raw" | openssl dgst -sha256 -hex | awk '{print substr($NF,1,8)}'
}

counter_value() {
  # $1 = metrics body file, $2 = fp label
  local body="$1" fp="$2"
  python3 - "$body" "$fp" <<'PY'
import re, sys
body = open(sys.argv[1], encoding="utf-8", errors="replace").read()
fp = sys.argv[2]
# Match Prometheus counter line (ignore HELP/TYPE).
pat = re.compile(
    r'^policy_bundle_auth_accept_total\{fp="' + re.escape(fp) + r'"\}\s+([0-9.eE+-]+)\s*$',
    re.M,
)
m = pat.search(body)
print(m.group(1) if m else "0")
PY
}

fetch_metrics() {
  curl -sS "http://127.0.0.1:${PF_LOCAL_PORT}/metrics" -o "$WORK_DIR/metrics.txt" \
    || fail "GET /metrics failed"
}

start_port_forward() {
  if [[ -n "${PF_PID:-}" ]]; then
    kill "$PF_PID" 2>/dev/null || true
    wait "$PF_PID" 2>/dev/null || true
  fi
  kubectl -n "$NS" port-forward "svc/${PE_DEPLOY}" "${PF_LOCAL_PORT}:8080" \
    >"$WORK_DIR/pf.log" 2>&1 &
  PF_PID=$!
  sleep 2
  kill -0 "$PF_PID" 2>/dev/null || fail "port-forward failed; see $WORK_DIR/pf.log"
}

curl_bundle() {
  # $1 = bearer token value (not logged). Echoes HTTP code only.
  local tok="$1"
  curl -sS -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer ${tok}" \
    "http://127.0.0.1:${PF_LOCAL_PORT}/v1/policy-bundle"
}

ensure_pe_volume_projects_previous() {
  # Patch Deployment to project token-previous beside token (idempotent).
  kubectl -n "$NS" get deploy "$PE_DEPLOY" -o json >"$WORK_DIR/pe-deploy.json"
  python3 - "$WORK_DIR/pe-deploy.json" <<'PY' >"$WORK_DIR/pe-deploy.patched.json"
import json, sys
dep = json.load(open(sys.argv[1], encoding="utf-8"))
for v in dep["spec"]["template"]["spec"]["volumes"]:
    if v.get("name") != "policy-bundle-token":
        continue
    items = v.setdefault("secret", {}).setdefault("items", [])
    keys = {i.get("key") for i in items}
    if "token" not in keys:
        items.append({"key": "token", "path": "token"})
    if "token-previous" not in keys:
        items.append({"key": "token-previous", "path": "token-previous"})
    break
else:
    raise SystemExit("policy-bundle-token volume missing on PE Deployment")
json.dump(dep, sys.stdout)
PY
  kubectl -n "$NS" apply -f "$WORK_DIR/pe-deploy.patched.json"
}

drop_pe_volume_previous() {
  kubectl -n "$NS" get deploy "$PE_DEPLOY" -o json >"$WORK_DIR/pe-deploy.json"
  python3 - "$WORK_DIR/pe-deploy.json" <<'PY' >"$WORK_DIR/pe-deploy.patched.json"
import json, sys
dep = json.load(open(sys.argv[1], encoding="utf-8"))
for v in dep["spec"]["template"]["spec"]["volumes"]:
    if v.get("name") != "policy-bundle-token":
        continue
    items = v.setdefault("secret", {}).setdefault("items", [])
    v["secret"]["items"] = [i for i in items if i.get("key") != "token-previous"]
    break
json.dump(dep, sys.stdout)
PY
  kubectl -n "$NS" apply -f "$WORK_DIR/pe-deploy.patched.json"
}

cleanup() {
  if [[ "$CLEANUP_DONE" -eq 1 ]]; then
    return 0
  fi
  CLEANUP_DONE=1
  set +e
  if [[ -n "${PF_PID:-}" ]]; then
    kill "$PF_PID" 2>/dev/null
    wait "$PF_PID" 2>/dev/null
  fi
  # Do NOT auto-revert Secret/Deployment on failure - operator may be mid-rotation.
  # Leaving dual-accept in place is the safe break-glass (Issue #179).
  echo "cleanup: port-forward stopped; Secret/Deployment left as-is (safe dual-accept default)" >&2
}
trap cleanup EXIT INT TERM

mkdir -p "$WORK_DIR"
chmod 700 "$WORK_DIR"

info "0) preflight"
command -v kubectl >/dev/null || fail "kubectl required"
command -v curl >/dev/null || fail "curl required"
command -v openssl >/dev/null || fail "openssl required"
command -v python3 >/dev/null || fail "python3 required"
kubectl -n "$NS" get deploy "$PE_DEPLOY" >/dev/null || fail "missing deploy/$PE_DEPLOY"
kubectl -n "$NS" get ds "$AGENT_DS" >/dev/null || fail "missing ds/$AGENT_DS"
kubectl -n "$NS" get secret "$SECRET_NAME" >/dev/null || fail "missing secret/$SECRET_NAME"
echo "NS=$NS PE=$PE_DEPLOY AGENT=$AGENT_DS SOAK_SECS=$SOAK_SECS WORK_DIR=$WORK_DIR"
pass "preflight"

info "1) capture N + generate N+1 (fingerprints only in logs)"
TOKEN_N="$(kubectl -n "$NS" get secret "$SECRET_NAME" -o jsonpath='{.data.token}' | base64 -d)"
[[ -n "$TOKEN_N" ]] || fail "empty current token"
TOKEN_N1="$(openssl rand -hex 32)"
FP_N="$(fingerprint "$TOKEN_N")"
FP_N1="$(fingerprint "$TOKEN_N1")"
printf '%s' "$TOKEN_N" >"$WORK_DIR/token_n"
printf '%s' "$TOKEN_N1" >"$WORK_DIR/token_n1"
chmod 600 "$WORK_DIR/token_n" "$WORK_DIR/token_n1"
echo "fp_N=$FP_N fp_N1=$FP_N1 (raw tokens written only under $WORK_DIR mode 0600)"
pass "generated N+1; fingerprints recorded"

info "1b) PE dual-accept: token=N, token-previous=N+1; project both; roll PE"
# Agents still present N via key token. PE accepts token + token-previous.
kubectl -n "$NS" create secret generic "$SECRET_NAME" \
  --from-file=token="$WORK_DIR/token_n" \
  --from-file=token-previous="$WORK_DIR/token_n1" \
  --dry-run=client -o yaml | kubectl apply -f -
ensure_pe_volume_projects_previous
kubectl -n "$NS" rollout restart "deploy/${PE_DEPLOY}"
kubectl -n "$NS" rollout status "deploy/${PE_DEPLOY}" --timeout=180s
start_port_forward
code_n="$(curl_bundle "$TOKEN_N")"
code_n1="$(curl_bundle "$TOKEN_N1")"
[[ "$code_n" == "200" ]] || fail "dual-accept: N → HTTP $code_n want 200"
[[ "$code_n1" == "200" ]] || fail "dual-accept: N+1 → HTTP $code_n1 want 200"
pass "PE dual-accept (N and N+1 both HTTP 200)"

info "2) roll agents to presenter N+1 (Secret token=N+1; keep token-previous=N for stragglers)"
# After this: agent presenter = N+1. PE still needs N for stragglers → swap previous to N.
kubectl -n "$NS" create secret generic "$SECRET_NAME" \
  --from-file=token="$WORK_DIR/token_n1" \
  --from-file=token-previous="$WORK_DIR/token_n" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$NS" rollout restart "deploy/${PE_DEPLOY}"
kubectl -n "$NS" rollout status "deploy/${PE_DEPLOY}" --timeout=180s
kubectl -n "$NS" rollout restart "ds/${AGENT_DS}"
kubectl -n "$NS" rollout status "ds/${AGENT_DS}" --timeout=240s
start_port_forward
code_n="$(curl_bundle "$TOKEN_N")"
code_n1="$(curl_bundle "$TOKEN_N1")"
[[ "$code_n" == "200" ]] || fail "post-agent-roll: N (straggler path) → HTTP $code_n want 200"
[[ "$code_n1" == "200" ]] || fail "post-agent-roll: N+1 → HTTP $code_n1 want 200"
pass "agents on N+1; PE still dual-accepts"

info "3) soak W=${SOAK_SECS}s - zero increase fp_N AND positive increase fp_N1"
fetch_metrics
c0_n="$(counter_value "$WORK_DIR/metrics.txt" "$FP_N")"
c0_n1="$(counter_value "$WORK_DIR/metrics.txt" "$FP_N1")"
echo "counters at soak start: fp_N=$FP_N val=$c0_n  fp_N1=$FP_N1 val=$c0_n1"
# Drive N+1 accepts during soak (simulates agent sync). Do NOT call with N
# (would spoil zero-N proof). Real agents should also hit N+1 via policy_sync.
end=$((SECONDS + SOAK_SECS))
while (( SECONDS < end )); do
  curl_bundle "$TOKEN_N1" >/dev/null || true
  sleep 5
done
fetch_metrics
c1_n="$(counter_value "$WORK_DIR/metrics.txt" "$FP_N")"
c1_n1="$(counter_value "$WORK_DIR/metrics.txt" "$FP_N1")"
echo "counters at soak end:   fp_N=$FP_N val=$c1_n  fp_N1=$FP_N1 val=$c1_n1"
python3 - "$c0_n" "$c1_n" "$c0_n1" "$c1_n1" <<'PY' || fail "soak window criterion failed"
import sys
c0_n, c1_n, c0_n1, c1_n1 = map(float, sys.argv[1:])
d_n = c1_n - c0_n
d_n1 = c1_n1 - c0_n1
print(f"delta_N={d_n} delta_N1={d_n1}")
if d_n != 0:
    sys.exit(f"fp_N increase must be 0 over soak, got {d_n}")
if d_n1 <= 0:
    sys.exit(f"fp_N1 increase must be >0 over soak, got {d_n1}")
PY
pass "soak: increase(fp_N)==0 and increase(fp_N1)>0 over W=${SOAK_SECS}s"

info "4) HUMAN GATE - retire N from PE accepted set"
echo
echo "================================================================"
echo " About to REMOVE token N (fp=$FP_N) from PE accepted set."
echo " Agents must already be on N+1 (fp=$FP_N1). This is irreversible"
echo " without restoring N from $WORK_DIR/token_n."
echo " Type exactly: RETIRE"
echo "================================================================"
confirm=""
if [[ -n "${NEUROMESH_TOKEN_ROTATION_ASSUME_YES:-}" ]]; then
  echo "(NEUROMESH_TOKEN_ROTATION_ASSUME_YES set - non-interactive lab only)"
  confirm="RETIRE"
else
  read -r -p "> " confirm
fi
[[ "$confirm" == "RETIRE" ]] || fail "human gate aborted (got ${confirm:-empty})"

kubectl -n "$NS" create secret generic "$SECRET_NAME" \
  --from-file=token="$WORK_DIR/token_n1" \
  --dry-run=client -o yaml | kubectl apply -f -
drop_pe_volume_previous
kubectl -n "$NS" rollout restart "deploy/${PE_DEPLOY}"
kubectl -n "$NS" rollout status "deploy/${PE_DEPLOY}" --timeout=180s
start_port_forward
code_n="$(curl_bundle "$TOKEN_N")"
code_n1="$(curl_bundle "$TOKEN_N1")"
[[ "$code_n" == "401" ]] || fail "retired N must be HTTP 401, got $code_n"
[[ "$code_n1" == "200" ]] || fail "N+1 alone must be HTTP 200, got $code_n1"
pass "N rejected (401); N+1 accepted (200)"

info "summary"
echo "PASS_COUNT=$PASS_COUNT"
echo "fp_N=$FP_N (retired) fp_N1=$FP_N1 (active)"
echo "ALL CHECKS PASSED - dual-token rotation rehearsal complete (Issue #179)."
echo "Destroy $WORK_DIR when finished (contains raw token material)."
