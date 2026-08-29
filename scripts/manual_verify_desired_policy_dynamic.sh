#!/usr/bin/env bash
# Live verification: Issue #137 dynamic DesiredPolicy management — FIRST-EVER live gate.
#
# Proves on a running k3s/lab cluster (PE + agent already bootstrapped via
# scripts/manual_verify_k8s_policy_engine.sh or equivalent):
#   1) ENABLE gate — watch starts, initial reconcile against bootstrap-equivalent CM
#   2) VALID CHANGE — bundle + Rego planes move together (prefix + SPIFFE ID)
#      ★ Also the RBAC regression gate for PE ConfigMap least privilege
#        (Role neuromesh-zt-policy-engine-desired-policy: get/watch on
#        resourceNames only). If get/watch is broken or over-narrowed, this
#        scenario fails when PE cannot read/watch the ConfigMap.
#   3) DOWNSTREAM — agent policy_sync → LSM rejects new dynamic deny prefix
#   4) REJECTION — invalid CM retains last-known-good (step-2 state)
#   5) SAFETY RAIL — floor removal override vs regression without flag
#   6) RESTART SELF-HEAL — PE pod restart re-reads live ConfigMap
#   7) CLEANUP — disable gate, restore bootstrap CM, no errors
#
# Usage (droplet — root/sudo, kubectl configured):
#   cd /path/to/neuromesh
#   git checkout <branch-with-this-script>   # e.g. main after #171
#   export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
#   export NEUROMESH_SPIFFE_CA_KEY=/tmp/neuromesh-k8s-keys/spiffe-lab-ca.key
#   sudo -E bash scripts/manual_verify_desired_policy_dynamic.sh
#
# SAFETY (read before live run):
#   - EXIT/INT/TERM trap ALWAYS restores floor-protected bootstrap ConfigMap on any
#     failure or interruption (including mid-scenario-5), disables the gate, restarts
#     PE + agent so LSM maps re-sync — not happy-path-only.
#   - Scenario 3 polls agent logs for a NEW apply line with the step-2 bundle version
#     (since-time bounded) — never a blind fixed sleep.
#
# Paste full stdout/stderr back to the PR. Do NOT merge until every scenario PASS.
set -euo pipefail

NS="${NEUROMESH_NAMESPACE:-neuromesh-system}"
KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
export KUBECONFIG
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PF_LOCAL_PORT="${NEUROMESH_PE_PF_PORT:-18082}"
CM_NAME="${NEUROMESH_DESIRED_POLICY_CONFIGMAP:-neuromesh-desired-policy}"
PE_DEPLOY="${NEUROMESH_PE_DEPLOY:-neuromesh-zt-policy-engine}"
KEY_DIR="${NEUROMESH_K8S_KEY_DIR:-/tmp/neuromesh-k8s-keys}"
SPIFFE_CA_KEY="${NEUROMESH_SPIFFE_CA_KEY:-${KEY_DIR}/spiffe-lab-ca.key}"
WORK_DIR="${NEUROMESH_DESIRED_POLICY_TEST_ROOT:-/opt/neuromesh-test/desired-policy-live}"
DYNAMIC_PREFIX="/opt/neuromesh/dynamic-test/"
DYNAMIC_SPIFFE="spiffe://neuromesh.security/ns/default/sa/dynamic-test-workload"
EVAL_TMP_PATH="/tmp/neuromesh-dynamic-eval-payload.bin"
POLICY_SYNC_WAIT_SECS="${NEUROMESH_POLICY_SYNC_WAIT_SECS:-120}"
PE_LOG_WAIT_SECS="${NEUROMESH_PE_LOG_WAIT_SECS:-90}"

PASS_COUNT=0
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
info() { echo; echo "== $* =="; }

PF_PID=""
GATE_ENABLED=0
BOOTSTRAP_JSON_FILE=""
RESTORE_CM=0
CLEANUP_DONE=0
FLOOR_UNSAFE=0

# Restore floor-protected bootstrap CM + recycle PE/agent so kernel maps catch up.
# CM-only restore is NOT enough: agent BPF deny maps lag until the next policy_sync.
#
# Must never abort mid-restore under set -e (same class as stop_agent in
# manual_measure_correlator_overhead.sh: a function returning non-zero on a
# benign path silently killed the caller before PHASE 2).
emergency_restore_floor_protection() {
  set +e
  local step_ec=0

  if [[ ! -f "${BOOTSTRAP_JSON_FILE:-}" ]]; then
    echo "EMERGENCY: bootstrap JSON file missing — cannot restore floors" >&2
    return 1
  fi
  echo "EMERGENCY: restoring floor-protected bootstrap ConfigMap (/tmp/, /dev/shm/, /var/tmp/)..." >&2
  if ! apply_policy_json_file "$BOOTSTRAP_JSON_FILE"; then
    echo "EMERGENCY: WARN — bootstrap ConfigMap apply failed (continuing with PE/agent recycle)" >&2
    step_ec=1
  fi
  if [[ "$GATE_ENABLED" == "1" ]]; then
    if ! kubectl -n "$NS" set env "deploy/${PE_DEPLOY}" \
      NEUROMESH_DESIRED_POLICY_ENABLE- \
      NEUROMESH_DESIRED_POLICY_CONFIGMAP-; then
      echo "EMERGENCY: WARN — unset desired-policy env on PE failed" >&2
      step_ec=1
    fi
    if ! kubectl -n "$NS" rollout restart "deploy/${PE_DEPLOY}"; then
      echo "EMERGENCY: WARN — PE rollout restart failed" >&2
      step_ec=1
    fi
    if ! kubectl -n "$NS" rollout status "deploy/${PE_DEPLOY}" --timeout=120s; then
      echo "EMERGENCY: WARN — PE rollout status failed/timed out" >&2
      step_ec=1
    fi
    GATE_ENABLED=0
  fi
  echo "EMERGENCY: restarting agent DaemonSet to force policy_sync + LSM map refresh..." >&2
  if ! kubectl -n "$NS" rollout restart ds/neuromesh-agent; then
    echo "EMERGENCY: WARN — agent rollout restart failed" >&2
    step_ec=1
  fi
  if ! kubectl -n "$NS" rollout status ds/neuromesh-agent --timeout=180s; then
    echo "EMERGENCY: WARN — agent rollout status failed/timed out" >&2
    step_ec=1
  fi
  FLOOR_UNSAFE=0
  return "$step_ec"
}

cleanup() {
  # Entire cleanup path runs with errexit OFF so no single kubectl/grep/kill
  # can silently abort mid-restore (stop_agent / set -e footgun class).
  set +e
  local ec=$?
  if [[ "$CLEANUP_DONE" == "1" ]]; then
    return 0
  fi
  if [[ -n "${PF_PID:-}" ]]; then
    kill "$PF_PID" 2>/dev/null
    wait "$PF_PID" 2>/dev/null
    PF_PID=""
  fi
  if [[ "$RESTORE_CM" == "1" || "$FLOOR_UNSAFE" == "1" ]]; then
    info "cleanup trap: emergency floor restoration (exit=${ec}, floor_unsafe=${FLOOR_UNSAFE})"
    emergency_restore_floor_protection
    local restore_ec=$?
    if [[ "$restore_ec" -ne 0 ]]; then
      echo "EMERGENCY: floor restoration completed with errors (exit=${restore_ec})" >&2
    fi
  fi
  rm -rf "${WORK_DIR}/payload" 2>/dev/null
  rm -rf /opt/neuromesh/dynamic-test 2>/dev/null
  if [[ "$ec" -ne 0 ]]; then
    echo "FAIL: script exited with status $ec (floor-protected bootstrap CM restore attempted)" >&2
  fi
  return 0
}
trap cleanup EXIT INT TERM

apply_policy_json_file() {
  local file="$1"
  kubectl -n "$NS" create configmap "$CM_NAME" \
    --from-file="policy.json=${file}" \
    --dry-run=client -o yaml | kubectl apply -f -
}

apply_policy_json_inline() {
  local file
  file="$(mktemp)"
  printf '%s\n' "$1" >"$file"
  apply_policy_json_file "$file"
  rm -f "$file"
}

pe_logs_since() {
  local since="${1:-90s}"
  kubectl -n "$NS" logs "deploy/${PE_DEPLOY}" --since="$since" 2>/dev/null || true
}

wait_pe_log() {
  local pattern="$1"
  local timeout="${2:-$PE_LOG_WAIT_SECS}"
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if pe_logs_since 120s | grep -Eq "$pattern"; then
      return 0
    fi
    sleep 2
  done
  echo "---- PE logs (last 120s) ----" >&2
  pe_logs_since 120s >&2 || true
  return 1
}

agent_pod() {
  kubectl -n "$NS" get pods -l app.kubernetes.io/name=neuromesh-agent \
    --field-selector=status.phase=Running \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true
}

wait_agent_log() {
  local pattern="$1"
  local timeout="${2:-$POLICY_SYNC_WAIT_SECS}"
  local pod deadline
  pod="$(agent_pod)"
  [[ -n "$pod" ]] || return 1
  deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if kubectl -n "$NS" logs "$pod" --since=5m 2>/dev/null | grep -Eq "$pattern"; then
      return 0
    fi
    sleep 3
  done
  echo "---- agent logs (tail) ----" >&2
  kubectl -n "$NS" logs "$pod" --tail=250 2>/dev/null >&2 || true
  return 1
}

# Poll for a NEW policy_sync apply after since_ts that carries the expected bundle version.
# Avoids false positives from pre-change sync lines (not a fixed sleep).
wait_agent_applied_bundle_since() {
  local since_ts="$1"
  local want_version="$2"
  local timeout="${3:-$POLICY_SYNC_WAIT_SECS}"
  local pod deadline logs
  pod="$(agent_pod)"
  [[ -n "$pod" ]] || return 1
  [[ -n "$want_version" ]] || return 1
  echo "waiting for agent apply of bundle version ${want_version} (logs since ${since_ts})..."
  deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    logs="$(kubectl -n "$NS" logs "$pod" --since-time="$since_ts" 2>/dev/null || true)"
    if echo "$logs" | grep -F "applied path-prefix deny list + identity validity" \
      | grep -F "$want_version"; then
      echo "agent confirmed apply of version ${want_version}"
      return 0
    fi
    sleep 3
  done
  echo "---- agent logs since ${since_ts} ----" >&2
  kubectl -n "$NS" logs "$pod" --since-time="$since_ts" 2>/dev/null >&2 || true
  return 1
}

start_port_forward() {
  if [[ -n "${PF_PID:-}" ]]; then
    kill "$PF_PID" 2>/dev/null || true
    wait "$PF_PID" 2>/dev/null || true
  fi
  kubectl -n "$NS" port-forward "svc/${PE_DEPLOY}" "${PF_LOCAL_PORT}:8080" \
    >/tmp/nm-desired-policy-pf.log 2>&1 &
  PF_PID=$!
  sleep 2
  kill -0 "$PF_PID" 2>/dev/null || fail "port-forward failed; see /tmp/nm-desired-policy-pf.log"
}

bundle_token() {
  kubectl -n "$NS" get secret neuromesh-policy-bundle-token \
    -o jsonpath='{.data.token}' | base64 -d
}

fetch_policy_bundle() {
  local token hdrs body http
  token="$(bundle_token)"
  [[ -n "$token" ]] || fail "empty policy-bundle token"
  hdrs="$(mktemp)"
  body="$(mktemp)"
  http="$(curl -sS -D "$hdrs" -o "$body" -w '%{http_code}' \
    -H "Authorization: Bearer ${token}" \
    "http://127.0.0.1:${PF_LOCAL_PORT}/v1/policy-bundle")"
  [[ "$http" == "200" ]] || fail "GET /v1/policy-bundle HTTP $http"
  grep -qi '^X-Neuromesh-Policy-Bundle-Signature:' "$hdrs" \
    || fail "missing X-Neuromesh-Policy-Bundle-Signature header"
  cp "$body" "${WORK_DIR}/last_bundle.body"
  cp "$hdrs" "${WORK_DIR}/last_bundle.headers"
  rm -f "$hdrs" "$body"
}

verify_bundle_signature_and_temporal() {
  python3 - "$WORK_DIR" <<'PY'
import base64, json, pathlib, sys
work = pathlib.Path(sys.argv[1])
body = (work / "last_bundle.body").read_bytes()
pub = (work / "bundle.pub").read_bytes()
sig_b64 = None
for line in (work / "last_bundle.headers").read_text().splitlines():
    if line.lower().startswith("x-neuromesh-policy-bundle-signature:"):
        sig_b64 = line.split(":", 1)[1].strip()
        break
if not sig_b64:
    raise SystemExit("signature header missing")
from cryptography.hazmat.primitives.serialization import load_pem_public_key
pubkey = load_pem_public_key(pub)
pubkey.verify(base64.b64decode(sig_b64), body)
doc = json.loads(body)
assert doc.get("schema_version") == 3, doc
assert doc.get("not_before") and doc.get("not_after"), doc
print("bundle Ed25519 signature + schema-3 temporal OK")
PY
}

bundle_has_prefix() {
  local prefix="$1"
  python3 - "$prefix" "${WORK_DIR}/last_bundle.body" <<'PY'
import json, pathlib, sys
prefix, body_path = sys.argv[1], sys.argv[2]
doc = json.loads(pathlib.Path(body_path).read_text())
prefixes = doc.get("deny_path_prefixes") or []
sys.exit(0 if prefix in prefixes else 1)
PY
}

bundle_has_spiffe() {
  local spiffe="$1"
  python3 - "$spiffe" "${WORK_DIR}/last_bundle.body" <<'PY'
import json, pathlib, sys
spiffe, body_path = sys.argv[1], sys.argv[2]
doc = json.loads(pathlib.Path(body_path).read_text())
ids = (doc.get("identity_allow_exceptions") or {}).get("spiffe_ids") or []
sys.exit(0 if spiffe in ids else 1)
PY
}

bundle_prefix_count() {
  python3 - "${WORK_DIR}/last_bundle.body" <<'PY'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
print(len(doc.get("deny_path_prefixes") or []))
PY
}

bundle_version() {
  python3 - "${WORK_DIR}/last_bundle.body" <<'PY'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
print(doc.get("version") or "")
PY
}

issue_spiffe_leaf_pem() {
  local spiffe_id="$1"
  local out_pem="$2"
  local bundle_pem="${WORK_DIR}/spiffe_bundle.pem"
  kubectl -n "$NS" get secret neuromesh-spiffe-trust-bundle \
    -o jsonpath='{.data.bundle\.pem}' | base64 -d >"$bundle_pem"
  [[ -s "$bundle_pem" ]] || fail "neuromesh-spiffe-trust-bundle Secret missing"
  python3 - "$SPIFFE_CA_KEY" "$bundle_pem" "$spiffe_id" "$out_pem" <<'PY'
import datetime, pathlib, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

ca_key_path = pathlib.Path(sys.argv[1])
bundle_pem_path = pathlib.Path(sys.argv[2])
spiffe_id = sys.argv[3]
out_path = pathlib.Path(sys.argv[4])

ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
ca_cert = x509.load_pem_x509_certificate(bundle_pem_path.read_bytes())
now = datetime.datetime.now(datetime.timezone.utc)

if isinstance(ca_key, ec.EllipticCurvePrivateKey):
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    sign_hash = hashes.SHA256()
elif isinstance(ca_key, rsa.RSAPrivateKey):
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sign_hash = hashes.SHA256()
else:
    raise SystemExit("unsupported lab CA key type (need RSA or EC P-256)")

leaf = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")]))
    .issuer_name(ca_cert.subject)
    .public_key(leaf_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(minutes=5))
    .not_valid_after(now + datetime.timedelta(hours=1))
    .add_extension(
        x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]),
        critical=False,
    )
    .add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=False,
            crl_sign=False,
            content_commitment=False,
            data_encipherment=False,
            key_encipherment=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    .sign(ca_key, sign_hash)
)
out_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
print("issued SVID PEM for", spiffe_id)
PY
}

post_evaluate() {
  local binary_path="$1"
  local cert_pem_file="$2"
  local out_file="${WORK_DIR}/last_evaluate.json"
  python3 - "$binary_path" "$cert_pem_file" "$PF_LOCAL_PORT" "$out_file" <<'PY'
import json, pathlib, sys, urllib.request
binary_path, cert_path, port, out_path = sys.argv[1:5]
cert_pem = pathlib.Path(cert_path).read_text()
body = json.dumps({"binary_path": binary_path, "certificate_pem": cert_pem}).encode()
req = urllib.request.Request(
    f"http://127.0.0.1:{port}/v1/evaluate",
    data=body,
    headers={"Content-Type": "application/json"},
    method="POST",
)
try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read())
        pathlib.Path(out_path).write_text(json.dumps(data))
        print(json.dumps(data))
except urllib.error.HTTPError as e:
    err = e.read().decode()
    pathlib.Path(out_path).write_text(json.dumps({"http_error": e.code, "body": err}))
    print(json.dumps({"http_error": e.code, "body": err}))
    sys.exit(0)
PY
}

evaluate_allowed() {
  python3 - "${WORK_DIR}/last_evaluate.json" <<'PY'
import json, pathlib, sys
data = json.loads(pathlib.Path(sys.argv[1]).read_text())
if "http_error" in data:
    print("HTTP", data["http_error"], data.get("body", ""))
    sys.exit(1)
sys.exit(0 if data.get("allowed") else 1)
PY
}

evaluate_denied() {
  python3 - "${WORK_DIR}/last_evaluate.json" <<'PY'
import json, pathlib, sys
data = json.loads(pathlib.Path(sys.argv[1]).read_text())
if "http_error" in data:
    sys.exit(0 if data["http_error"] in (401, 403) else 1)
sys.exit(0 if not data.get("allowed") else 1)
PY
}

enable_desired_policy_gate() {
  kubectl -n "$NS" set env "deploy/${PE_DEPLOY}" \
    NEUROMESH_DESIRED_POLICY_ENABLE=true \
    "NEUROMESH_DESIRED_POLICY_CONFIGMAP=${CM_NAME}"
  kubectl -n "$NS" rollout restart "deploy/${PE_DEPLOY}"
  kubectl -n "$NS" rollout status "deploy/${PE_DEPLOY}" --timeout=180s
  GATE_ENABLED=1
}

disable_desired_policy_gate() {
  kubectl -n "$NS" set env "deploy/${PE_DEPLOY}" \
    NEUROMESH_DESIRED_POLICY_ENABLE- \
    NEUROMESH_DESIRED_POLICY_CONFIGMAP-
  kubectl -n "$NS" rollout restart "deploy/${PE_DEPLOY}"
  kubectl -n "$NS" rollout status "deploy/${PE_DEPLOY}" --timeout=180s
  GATE_ENABLED=0
}

write_lsm_payload() {
  local path="$1"
  mkdir -p "$(dirname "$path")"
  printf '#!/bin/sh\necho neuromesh-desired-policy-live-ok\n' >"$path"
  chmod +x "$path"
}

expect_lsm_deny() {
  local label="$1"
  local payload="$2"
  local rc=0
  set +e
  "$payload"
  rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    fail "${label}: expected LSM DENY (non-zero exit) but payload exited 0"
  fi
  pass "${label} (exit=${rc})"
}

expect_lsm_allow() {
  local label="$1"
  local payload="$2"
  local out rc=0
  set +e
  out="$("$payload" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    fail "${label}: expected LSM ALLOW but exit=${rc} out=${out}"
  fi
  echo "$out" | grep -q 'neuromesh-desired-policy-live-ok' \
    || fail "${label}: payload ran but missing ok marker"
  pass "${label}"
}

# --- bootstrap policy (matches deploy/kubernetes/neuromesh-desired-policy.yaml) ---
read -r -d '' BOOTSTRAP_JSON <<'JSON' || true
{
  "deny_path_prefixes": ["/tmp/", "/dev/shm/", "/var/tmp/"],
  "identity_allow_exceptions": {
    "scope_path_prefix": "/tmp/",
    "spiffe_ids": [
      "spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor",
      "spiffe://neuromesh.security/ns/default/sa/zt-policy-engine",
      "spiffe://neuromesh.security/ns/default/sa/ai-threat-detector"
    ]
  }
}
JSON

read -r -d '' STEP2_JSON <<JSON || true
{
  "deny_path_prefixes": [
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
    "${DYNAMIC_PREFIX}"
  ],
  "identity_allow_exceptions": {
    "scope_path_prefix": "/tmp/",
    "spiffe_ids": [
      "spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor",
      "spiffe://neuromesh.security/ns/default/sa/zt-policy-engine",
      "spiffe://neuromesh.security/ns/default/sa/ai-threat-detector",
      "${DYNAMIC_SPIFFE}"
    ]
  }
}
JSON

info "0) preflight"
command -v kubectl >/dev/null || fail "kubectl required"
command -v curl >/dev/null || fail "curl required"
command -v python3 >/dev/null || fail "python3 required"
python3 -c "import cryptography" >/dev/null 2>&1 || fail "python3 cryptography package required"
command -v jq >/dev/null || echo "NOTE: jq not found — using python3 for JSON checks"
test -d "$ROOT/deploy/kubernetes" || fail "repo root missing deploy/kubernetes (ROOT=$ROOT)"
test "$(id -u)" -eq 0 || fail "must run as root (LSM exec proof on node)"
mount | grep -Eq 'type bpf|bpffs' || fail "bpffs not mounted — agent LSM not active?"
kubectl get ns "$NS" >/dev/null || fail "namespace $NS missing"
kubectl -n "$NS" get deploy "$PE_DEPLOY" >/dev/null || fail "Deployment $PE_DEPLOY missing — run manual_verify_k8s_policy_engine.sh first"
kubectl -n "$NS" get ds neuromesh-agent >/dev/null || fail "DaemonSet neuromesh-agent missing"
[[ -s "$SPIFFE_CA_KEY" ]] || fail "SPIFFE lab CA key missing at $SPIFFE_CA_KEY (export NEUROMESH_SPIFFE_CA_KEY=... from k8s bootstrap)"
mkdir -p "$WORK_DIR"
kubectl -n "$NS" get secret neuromesh-policy-bundle-pubkey \
  -o jsonpath='{.data.bundle\.pub}' | base64 -d >"${WORK_DIR}/bundle.pub"
[[ -s "${WORK_DIR}/bundle.pub" ]] || fail "neuromesh-policy-bundle-pubkey Secret missing"
kubectl apply -f "$ROOT/deploy/kubernetes/neuromesh-desired-policy.yaml" >/dev/null
pass "preflight OK (namespace, PE, agent, RBAC+CM, bundle pubkey, SPIFFE CA key)"

# Save live bootstrap for idempotent restore (may differ slightly from template).
BOOTSTRAP_JSON_FILE="${WORK_DIR}/bootstrap_saved.json"
if kubectl -n "$NS" get configmap "$CM_NAME" >/dev/null 2>&1; then
  kubectl -n "$NS" get configmap "$CM_NAME" -o jsonpath='{.data.policy\.json}' >"$BOOTSTRAP_JSON_FILE"
else
  printf '%s\n' "$BOOTSTRAP_JSON" >"$BOOTSTRAP_JSON_FILE"
fi
RESTORE_CM=1
apply_policy_json_file "$BOOTSTRAP_JSON_FILE"
pass "bootstrap ConfigMap applied (saved for restore)"

AGENT_POD="$(agent_pod)"
[[ -n "$AGENT_POD" ]] || fail "no Running neuromesh-agent pod"
echo "agent_pod=$AGENT_POD"

# ---------------------------------------------------------------------------
info "1) ENABLE — start DesiredPolicy watch + initial reconcile"
# Ensure gate is off before we enable (idempotent re-run).
kubectl -n "$NS" set env "deploy/${PE_DEPLOY}" \
  NEUROMESH_DESIRED_POLICY_ENABLE- \
  NEUROMESH_DESIRED_POLICY_CONFIGMAP- 2>/dev/null || true
kubectl -n "$NS" rollout restart "deploy/${PE_DEPLOY}" >/dev/null 2>&1 || true
kubectl -n "$NS" rollout status "deploy/${PE_DEPLOY}" --timeout=180s >/dev/null 2>&1 || true
sleep 3

enable_desired_policy_gate
wait_pe_log 'desired_policy_watch starting configmap=.*/'"${CM_NAME}" \
  || fail "PE did not log desired_policy_watch starting"
pass "1a: desired_policy_watch starting logged"

wait_pe_log 'desired_policy_accepted' \
  || fail "PE did not log desired_policy_accepted on initial reconcile"
pass "1b: desired_policy_accepted on initial reconcile"

start_port_forward
fetch_policy_bundle
verify_bundle_signature_and_temporal
bundle_has_prefix "/tmp/" || fail "initial bundle missing bootstrap floor /tmp/"
bundle_has_prefix "/dev/shm/" || fail "initial bundle missing bootstrap floor /dev/shm/"
bundle_has_prefix "/var/tmp/" || fail "initial bundle missing bootstrap floor /var/tmp/"
[[ "$(bundle_prefix_count)" == "3" ]] || fail "initial bundle prefix count want 3 got $(bundle_prefix_count)"
pass "1c: initial bundle equals bootstrap-equivalent (3 floor prefixes, signed)"

# ---------------------------------------------------------------------------
info "2) VALID CHANGE — new deny prefix + SPIFFE ID on BOTH planes"
issue_spiffe_leaf_pem "$DYNAMIC_SPIFFE" "${WORK_DIR}/dynamic_svid.pem"
start_port_forward
post_evaluate "$EVAL_TMP_PATH" "${WORK_DIR}/dynamic_svid.pem" >/dev/null
evaluate_denied || fail "pre-change evaluate: dynamic SPIFFE should be DENIED on /tmp/ path"
pass "2-pre: evaluate denies dynamic SPIFFE before ConfigMap widen"

STEP2_CM_APPLY_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "step-2 ConfigMap apply timestamp (agent log since-time): ${STEP2_CM_APPLY_TS}"
apply_policy_json_inline "$STEP2_JSON"
wait_pe_log 'desired_policy_accepted.*prefixes_added=.*/opt/neuromesh/dynamic-test/' \
  || fail "PE did not log desired_policy_accepted with dynamic prefix added"
wait_pe_log 'desired_policy_accepted.*spiffe_ids_added=.*dynamic-test-workload' \
  || fail "PE did not log desired_policy_accepted with dynamic SPIFFE ID added"
pe_logs_since 60s | grep -E 'desired_policy_accepted' | tail -3 || true
pass "2a: desired_policy_accepted with prefix + SPIFFE diff"

fetch_policy_bundle
verify_bundle_signature_and_temporal
bundle_has_prefix "$DYNAMIC_PREFIX" || fail "bundle missing dynamic deny prefix after valid change"
bundle_has_spiffe "$DYNAMIC_SPIFFE" || fail "bundle missing dynamic SPIFFE ID after valid change"
STEP2_BUNDLE_VERSION="$(bundle_version)"
[[ -n "$STEP2_BUNDLE_VERSION" ]] || fail "step-2 bundle missing version field"
echo "step-2 bundle version=${STEP2_BUNDLE_VERSION}"
pass "2b: GET /v1/policy-bundle includes new prefix + SPIFFE; signature + temporal OK"

post_evaluate "$EVAL_TMP_PATH" "${WORK_DIR}/dynamic_svid.pem" >/dev/null
evaluate_allowed || fail "post-change evaluate: dynamic SPIFFE should be ALLOWED on /tmp/ path"
pass "2c: POST /v1/evaluate allows dynamic SPIFFE on /tmp/ after widen"

# ---------------------------------------------------------------------------
info "3) DOWNSTREAM ENFORCEMENT — agent sync + LSM deny on dynamic prefix"
PAYLOAD="${DYNAMIC_PREFIX}neuromesh-dynamic-lsm-payload.sh"
write_lsm_payload "$PAYLOAD"

# Baseline: before agent sync, path may still be allowed on LSM maps.
set +e
"$PAYLOAD" >/dev/null 2>&1
BASELINE_RC=$?
set -e
echo "pre-sync exec exit=${BASELINE_RC} (may be 0 if maps not yet updated)"

wait_agent_applied_bundle_since "$STEP2_CM_APPLY_TS" "$STEP2_BUNDLE_VERSION" \
  || fail "agent did not apply step-2 bundle version ${STEP2_BUNDLE_VERSION} within ${POLICY_SYNC_WAIT_SECS}s"
pass "3a: agent policy_sync applied step-2 bundle (version-confirmed, not blind sleep)"

expect_lsm_deny "3b: exec from ${DYNAMIC_PREFIX} rejected by LSM" "$PAYLOAD"

# ---------------------------------------------------------------------------
info "4) REJECTION PATH — invalid CM retains step-2 LKG"
read -r -d '' INVALID_JSON <<'JSON' || true
{
  "deny_path_prefixes": [],
  "identity_allow_exceptions": {
    "scope_path_prefix": "/tmp/",
    "spiffe_ids": [
      "spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor"
    ]
  }
}
JSON
apply_policy_json_inline "$INVALID_JSON"
wait_pe_log 'desired_policy_rejected.*reason=.*empty' \
  || fail "PE did not log desired_policy_rejected for empty deny_path_prefixes"
pass "4a: desired_policy_rejected logged (empty deny_path_prefixes)"

fetch_policy_bundle
bundle_has_prefix "$DYNAMIC_PREFIX" || fail "LKG drift: dynamic prefix missing after rejection"
bundle_has_spiffe "$DYNAMIC_SPIFFE" || fail "LKG drift: dynamic SPIFFE missing after rejection"
post_evaluate "$EVAL_TMP_PATH" "${WORK_DIR}/dynamic_svid.pem" >/dev/null
evaluate_allowed || fail "LKG drift: evaluate no longer allows dynamic SPIFFE after rejection"
pass "4b: bundle + evaluate still on step-2 LKG (not reverted further)"

# ---------------------------------------------------------------------------
info "5) SAFETY RAIL OVERRIDE — floor removal regression + override"
read -r -d '' FLOOR_REJECT_JSON <<JSON || true
{
  "deny_path_prefixes": ["/dev/shm/", "/var/tmp/", "${DYNAMIC_PREFIX}"],
  "identity_allow_exceptions": {
    "scope_path_prefix": "/tmp/",
    "spiffe_ids": [
      "spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor",
      "spiffe://neuromesh.security/ns/default/sa/zt-policy-engine",
      "spiffe://neuromesh.security/ns/default/sa/ai-threat-detector",
      "${DYNAMIC_SPIFFE}"
    ]
  }
}
JSON
apply_policy_json_inline "$FLOOR_REJECT_JSON"
wait_pe_log 'desired_policy_rejected.*floor deny prefix "/tmp/" missing' \
  || fail "PE did not reject /tmp/ floor removal without override flag"
if pe_logs_since 60s | grep -q 'desired_policy_SAFETY_RAIL_OVERRIDE'; then
  fail "SAFETY_RAIL_OVERRIDE must NOT fire on rejected apply"
fi
pass "5-regression: /tmp/ floor removal without override rejected"

FLOOR_UNSAFE=1
echo "FLOOR_UNSAFE=1 — trap will restore bootstrap floors on any failure from here until scenario 7"
read -r -d '' FLOOR_OVERRIDE_JSON <<JSON || true
{
  "deny_path_prefixes": ["/dev/shm/", "/var/tmp/", "${DYNAMIC_PREFIX}"],
  "allow_floor_prefix_removal": true,
  "identity_allow_exceptions": {
    "scope_path_prefix": "/tmp/",
    "spiffe_ids": [
      "spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor",
      "spiffe://neuromesh.security/ns/default/sa/zt-policy-engine",
      "spiffe://neuromesh.security/ns/default/sa/ai-threat-detector",
      "${DYNAMIC_SPIFFE}"
    ]
  }
}
JSON
apply_policy_json_inline "$FLOOR_OVERRIDE_JSON"
wait_pe_log 'desired_policy_accepted' || fail "override apply did not log accepted"
wait_pe_log 'desired_policy_SAFETY_RAIL_OVERRIDE.*floor_prefixes_removed=.*/tmp/' \
  || fail "PE did not log desired_policy_SAFETY_RAIL_OVERRIDE for /tmp/ removal"
pass "5: SAFETY_RAIL_OVERRIDE logged (distinct from accepted) for /tmp/ floor removal"

fetch_policy_bundle
bundle_has_prefix "/tmp/" && fail "bundle still lists /tmp/ after override removal" || true
bundle_has_prefix "$DYNAMIC_PREFIX" || fail "dynamic prefix lost after safety-rail apply"
pass "5-verify: bundle reflects override state (/tmp/ gone, dynamic prefix retained)"

# ---------------------------------------------------------------------------
info "6) RESTART SELF-HEAL — PE pod restart reconciles live ConfigMap"
kubectl -n "$NS" rollout restart "deploy/${PE_DEPLOY}"
kubectl -n "$NS" rollout status "deploy/${PE_DEPLOY}" --timeout=180s
sleep 4
wait_pe_log 'desired_policy_watch starting' \
  || fail "restarted PE did not log watch starting"
wait_pe_log 'desired_policy_accepted' \
  || fail "restarted PE did not reconcile ConfigMap on startup"
fetch_policy_bundle
bundle_has_prefix "/tmp/" && fail "post-restart bundle incorrectly restored /tmp/" || true
bundle_has_prefix "$DYNAMIC_PREFIX" || fail "post-restart bundle missing dynamic prefix from live CM"
pass "6: PE restart reconciled current ConfigMap (not stale in-memory state)"

# ---------------------------------------------------------------------------
info "7) CLEANUP — disable gate, restore bootstrap-only behavior"
disable_desired_policy_gate
wait_pe_log 'desired_policy_watch disabled' \
  || fail "PE did not log desired_policy_watch disabled after env unset"
pass "7a: gate disabled cleanly (watch disabled log)"

apply_policy_json_file "$BOOTSTRAP_JSON_FILE"
fetch_policy_bundle
verify_bundle_signature_and_temporal
bundle_has_prefix "/tmp/" || fail "post-cleanup bundle missing bootstrap /tmp/"
[[ "$(bundle_prefix_count)" == "3" ]] || fail "post-cleanup bundle prefix count want 3 got $(bundle_prefix_count)"
FLOOR_UNSAFE=0
pass "7b: bootstrap-only bundle restored (3 floor prefixes)"

# Successful end — skip trap restore (already cleaned).
RESTORE_CM=0
CLEANUP_DONE=1
rm -rf /opt/neuromesh/dynamic-test 2>/dev/null || true

info "summary"
echo "PASS_COUNT=$PASS_COUNT"
echo "ALL PASS — paste this full output to PR (Issue #137 first live activation)"
