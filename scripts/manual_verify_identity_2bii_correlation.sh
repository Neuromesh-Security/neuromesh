#!/usr/bin/env bash
# Manual verification for Slice 2b-ii-C — LIVE auto-correlation (Issue #95).
#
# Proves the host-agent ↔ k3s architecture end-to-end:
#   - Agent on the SAME host as k3s (not nested in a pod / kind node)
#   - Real Pod informer + PE allowlist ∩ SPIFFE path-form → BPF auto-insert
#   - Multi-container pod (main + 2 sidecars) exercises 2b-ii-B N-key path
#   - Delete invalidation (pod_delete and/or cgroup_teardown — report which wins)
#   - PE allowlist revoke while pod STILL RUNNING (revoke-on-sync, not delete)
#
# SPIFFE path-form (Slice 2a / 2b-ii-A lock):
#   spiffe://{trust}/ns/{ns}/sa/{sa}
#   default trust = neuromesh.security
#   this harness: spiffe://neuromesh.security/ns/default/sa/default
#
# Auth note (Fortune 500 clarity):
#   The agent does NOT read KUBECONFIG. kubectl uses KUBECONFIG for apply/create.
#   The agent uses NEUROMESH_K8S_API_URL + NEUROMESH_K8S_BEARER_TOKEN +
#   NEUROMESH_K8S_CA_FILE (SA token after applying correlator RBAC).
#
# Requires: Linux root, cgroup v2, bpftool, python3, kubectl, k3s (or compatible),
# agent binary with orchestrator + identity correlator, Cosign attestation material
# (same as other manual_verify_*.sh scripts).
#
# Env (defaults match neuromesh-dev-lab droplet):
#   AGENT_BIN, NEUROMESH_BPF_PIN_ROOT, NEUROMESH_CGROUP_ROOT,
#   KUBECONFIG=/etc/rancher/k3s/k3s.yaml
#   NEUROMESH_NODE_NAME=neuromesh-dev-lab
#   NEUROMESH_K8S_API_URL=https://127.0.0.1:6443
#   NEUROMESH_K8S_CA_FILE=/var/lib/rancher/k3s/server/tls/server-ca.crt
#
# NEVER set NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS — this proves REAL auto-correlation.
set -euo pipefail

PIN_ROOT="${NEUROMESH_BPF_PIN_ROOT:-/sys/fs/bpf/neuromesh}"
AGENT_BIN="${AGENT_BIN:-./target/release/agent-ebpf-sensor}"
TEST_ROOT="${NEUROMESH_IDENTITY_TEST_ROOT:-/opt/neuromesh-test-2biic}"
BUNDLE_TOKEN="${NEUROMESH_POLICY_BUNDLE_TOKEN:-slice2biic-manual-verify-token}"
PE_PORT="${NEUROMESH_IDENTITY_TEST_PE_PORT:-18082}"
AGENT_LOG="${TEST_ROOT}/identity-2biic-agent.log"
STUB_LOG="${TEST_ROOT}/identity-2biic-stub.log"
SPIFFE_FILE="${TEST_ROOT}/spiffe_allow.json"
POD_NAME="${NEUROMESH_2BIIC_POD_NAME:-nm-2biic-corr}"
POD_NS="${NEUROMESH_2BIIC_POD_NS:-default}"
NODE_NAME="${NEUROMESH_NODE_NAME:-neuromesh-dev-lab}"
KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
export KUBECONFIG
K8S_API_URL="${NEUROMESH_K8S_API_URL:-https://127.0.0.1:6443}"
K8S_CA_FILE="${NEUROMESH_K8S_CA_FILE:-/var/lib/rancher/k3s/server/tls/server-ca.crt}"
TRUST_DOMAIN="${NEUROMESH_SPIFFE_TRUST_DOMAIN:-neuromesh.security}"
EXPECTED_SPIFFE="spiffe://${TRUST_DOMAIN}/ns/${POD_NS}/sa/default"
METRICS_URL="${NEUROMESH_METRICS_URL:-http://127.0.0.1:9090/metrics}"
# Policy sync interval is 30s in agent; allow ~3 intervals + margin for revoke.
REVOKE_WAIT_SECS="${NEUROMESH_2BIIC_REVOKE_WAIT_SECS:-100}"
INSERT_WAIT_SECS="${NEUROMESH_2BIIC_INSERT_WAIT_SECS:-120}"
DELETE_WAIT_SECS="${NEUROMESH_2BIIC_DELETE_WAIT_SECS:-60}"

PASS_COUNT=0
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; PASS_COUNT=$((PASS_COUNT + 1)); }

echo "== Slice 2b-ii-C preflight =="
test "$(id -u)" -eq 0 || fail "must run as root"
test -x "$AGENT_BIN" || fail "AGENT_BIN not executable: $AGENT_BIN"
test -f /sys/kernel/btf/vmlinux || fail "BTF missing"
command -v bpftool >/dev/null || fail "bpftool required"
command -v python3 >/dev/null || fail "python3 required"
command -v kubectl >/dev/null || fail "kubectl required"
test -f /sys/fs/cgroup/cgroup.controllers || fail "cgroup v2 required"
test -f "$KUBECONFIG" || fail "KUBECONFIG missing: $KUBECONFIG"
test -f "$K8S_CA_FILE" || fail "NEUROMESH_K8S_CA_FILE missing: $K8S_CA_FILE"
# Fail closed if someone left a manual seed in the environment.
if [[ -n "${NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS:-}" ]]; then
  fail "NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS is set — unset it (this gate proves auto-correlation, not lab seed)"
fi
mkdir -p "$PIN_ROOT" "$TEST_ROOT"

# Confirm SPIFFE path-form matches Slice 2a lock (construct_spiffe_id).
echo "EXPECTED_SPIFFE=$EXPECTED_SPIFFE"
[[ "$EXPECTED_SPIFFE" == "spiffe://${TRUST_DOMAIN}/ns/${POD_NS}/sa/default" ]] \
  || fail "SPIFFE path-form mismatch vs Slice 2a lock"

u64_le_hex() {
  python3 -c "import struct,sys; print(' '.join(f'{b:02x}' for b in struct.pack('<Q', int(sys.argv[1]))))" "$1"
}

# Lookup only — caller must pass precomputed `key hex` bytes (same pattern as 2b-i).
map_has_key_hex() {
  # shellcheck disable=SC2086
  bpftool map lookup name ID_ALLOW_CGROUP key hex $1 >/dev/null 2>&1
}

map_has_all_ids() {
  local id key
  for id in "$@"; do
    key="$(u64_le_hex "$id")"
    map_has_key_hex "$key" || return 1
  done
  return 0
}

map_missing_all_ids() {
  local id key
  for id in "$@"; do
    key="$(u64_le_hex "$id")"
    if map_has_key_hex "$key"; then
      return 1
    fi
  done
  return 0
}

# Resolve container-level cgroup inodes for a Running pod (cri-containerd scopes).
collect_pod_cgroup_ids() {
  local uid="$1"
  python3 - "$uid" <<'PY'
import os, sys
uid = sys.argv[1].strip()
uid_under = uid.replace("-", "_")
root = os.environ.get("NEUROMESH_CGROUP_ROOT", "/sys/fs/cgroup")
candidates = [
    os.path.join(root, "kubepods.slice", "kubepods-besteffort.slice",
                 f"kubepods-besteffort-pod{uid_under}.slice"),
    os.path.join(root, "kubepods.slice", "kubepods-burstable.slice",
                 f"kubepods-burstable-pod{uid_under}.slice"),
    os.path.join(root, "kubepods.slice", f"kubepods-pod{uid_under}.slice"),
    os.path.join(root, "kubepods", "besteffort", f"pod{uid}"),
    os.path.join(root, "kubepods", "burstable", f"pod{uid}"),
    os.path.join(root, "kubepods", f"pod{uid}"),
]
pod_dir = next((p for p in candidates if os.path.isdir(p)), None)
if not pod_dir:
    sys.stderr.write(f"no pod cgroup dir for uid={uid}\n")
    sys.exit(2)
ids = []
for name in sorted(os.listdir(pod_dir)):
    path = os.path.join(pod_dir, name)
    if not os.path.isdir(path):
        continue
    # container leaves: cri-containerd-<id>.scope / crio-*.scope / docker-*.scope
    # or cgroupfs raw container-id directory names (64 hex).
    is_scope = name.endswith(".scope") and (
        "containerd" in name or name.startswith("crio-") or name.startswith("docker-")
    )
    is_raw = len(name) >= 12 and all(c in "0123456789abcdef" for c in name[:12])
    if not (is_scope or is_raw):
        continue
    try:
        ids.append(str(os.stat(path).st_ino))
    except OSError as e:
        sys.stderr.write(f"stat failed {path}: {e}\n")
        sys.exit(3)
if len(ids) < 2:
    sys.stderr.write(f"expected >=2 container leaves under {pod_dir}, got {ids}\n")
    sys.exit(4)
print(" ".join(ids))
print(f"# pod_dir={pod_dir} n={len(ids)}", file=sys.stderr)
PY
}

write_spiffe_allow() {
  # $1 = JSON array string, e.g. '["spiffe://..."]' or '[]'
  printf '%s\n' "$1" >"$SPIFFE_FILE"
}

# --- scenario 1: apply RBAC + ensure SA exists ---
echo "== scenario 1: apply correlator RBAC + neuromesh-agent SA =="
kubectl apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: neuromesh-system
  labels:
    app.kubernetes.io/part-of: neuromesh
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: neuromesh-agent
  namespace: neuromesh-system
  labels:
    app.kubernetes.io/name: neuromesh-agent
EOF
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RBAC_YAML="${REPO_ROOT}/deploy/kubernetes/neuromesh-agent-correlator-rbac.yaml"
test -f "$RBAC_YAML" || fail "missing $RBAC_YAML"
kubectl apply -f "$RBAC_YAML"
pass "scenario 1: RBAC + SA applied (no k3s-specific changes)"

# Mint SA token for host agent (agent does not read KUBECONFIG).
BEARER_TOKEN="$(kubectl -n neuromesh-system create token neuromesh-agent --duration=2h)"
test -n "$BEARER_TOKEN" || fail "failed to mint neuromesh-agent SA token"
echo "NEUROMESH_K8S_API_URL=$K8S_API_URL (token minted; CA=$K8S_CA_FILE)"

# --- scenario 2: mutable PE stub with identity_allow_exceptions ---
echo "== scenario 2: start PE stub (schema_version 2, SPIFFE=$EXPECTED_SPIFFE) =="
write_spiffe_allow "[\"${EXPECTED_SPIFFE}\"]"
cat >"${TEST_ROOT}/stub_pe_2biic.py" <<'PY'
import json, os, time
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = os.environ.get("NEUROMESH_POLICY_BUNDLE_TOKEN", "slice2biic-manual-verify-token")
SPIFFE_FILE = os.environ["SPIFFE_ALLOW_FILE"]
PORT = int(os.environ["PE_PORT"])


def bundle():
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    exp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600))
    with open(SPIFFE_FILE, "r", encoding="utf-8") as f:
        spiffe_ids = json.load(f)
    # Bump version whenever allowlist changes so operators can grep Fresh applies;
    # allowlist cache refresh also happens on unchanged-version TTL sync.
    version = "sha256:slice2biic-" + str(abs(hash(json.dumps(spiffe_ids, sort_keys=True))) % (10**12))
    return {
        "schema_version": 2,
        "version": version,
        "deny_path_prefixes": ["/tmp/", "/dev/shm/", "/var/tmp/"],
        "identity_allow_exceptions": {
            "scope_path_prefix": "/tmp/",
            "spiffe_ids": spiffe_ids,
            "issued_at": now,
            "expires_at": exp,
        },
    }


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/v1/policy-bundle":
            self.send_response(404)
            self.end_headers()
            return
        auth = self.headers.get("Authorization", "")
        if auth != f"Bearer {TOKEN}":
            self.send_response(401)
            self.end_headers()
            return
        body = json.dumps(bundle()).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


HTTPServer(("127.0.0.1", PORT), H).serve_forever()
PY

export PE_PORT BUNDLE_TOKEN
NEUROMESH_POLICY_BUNDLE_TOKEN="$BUNDLE_TOKEN" PE_PORT="$PE_PORT" \
  SPIFFE_ALLOW_FILE="$SPIFFE_FILE" \
  python3 "${TEST_ROOT}/stub_pe_2biic.py" >"$STUB_LOG" 2>&1 &
STUB_PID=$!
sleep 0.5
kill -0 "$STUB_PID" || fail "PE stub failed to start (see $STUB_LOG)"

export EXPECTED_SPIFFE
STUB_BODY="$(curl -sf -H "Authorization: Bearer ${BUNDLE_TOKEN}" \
  "http://127.0.0.1:${PE_PORT}/v1/policy-bundle")" \
  || fail "stub GET /v1/policy-bundle failed"
echo "$STUB_BODY" | python3 -c '
import json,sys,os
b=json.load(sys.stdin)
assert b["schema_version"]==2, b
want=os.environ["EXPECTED_SPIFFE"]
assert want in b["identity_allow_exceptions"]["spiffe_ids"], (want, b)
print("stub ok spiffe=", want)
'
pass "scenario 2: schema_version 2 stub serves EXPECTED_SPIFFE"

AGENT_PID=""
POD_CREATED=0
cleanup() {
  if [[ "$POD_CREATED" -eq 1 ]]; then
    kubectl -n "$POD_NS" delete pod "$POD_NAME" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  fi
  if [[ -n "${AGENT_PID}" ]]; then
    kill -TERM "$AGENT_PID" 2>/dev/null || true
    wait "$AGENT_PID" 2>/dev/null || true
  fi
  if [[ -n "${STUB_PID:-}" ]]; then
    kill -TERM "$STUB_PID" 2>/dev/null || true
    wait "$STUB_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# --- scenario 3: start agent (correlator on, NO manual seed) ---
echo "== scenario 3: start agent (correlator=1, node=$NODE_NAME, NO manual seed) =="
: >"$AGENT_LOG"
unset NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS || true
unset NEUROMESH_POLICY_BUNDLE_TOKEN_FILE || true
export NEUROMESH_IDENTITY_CORRELATOR=1
export NEUROMESH_NODE_NAME="$NODE_NAME"
export NEUROMESH_CGROUP_ROOT="${NEUROMESH_CGROUP_ROOT:-/sys/fs/cgroup}"
export NEUROMESH_SPIFFE_TRUST_DOMAIN="$TRUST_DOMAIN"
export NEUROMESH_K8S_API_URL="$K8S_API_URL"
export NEUROMESH_K8S_BEARER_TOKEN="$BEARER_TOKEN"
export NEUROMESH_K8S_CA_FILE="$K8S_CA_FILE"
export NEUROMESH_ZT_POLICY_ENGINE_URL="http://127.0.0.1:${PE_PORT}"
export NEUROMESH_POLICY_BUNDLE_TOKEN="$BUNDLE_TOKEN"
export NEUROMESH_BPF_PIN_ROOT="$PIN_ROOT"
export NEUROMESH_INTEGRITY_EXIT_ON_FAILURE="${NEUROMESH_INTEGRITY_EXIT_ON_FAILURE:-false}"
export RUST_LOG="${RUST_LOG:-info,neuromesh::identity_correlator=info,neuromesh::policy_sync=info}"

"$AGENT_BIN" >"$AGENT_LOG" 2>&1 &
AGENT_PID=$!
sleep 4
kill -0 "$AGENT_PID" 2>/dev/null || {
  echo "---- agent log ----"
  tail -n 120 "$AGENT_LOG" || true
  fail "agent failed to stay up"
}
# Must NOT emit manual-seed SECURITY WARNING.
if grep -q "SECURITY WARNING: NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS" "$AGENT_LOG"; then
  fail "manual seed warning present — NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS must stay unset"
fi
# Wait for first successful policy sync (allowlist cache warm).
synced=0
for _ in $(seq 1 60); do
  if grep -qE 'applied path-prefix deny list|policy bundle unchanged' "$AGENT_LOG"; then
    synced=1
    break
  fi
  sleep 0.5
done
test "$synced" -eq 1 || {
  echo "---- agent log ----"
  tail -n 160 "$AGENT_LOG" || true
  fail "agent never synced policy bundle (PE allowlist cold)"
}
pass "scenario 3: agent up with correlator; no manual seed; PE synced"

# --- scenario 4+5: multi-container pod + auto-insert all container cgroup_ids ---
echo "== scenario 4: create multi-container pod (main + 2 sidecars) =="
kubectl -n "$POD_NS" delete pod "$POD_NAME" --ignore-not-found --wait=true >/dev/null 2>&1 || true
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${POD_NAME}
  namespace: ${POD_NS}
  labels:
    app.kubernetes.io/name: neuromesh-2biic-verify
    neuromesh.io/slice: "2b-ii-C"
spec:
  serviceAccountName: default
  restartPolicy: Never
  nodeName: ${NODE_NAME}
  containers:
    - name: main
      image: busybox:1.36
      command: ["sleep", "3600"]
    - name: sidecar-a
      image: busybox:1.36
      command: ["sleep", "3600"]
    - name: sidecar-b
      image: busybox:1.36
      command: ["sleep", "3600"]
EOF
POD_CREATED=1
pass "scenario 4: 3-container pod applied (ns=${POD_NS}/sa=default → ${EXPECTED_SPIFFE})"

echo "== wait for Pod Ready =="
kubectl -n "$POD_NS" wait --for=condition=Ready "pod/${POD_NAME}" --timeout=120s \
  || {
    kubectl -n "$POD_NS" describe "pod/${POD_NAME}" || true
    fail "pod never became Ready"
  }
READY_NS="$(date +%s%N)"
POD_UID="$(kubectl -n "$POD_NS" get "pod/${POD_NAME}" -o jsonpath='{.metadata.uid}')"
test -n "$POD_UID" || fail "empty pod uid"
echo "pod Ready uid=$POD_UID at READY_NS=$READY_NS"

# Give container statuses a moment to populate containerIDs + cgroup leaves.
sleep 1
CG_IDS_STR="$(collect_pod_cgroup_ids "$POD_UID")" || {
  echo "---- cgroup tree hint ----"
  find /sys/fs/cgroup/kubepods.slice -maxdepth 3 -type d -name "*${POD_UID//-/_}*" 2>/dev/null | head || true
  fail "could not resolve container cgroup_ids for pod uid=$POD_UID"
}
# shellcheck disable=SC2206
CG_IDS=($CG_IDS_STR)
echo "container cgroup_ids (${#CG_IDS[@]}): ${CG_IDS[*]}"
test "${#CG_IDS[@]}" -ge 3 || fail "expected 3 container cgroup_ids, got ${#CG_IDS[@]}: ${CG_IDS[*]}"
pass "scenario 4b: resolved ${#CG_IDS[@]} container-level cgroup_ids under kubepods"

echo "== scenario 5: poll BPF until ALL container keys auto-inserted =="
INSERT_OK=0
INSERT_END_NS=""
deadline=$((SECONDS + INSERT_WAIT_SECS))
while (( SECONDS < deadline )); do
  if map_has_all_ids "${CG_IDS[@]}"; then
    INSERT_END_NS="$(date +%s%N)"
    INSERT_OK=1
    break
  fi
  sleep 0.050
done
test "$INSERT_OK" -eq 1 || {
  echo "---- agent log (auto-insert) ----"
  grep -E 'auto-inserted IDENTITY_ALLOW_CGROUPS|reconcile_pod|spiffe' "$AGENT_LOG" || true
  tail -n 100 "$AGENT_LOG" || true
  for id in "${CG_IDS[@]}"; do
    key="$(u64_le_hex "$id")"
    if map_has_key_hex "$key"; then
      echo "present: $id"
    else
      echo "MISSING: $id"
    fi
  done
  fail "not all container cgroup_ids auto-inserted within ${INSERT_WAIT_SECS}s"
}
INSERT_NS=$((INSERT_END_NS - READY_NS))
MEASURED_INSERT_LATENCY_MS="$(python3 -c "print(f'{int('$INSERT_NS')/1e6:.3f}')")"
echo "MEASURED_INSERT_LATENCY_MS=$MEASURED_INSERT_LATENCY_MS"
# Confirm agent logged auto-insert (not manual seed) for this SPIFFE.
grep -q "auto-inserted IDENTITY_ALLOW_CGROUPS entry (2b-ii-A)" "$AGENT_LOG" \
  || fail "agent log missing auto-inserted lines"
grep -q "$EXPECTED_SPIFFE" "$AGENT_LOG" \
  || fail "agent log missing EXPECTED_SPIFFE=$EXPECTED_SPIFFE"
pass "scenario 5: ALL ${#CG_IDS[@]} cgroup_ids auto-inserted (MEASURED_INSERT_LATENCY_MS=$MEASURED_INSERT_LATENCY_MS)"

# --- scenario 6: delete pod → all entries removed; report which path wins ---
echo "== scenario 6: delete pod; measure invalidation latency =="
# Snapshot log offset so we attribute reasons to THIS delete.
LOG_MARK="$(wc -l <"$AGENT_LOG" | tr -d ' ')"
DELETE_START_NS="$(date +%s%N)"
kubectl -n "$POD_NS" delete pod "$POD_NAME" --wait=false
POD_CREATED=0

DELETE_OK=0
DELETE_END_NS=""
deadline=$((SECONDS + DELETE_WAIT_SECS))
while (( SECONDS < deadline )); do
  if map_missing_all_ids "${CG_IDS[@]}"; then
    DELETE_END_NS="$(date +%s%N)"
    DELETE_OK=1
    break
  fi
  sleep 0.050
done
test "$DELETE_OK" -eq 1 || {
  echo "---- agent log (delete) ----"
  tail -n +"$((LOG_MARK + 1))" "$AGENT_LOG" | grep -E 'invalidated IDENTITY_ALLOW_CGROUPS|pod_delete|cgroup_teardown' || true
  fail "map entries still present >${DELETE_WAIT_SECS}s after pod delete"
}
DELETE_NS=$((DELETE_END_NS - DELETE_START_NS))
MEASURED_DELETE_INVALIDATION_LATENCY_MS="$(python3 -c "print(f'{int('$DELETE_NS')/1e6:.3f}')")"
echo "MEASURED_DELETE_INVALIDATION_LATENCY_MS=$MEASURED_DELETE_INVALIDATION_LATENCY_MS"

# Which invalidation path fired first after delete?
WINNER="$(
  tail -n +"$((LOG_MARK + 1))" "$AGENT_LOG" \
    | grep -E 'invalidated IDENTITY_ALLOW_CGROUPS entry' \
    | head -n 1 \
    | python3 -c '
import re,sys
line=sys.stdin.read()
m=re.search(r"reason[=:\s\"]+(pod_delete|cgroup_teardown|pe_allowlist_revoke)", line)
print(m.group(1) if m else "unknown")
'
)"
echo "DELETE_INVALIDATION_PATH_WINNER=$WINNER"
case "$WINNER" in
  pod_delete|cgroup_teardown)
    pass "scenario 6: all entries removed via ${WINNER} (MEASURED_DELETE_INVALIDATION_LATENCY_MS=$MEASURED_DELETE_INVALIDATION_LATENCY_MS)"
    ;;
  *)
    # Still PASS map-empty if keys gone; warn on unknown reason parse.
    echo "WARN: could not parse winner from agent log (got='$WINNER'); map empty confirmed"
    pass "scenario 6: all entries removed (winner parse='$WINNER'; MEASURED_DELETE_INVALIDATION_LATENCY_MS=$MEASURED_DELETE_INVALIDATION_LATENCY_MS)"
    ;;
esac

# Wait until pod object is fully gone before recreate.
kubectl -n "$POD_NS" wait --for=delete "pod/${POD_NAME}" --timeout=60s 2>/dev/null || true

# --- scenario 7: PE revoke while pod STILL RUNNING ---
echo "== scenario 7: PE allowlist revoke while pod running =="
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${POD_NAME}
  namespace: ${POD_NS}
  labels:
    app.kubernetes.io/name: neuromesh-2biic-verify
    neuromesh.io/slice: "2b-ii-C"
spec:
  serviceAccountName: default
  restartPolicy: Never
  nodeName: ${NODE_NAME}
  containers:
    - name: main
      image: busybox:1.36
      command: ["sleep", "3600"]
    - name: sidecar-a
      image: busybox:1.36
      command: ["sleep", "3600"]
    - name: sidecar-b
      image: busybox:1.36
      command: ["sleep", "3600"]
EOF
POD_CREATED=1
kubectl -n "$POD_NS" wait --for=condition=Ready "pod/${POD_NAME}" --timeout=120s \
  || fail "revoke-scenario pod never Ready"
POD_UID="$(kubectl -n "$POD_NS" get "pod/${POD_NAME}" -o jsonpath='{.metadata.uid}')"
sleep 1
CG_IDS_STR="$(collect_pod_cgroup_ids "$POD_UID")" || fail "revoke scenario: cgroup_id resolve failed"
# shellcheck disable=SC2206
CG_IDS=($CG_IDS_STR)
deadline=$((SECONDS + INSERT_WAIT_SECS))
while (( SECONDS < deadline )); do
  map_has_all_ids "${CG_IDS[@]}" && break
  sleep 0.050
done
map_has_all_ids "${CG_IDS[@]}" || fail "revoke scenario: entries never inserted before revoke"
pass "scenario 7a: pod running with all ${#CG_IDS[@]} entries present (pre-revoke)"

LOG_MARK="$(wc -l <"$AGENT_LOG" | tr -d ' ')"
# Operator revoke: remove SPIFFE from next-served bundle (pod stays Running).
write_spiffe_allow '[]'
REVOKE_START_NS="$(date +%s%N)"
echo "SPIFFE allowlist cleared in stub at REVOKE_START_NS=$REVOKE_START_NS (pod still Running)"

REVOKE_OK=0
REVOKE_END_NS=""
deadline=$((SECONDS + REVOKE_WAIT_SECS))
while (( SECONDS < deadline )); do
  if map_missing_all_ids "${CG_IDS[@]}"; then
    REVOKE_END_NS="$(date +%s%N)"
    REVOKE_OK=1
    break
  fi
  sleep 0.200
done
test "$REVOKE_OK" -eq 1 || {
  echo "---- agent log (revoke) ----"
  tail -n +"$((LOG_MARK + 1))" "$AGENT_LOG" | grep -E 'invalidated|pe_allowlist|allowlist' || true
  kubectl -n "$POD_NS" get "pod/${POD_NAME}" -o wide || true
  fail "entries not revoked within ${REVOKE_WAIT_SECS}s (policy sync interval=30s)"
}
REVOKE_NS=$((REVOKE_END_NS - REVOKE_START_NS))
MEASURED_REVOKE_LATENCY_MS="$(python3 -c "print(f'{int('$REVOKE_NS')/1e6:.3f}')")"
echo "MEASURED_REVOKE_LATENCY_MS=$MEASURED_REVOKE_LATENCY_MS"

# Assert path was pe_allowlist_revoke (not pod_delete — pod still Running).
REVOKE_REASON="$(
  tail -n +"$((LOG_MARK + 1))" "$AGENT_LOG" \
    | grep -E 'invalidated IDENTITY_ALLOW_CGROUPS entry' \
    | head -n 1 \
    | python3 -c '
import re,sys
line=sys.stdin.read()
m=re.search(r"reason[=:\s\"]+(pod_delete|cgroup_teardown|pe_allowlist_revoke)", line)
print(m.group(1) if m else "unknown")
'
)"
echo "REVOKE_INVALIDATION_PATH=$REVOKE_REASON"
PHASE="$(kubectl -n "$POD_NS" get "pod/${POD_NAME}" -o jsonpath='{.status.phase}' 2>/dev/null || echo missing)"
[[ "$PHASE" == "Running" ]] || fail "pod phase=$PHASE — revoke must happen while Running (not via delete)"
[[ "$REVOKE_REASON" == "pe_allowlist_revoke" ]] \
  || fail "expected pe_allowlist_revoke, got '$REVOKE_REASON' (pod still $PHASE)"
pass "scenario 7: PE revoke cleared all entries via pe_allowlist_revoke (MEASURED_REVOKE_LATENCY_MS=$MEASURED_REVOKE_LATENCY_MS; pod=$PHASE)"

# Soft budgets (report always; hard-fail only on extreme outliers).
python3 -c "
insert=float('$MEASURED_INSERT_LATENCY_MS')
delete=float('$MEASURED_DELETE_INVALIDATION_LATENCY_MS')
revoke=float('$MEASURED_REVOKE_LATENCY_MS')
print(f'latency summary: insert={insert:.3f}ms delete={delete:.3f}ms revoke={revoke:.3f}ms')
# Insert includes apiserver watch + cgroup resolve — allow tens of seconds.
if insert > 90000:
  raise SystemExit('insert latency >90s — investigate correlator/watch')
# Delete should be fast once DELETE/teardown fires.
if delete > 10000:
  raise SystemExit('delete invalidation >10s — investigate')
# Revoke bounded by POLICY_SYNC_INTERVAL (30s) + jitter; hard fail >95s.
if revoke > 95000:
  raise SystemExit('revoke latency >95s — sync loop stuck?')
"

echo "== metrics (best-effort) =="
if curl -sf "$METRICS_URL" 2>/dev/null | grep -q 'identity_correlator_invalidation_total'; then
  curl -sf "$METRICS_URL" | grep 'identity_correlator_' || true
  pass "identity_correlator_* metrics exported"
else
  echo "WARN: metrics endpoint missing identity_correlator_* (non-fatal for this gate)"
  pass "metrics optional skip"
fi

# Cleanup revoke pod explicitly before EXIT trap.
kubectl -n "$POD_NS" delete pod "$POD_NAME" --ignore-not-found --wait=false >/dev/null 2>&1 || true
POD_CREATED=0

echo "== DONE: $PASS_COUNT checks passed =="
echo "MEASURED_INSERT_LATENCY_MS=$MEASURED_INSERT_LATENCY_MS"
echo "MEASURED_DELETE_INVALIDATION_LATENCY_MS=$MEASURED_DELETE_INVALIDATION_LATENCY_MS"
echo "DELETE_INVALIDATION_PATH_WINNER=$WINNER"
echo "MEASURED_REVOKE_LATENCY_MS=$MEASURED_REVOKE_LATENCY_MS"
echo "REVOKE_INVALIDATION_PATH=$REVOKE_REASON"
echo "EXPECTED_SPIFFE=$EXPECTED_SPIFFE"
echo "NOTE: live evidence gate only — do not merge/claim production-safe from this script alone."
