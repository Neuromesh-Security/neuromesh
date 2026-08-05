#!/usr/bin/env bash
# Manual MEASUREMENT for Slice 2b-ii correlator CPU/RSS overhead (Issue #100).
#
# Isolates correlator cost (K8s watch + inotify poll @ 200ms + BPF map churn)
# from the base agent execve/network monitoring overhead already covered in
# docs/performance-baseline.md.
#
# Methodology (three sequential phases, same host, no execve stress):
#   1) Baseline          — NEUROMESH_IDENTITY_CORRELATOR unset/0, idle window
#   2) Correlator idle   — correlator=1, real k3s watch armed, NO pod churn
#   3) Correlator churn  — same correlator process; create/delete multi-container
#                          pods in a loop during the window (2b-ii-C pod shape)
#
# Process identification (LOCKED — do not "improve"):
#   Linux TASK_COMM_LEN truncates "agent-ebpf-sensor" → "agent-ebpf-sens" (15 chars).
#   Resolve with:  pgrep -x agent-ebpf-sens
#   NEVER: pgrep -f  (matches sudo wrappers / shell lines)
#   NEVER: pgrep -x agent-ebpf-sensor  (full name never matches -x)
#   The script echoes RESOLVED_AGENT_PID before every pidstat window so a wrong
#   PID fails loudly instead of wasting a measurement.
#
# Auth note (same as 2b-ii-C):
#   Agent does NOT read KUBECONFIG. kubectl uses KUBECONFIG; agent uses
#   NEUROMESH_K8S_API_URL + NEUROMESH_K8S_BEARER_TOKEN + NEUROMESH_K8S_CA_FILE.
#
# Requires: Linux root, cgroup v2, bpftool, python3, kubectl, k3s, pidstat
#   (sysstat), agent binary with orchestrator + identity correlator.
#
# Env (defaults match neuromesh-dev-lab):
#   AGENT_BIN, NEUROMESH_BPF_PIN_ROOT, NEUROMESH_CGROUP_ROOT,
#   KUBECONFIG=/etc/rancher/k3s/k3s.yaml
#   NEUROMESH_NODE_NAME=neuromesh-dev-lab
#   NEUROMESH_K8S_API_URL=https://127.0.0.1:6443
#   NEUROMESH_K8S_CA_FILE=/var/lib/rancher/k3s/server/tls/server-ca.crt
#   NEUROMESH_MEASURE_WINDOW_SECS=60
#   NEUROMESH_MEASURE_SETTLE_SECS=10
#   NEUROMESH_IDENTITY_TEST_PE_PORT=18083
set -euo pipefail

PIN_ROOT="${NEUROMESH_BPF_PIN_ROOT:-/sys/fs/bpf/neuromesh}"
AGENT_BIN="${AGENT_BIN:-./target/release/agent-ebpf-sensor}"
# Linux /proc/<pid>/comm truncates to 15 chars — exact -x match target.
AGENT_COMM="agent-ebpf-sens"
TEST_ROOT="${NEUROMESH_IDENTITY_TEST_ROOT:-/opt/neuromesh-test-corr-ovhd}"
BUNDLE_TOKEN="${NEUROMESH_POLICY_BUNDLE_TOKEN:-slice2bii-corr-ovhd-token}"
PE_PORT="${NEUROMESH_IDENTITY_TEST_PE_PORT:-18083}"
METRICS_PORT="${NEUROMESH_METRICS_PORT:-9090}"
AGENT_LOG="${TEST_ROOT}/corr-ovhd-agent.log"
STUB_LOG="${TEST_ROOT}/corr-ovhd-stub.log"
SPIFFE_FILE="${TEST_ROOT}/spiffe_allow.json"
POD_NAME="${NEUROMESH_2BIIC_POD_NAME:-nm-2biic-ovhd}"
POD_NS="${NEUROMESH_2BIIC_POD_NS:-default}"
NODE_NAME="${NEUROMESH_NODE_NAME:-neuromesh-dev-lab}"
KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
export KUBECONFIG
K8S_API_URL="${NEUROMESH_K8S_API_URL:-https://127.0.0.1:6443}"
K8S_CA_FILE="${NEUROMESH_K8S_CA_FILE:-/var/lib/rancher/k3s/server/tls/server-ca.crt}"
TRUST_DOMAIN="${NEUROMESH_SPIFFE_TRUST_DOMAIN:-neuromesh.security}"
EXPECTED_SPIFFE="spiffe://${TRUST_DOMAIN}/ns/${POD_NS}/sa/default"
WINDOW_SECS="${NEUROMESH_MEASURE_WINDOW_SECS:-60}"
SETTLE_SECS="${NEUROMESH_MEASURE_SETTLE_SECS:-10}"
PIDSTAT_INTERVAL_SECS="${NEUROMESH_MEASURE_PIDSTAT_INTERVAL_SECS:-1}"

PASS_COUNT=0
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; PASS_COUNT=$((PASS_COUNT + 1)); }

echo "== Slice 2b-ii correlator overhead measurement preflight (Issue #100) =="
echo "METHODOLOGY: baseline (corr=0 idle) → correlator idle (watch+inotify, no churn) → correlator churn"
echo "AGENT_COMM_FOR_pgrep_x=${AGENT_COMM}  (15-char truncated comm; NOT full binary name)"
test "$(id -u)" -eq 0 || fail "must run as root"
test -x "$AGENT_BIN" || fail "AGENT_BIN not executable: $AGENT_BIN"
test -f /sys/kernel/btf/vmlinux || fail "BTF missing"
command -v bpftool >/dev/null || fail "bpftool required"
command -v python3 >/dev/null || fail "python3 required"
command -v kubectl >/dev/null || fail "kubectl required"
command -v pidstat >/dev/null || fail "pidstat required (apt install sysstat)"
command -v ss >/dev/null || fail "ss required"
test -f /sys/fs/cgroup/cgroup.controllers || fail "cgroup v2 required"
test -f "$KUBECONFIG" || fail "KUBECONFIG missing: $KUBECONFIG"
test -f "$K8S_CA_FILE" || fail "NEUROMESH_K8S_CA_FILE missing: $K8S_CA_FILE"
if [[ -n "${NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS:-}" ]]; then
  fail "NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS is set — unset it (measurement must not use manual seed)"
fi
mkdir -p "$PIN_ROOT" "$TEST_ROOT"

# --- port / leftover process hygiene ---
port_in_use() {
  local port="$1"
  ss -ltn "( sport = :${port} )" 2>/dev/null | grep -q LISTEN
}

if pgrep -x "$AGENT_COMM" >/dev/null 2>&1; then
  echo "preflight: killing leftover ${AGENT_COMM} process(es)"
  pkill -x "$AGENT_COMM" || true
  sleep 2
  pgrep -x "$AGENT_COMM" >/dev/null 2>&1 \
    && fail "could not clear leftover agent (pgrep -x ${AGENT_COMM} still matches)"
fi
if port_in_use "$PE_PORT"; then
  fail "PE_PORT ${PE_PORT} already listening — free it or set NEUROMESH_IDENTITY_TEST_PE_PORT"
fi
if port_in_use "$METRICS_PORT"; then
  fail "METRICS_PORT ${METRICS_PORT} already listening — stop prior agent / free the port"
fi

# Best-effort pin cleanup so a prior crash does not trip integrity mid-window.
if [[ -d "$PIN_ROOT" ]]; then
  echo "preflight: clearing BPF pins under ${PIN_ROOT}"
  find "$PIN_ROOT" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true
fi
pass "preflight: tools, ports ${PE_PORT}/${METRICS_PORT}, pins, no leftover agent"

# ---------------------------------------------------------------------------
# PID resolution — the single most common harness footgun this week.
# ---------------------------------------------------------------------------
resolve_agent_pid() {
  local pids count
  # Exact comm match only. Do NOT use -f; do NOT use the untruncated binary name.
  pids="$(pgrep -x "$AGENT_COMM" 2>/dev/null || true)"
  if [[ -z "$pids" ]]; then
    fail "pgrep -x ${AGENT_COMM} returned empty — agent not running (or wrong COMM)"
  fi
  count="$(printf '%s\n' "$pids" | grep -c . || true)"
  if [[ "$count" -ne 1 ]]; then
    fail "pgrep -x ${AGENT_COMM} matched ${count} PIDs (want exactly 1): $(echo "$pids" | tr '\n' ' ')"
  fi
  printf '%s\n' "$pids"
}

# Sample CPU (% of one core, pidstat %CPU Average) + RSS (KB, pidstat Average).
# Writes MEASURED_* into named vars via nameref-style eval of prefix.
measure_window() {
  local phase_label="$1"
  local out_prefix="$2" # e.g. BASELINE → MEASURED_BASELINE_CPU_PCT
  local measure_pid pidstat_file rss_start_kb rss_end_kb parse

  measure_pid="$(resolve_agent_pid)"
  echo "RESOLVED_AGENT_PID=${measure_pid} (via pgrep -x ${AGENT_COMM})"
  if [[ -n "${AGENT_LAUNCH_PID:-}" && "$measure_pid" != "$AGENT_LAUNCH_PID" ]]; then
    echo "WARN: bash launch PID=${AGENT_LAUNCH_PID} != pgrep PID=${measure_pid}; using pgrep (correct)"
  fi
  # Sanity: /proc comm must be the truncated name.
  local proc_comm
  proc_comm="$(tr -d '\0' <"/proc/${measure_pid}/comm" || true)"
  echo "PROC_COMM=${proc_comm}"
  [[ "$proc_comm" == "$AGENT_COMM" ]] \
    || fail " /proc/${measure_pid}/comm='${proc_comm}' != expected '${AGENT_COMM}'"

  rss_start_kb="$(awk '/^VmRSS:/{print $2}' "/proc/${measure_pid}/status")"
  echo "== measure ${phase_label}: pidstat -u -r -h -p ${measure_pid} ${PIDSTAT_INTERVAL_SECS} ${WINDOW_SECS} =="
  pidstat_file="${TEST_ROOT}/pidstat_${phase_label}.txt"
  # -u CPU, -r memory, -h omit average-only footer confusion on some versions;
  # Average: lines are still emitted at end of the run.
  pidstat -u -r -h -p "$measure_pid" "$PIDSTAT_INTERVAL_SECS" "$WINDOW_SECS" \
    >"$pidstat_file" 2>&1 \
    || fail "pidstat failed for phase=${phase_label} (see ${pidstat_file})"

  kill -0 "$measure_pid" 2>/dev/null \
    || fail "agent died during ${phase_label} window (see ${AGENT_LOG})"
  rss_end_kb="$(awk '/^VmRSS:/{print $2}' "/proc/${measure_pid}/status")"

  parse="$(python3 - "$pidstat_file" <<'PY'
import re, sys
path = sys.argv[1]
cpu_avgs = []
rss_avgs = []
# pidstat -h -u -r interleaves CPU and memory sample lines; Average: appears twice
# (once per report type) or as combined depending on sysstat version.
cpu_re = re.compile(
    r"^Average:\s+\S+\s+\d+\s+"
    r"([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\b"
)
# memory Average: UID PID minflt/s majflt/s VSZ RSS %MEM Command
rss_re = re.compile(
    r"^Average:\s+\S+\s+\d+\s+"
    r"([\d.]+)\s+([\d.]+)\s+(\d+)\s+(\d+)\s+([\d.]+)\b"
)
with open(path, "r", errors="replace") as f:
    for line in f:
        line = line.rstrip()
        if not line.startswith("Average:"):
            continue
        # Prefer memory line when VSZ/RSS integers present (field shape).
        m_rss = rss_re.match(line)
        m_cpu = cpu_re.match(line)
        if m_rss and int(m_rss.group(3)) > 1000:  # VSZ KB heuristic
            rss_avgs.append(int(m_rss.group(4)))
            continue
        if m_cpu:
            cpu_avgs.append(float(m_cpu.group(5)))  # %CPU
            continue
        # Fallback: last numeric % before Command on CPU Average lines.
        parts = line.split()
        if len(parts) >= 8:
            try:
                # Average: UID PID %usr %system %guest %wait %CPU ...
                cpu_avgs.append(float(parts[7]))
            except ValueError:
                pass

if not cpu_avgs:
    sys.stderr.write(f"no CPU Average line parsed from {path}\n")
    sys.exit(2)
cpu = cpu_avgs[-1]
rss = rss_avgs[-1] if rss_avgs else -1
print(f"{cpu:.3f} {rss}")
PY
)" || {
    echo "---- pidstat output ----" >&2
    cat "$pidstat_file" >&2 || true
    fail "failed to parse pidstat Average for ${phase_label}"
  }

  local cpu_pct rss_kb
  cpu_pct="$(echo "$parse" | awk '{print $1}')"
  rss_kb="$(echo "$parse" | awk '{print $2}')"
  if [[ "$rss_kb" == "-1" ]]; then
    # Fallback: mean of /proc VmRSS start/end when pidstat -r Average missing.
    rss_kb="$(python3 -c "print(int((int('$rss_start_kb')+int('$rss_end_kb'))/2))")"
    echo "NOTE: pidstat RSS Average missing; using /proc VmRSS mid=(${rss_start_kb}+${rss_end_kb})/2=${rss_kb}"
  fi

  eval "MEASURED_${out_prefix}_CPU_PCT=${cpu_pct}"
  eval "MEASURED_${out_prefix}_RSS_KB=${rss_kb}"
  echo "MEASURED_${out_prefix}_CPU_PCT=${cpu_pct}"
  echo "MEASURED_${out_prefix}_RSS_KB=${rss_kb}"
  echo "PROC_VmRSS_START_KB=${rss_start_kb} PROC_VmRSS_END_KB=${rss_end_kb}"
  pass "phase ${phase_label}: measured CPU=${cpu_pct}% RSS=${rss_kb} KiB over ${WINDOW_SECS}s"
}

stop_agent() {
  if [[ -n "${AGENT_LAUNCH_PID:-}" ]]; then
    kill -TERM "$AGENT_LAUNCH_PID" 2>/dev/null || true
    wait "$AGENT_LAUNCH_PID" 2>/dev/null || true
  fi
  # Ensure COMM-matched process is gone (covers stdbuf / unexpected reparent).
  if pgrep -x "$AGENT_COMM" >/dev/null 2>&1; then
    pkill -TERM -x "$AGENT_COMM" || true
    sleep 1
    pkill -KILL -x "$AGENT_COMM" 2>/dev/null || true
    sleep 1
  fi
  AGENT_LAUNCH_PID=""
  pgrep -x "$AGENT_COMM" >/dev/null 2>&1 \
    && fail "agent still running after stop (pgrep -x ${AGENT_COMM})"
  # Metrics port must free before next launch.
  for _ in $(seq 1 20); do
    port_in_use "$METRICS_PORT" || break
    sleep 0.25
  done
  port_in_use "$METRICS_PORT" \
    && fail "METRICS_PORT ${METRICS_PORT} still listening after agent stop"
}

start_agent() {
  # $1 = correlator mode: "off" | "on"
  local mode="$1"
  : >"$AGENT_LOG"
  unset NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS || true
  unset NEUROMESH_POLICY_BUNDLE_TOKEN_FILE || true
  export NEUROMESH_ZT_POLICY_ENGINE_URL="http://127.0.0.1:${PE_PORT}"
  export NEUROMESH_POLICY_BUNDLE_TOKEN="$BUNDLE_TOKEN"
  export NEUROMESH_BPF_PIN_ROOT="$PIN_ROOT"
  export NEUROMESH_CGROUP_ROOT="${NEUROMESH_CGROUP_ROOT:-/sys/fs/cgroup}"
  export NEUROMESH_SPIFFE_TRUST_DOMAIN="$TRUST_DOMAIN"
  export NEUROMESH_INTEGRITY_EXIT_ON_FAILURE="${NEUROMESH_INTEGRITY_EXIT_ON_FAILURE:-false}"
  export RUST_LOG="${RUST_LOG:-info,neuromesh::identity_correlator=info,neuromesh::policy_sync=info}"

  if [[ "$mode" == "on" ]]; then
    export NEUROMESH_IDENTITY_CORRELATOR=1
    export NEUROMESH_NODE_NAME="$NODE_NAME"
    export NEUROMESH_K8S_API_URL="$K8S_API_URL"
    export NEUROMESH_K8S_BEARER_TOKEN="$BEARER_TOKEN"
    export NEUROMESH_K8S_CA_FILE="$K8S_CA_FILE"
  else
    unset NEUROMESH_IDENTITY_CORRELATOR || true
    export NEUROMESH_IDENTITY_CORRELATOR=0
    unset NEUROMESH_K8S_API_URL || true
    unset NEUROMESH_K8S_BEARER_TOKEN || true
    unset NEUROMESH_K8S_CA_FILE || true
    # NODE_NAME harmless when correlator off; leave unset for clarity.
    unset NEUROMESH_NODE_NAME || true
  fi

  if command -v stdbuf >/dev/null 2>&1; then
    stdbuf -oL -eL "$AGENT_BIN" >"$AGENT_LOG" 2>&1 &
  else
    "$AGENT_BIN" >"$AGENT_LOG" 2>&1 &
  fi
  AGENT_LAUNCH_PID=$!
  sleep 4
  kill -0 "$AGENT_LAUNCH_PID" 2>/dev/null || {
    echo "---- agent log ----" >&2
    tail -n 120 "$AGENT_LOG" >&2 || true
    fail "agent failed to stay up (mode=${mode})"
  }

  local resolved
  resolved="$(resolve_agent_pid)"
  echo "AGENT_LAUNCH_PID=${AGENT_LAUNCH_PID} RESOLVED_AGENT_PID=${resolved} mode=${mode}"
  [[ "$resolved" == "$AGENT_LAUNCH_PID" ]] \
    || echo "WARN: launch PID != pgrep PID (will trust pgrep for pidstat)"

  # Wait for PE sync (both modes need deny-list / identity VALID path warm).
  local synced=0
  for _ in $(seq 1 60); do
    if grep -qE 'applied path-prefix deny list|policy bundle unchanged' "$AGENT_LOG"; then
      synced=1
      break
    fi
    sleep 0.5
  done
  test "$synced" -eq 1 || {
    echo "---- agent log ----" >&2
    tail -n 160 "$AGENT_LOG" >&2 || true
    fail "agent never synced policy bundle (mode=${mode})"
  }

  if [[ "$mode" == "off" ]]; then
    grep -q "NEUROMESH_IDENTITY_CORRELATOR disabled" "$AGENT_LOG" \
      || fail "expected correlator-disabled log line (mode=off)"
  else
    grep -q "starting Slice 2b identity correlator" "$AGENT_LOG" \
      || fail "expected correlator-start log line (mode=on)"
  fi

  echo "settle ${SETTLE_SECS}s before measurement window..."
  sleep "$SETTLE_SECS"
}

write_spiffe_allow() {
  printf '%s\n' "$1" >"$SPIFFE_FILE"
}

apply_churn_pod() {
  kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${POD_NAME}
  namespace: ${POD_NS}
  labels:
    app.kubernetes.io/name: neuromesh-2biic-ovhd
    neuromesh.io/slice: "2b-ii-ovhd"
spec:
  serviceAccountName: default
  restartPolicy: Never
  terminationGracePeriodSeconds: 0
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
}

# --- scenario 1: RBAC + SA token (needed for correlator phases) ---
echo "== scenario 1: apply correlator RBAC + mint SA token =="
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
BEARER_TOKEN="$(kubectl -n neuromesh-system create token neuromesh-agent --duration=2h)"
test -n "$BEARER_TOKEN" || fail "failed to mint neuromesh-agent SA token"
pass "scenario 1: RBAC + SA token minted"

# --- scenario 2: PE stub (schema_version 2, SPIFFE for default/sa) ---
echo "== scenario 2: start PE stub =="
write_spiffe_allow "[\"${EXPECTED_SPIFFE}\"]"
cat >"${TEST_ROOT}/stub_pe_ovhd.py" <<'PY'
import json, os, time
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = os.environ.get("NEUROMESH_POLICY_BUNDLE_TOKEN", "slice2bii-corr-ovhd-token")
SPIFFE_FILE = os.environ["SPIFFE_ALLOW_FILE"]
PORT = int(os.environ["PE_PORT"])


def bundle():
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    exp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600))
    with open(SPIFFE_FILE, "r", encoding="utf-8") as f:
        spiffe_ids = json.load(f)
    version = "sha256:corr-ovhd-" + str(abs(hash(json.dumps(spiffe_ids, sort_keys=True))) % (10**12))
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
  python3 "${TEST_ROOT}/stub_pe_ovhd.py" >"$STUB_LOG" 2>&1 &
STUB_PID=$!
sleep 0.5
kill -0 "$STUB_PID" || fail "PE stub failed to start (see $STUB_LOG)"
curl -sf -H "Authorization: Bearer ${BUNDLE_TOKEN}" \
  "http://127.0.0.1:${PE_PORT}/v1/policy-bundle" >/dev/null \
  || fail "stub GET /v1/policy-bundle failed"
pass "scenario 2: PE stub up on :${PE_PORT}"

AGENT_LAUNCH_PID=""
CHURN_PID=""
POD_CREATED=0
cleanup() {
  if [[ -n "${CHURN_PID}" ]]; then
    kill -TERM "$CHURN_PID" 2>/dev/null || true
    wait "$CHURN_PID" 2>/dev/null || true
  fi
  if [[ "$POD_CREATED" -eq 1 ]]; then
    kubectl -n "$POD_NS" delete pod "$POD_NAME" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  fi
  stop_agent || true
  if [[ -n "${STUB_PID:-}" ]]; then
    kill -TERM "$STUB_PID" 2>/dev/null || true
    wait "$STUB_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# --- Phase 1: baseline (correlator OFF, idle) ---
echo "== PHASE 1: baseline — correlator OFF, idle ${WINDOW_SECS}s =="
start_agent off
measure_window "baseline" "BASELINE"
stop_agent
pass "phase 1 complete (baseline)"

# --- Phase 2: correlator idle (watch + inotify poll, no pod churn) ---
echo "== PHASE 2: correlator idle — correlator ON, k3s watch, NO churn ${WINDOW_SECS}s =="
start_agent on
# Confirm no leftover harness pods that would inject churn into the idle window.
kubectl -n "$POD_NS" delete pod "$POD_NAME" --ignore-not-found --wait=true >/dev/null 2>&1 || true
measure_window "correlator_idle" "CORRELATOR_IDLE"
pass "phase 2 complete (correlator idle)"

# --- Phase 3: correlator under pod create/delete churn (same agent process) ---
echo "== PHASE 3: correlator churn — create/delete 3-container pods during ${WINDOW_SECS}s =="
POD_CREATED=1
(
  set +e
  while true; do
    kubectl -n "$POD_NS" delete pod "$POD_NAME" --ignore-not-found --wait=true >/dev/null 2>&1
    apply_churn_pod >/dev/null 2>&1 || continue
    kubectl -n "$POD_NS" wait --for=condition=Ready "pod/${POD_NAME}" --timeout=90s >/dev/null 2>&1 || true
    # Brief dwell so insert/reconcile work is visible before delete.
    sleep 2
    kubectl -n "$POD_NS" delete pod "$POD_NAME" --wait=true --timeout=60s >/dev/null 2>&1 || true
  done
) &
CHURN_PID=$!
sleep 2
kill -0 "$CHURN_PID" 2>/dev/null || fail "churn loop failed to start"
measure_window "correlator_churn" "CORRELATOR_CHURN"
kill -TERM "$CHURN_PID" 2>/dev/null || true
wait "$CHURN_PID" 2>/dev/null || true
CHURN_PID=""
kubectl -n "$POD_NS" delete pod "$POD_NAME" --ignore-not-found --wait=false >/dev/null 2>&1 || true
POD_CREATED=0
pass "phase 3 complete (correlator churn)"

# --- Deltas (pure correlator idle tax = idle − baseline) ---
DELTA="$(python3 - <<PY
base_cpu = float("$MEASURED_BASELINE_CPU_PCT")
idle_cpu = float("$MEASURED_CORRELATOR_IDLE_CPU_PCT")
churn_cpu = float("$MEASURED_CORRELATOR_CHURN_CPU_PCT")
base_rss = int("$MEASURED_BASELINE_RSS_KB")
idle_rss = int("$MEASURED_CORRELATOR_IDLE_RSS_KB")
churn_rss = int("$MEASURED_CORRELATOR_CHURN_RSS_KB")
print(f"{idle_cpu - base_cpu:.3f}")
print(f"{idle_rss - base_rss}")
print(f"{churn_cpu - idle_cpu:.3f}")
print(f"{churn_rss - idle_rss}")
PY
)"
MEASURED_CORRELATOR_IDLE_TAX_CPU_PCT="$(echo "$DELTA" | sed -n '1p')"
MEASURED_CORRELATOR_IDLE_TAX_RSS_KB="$(echo "$DELTA" | sed -n '2p')"
MEASURED_CORRELATOR_CHURN_DELTA_CPU_PCT="$(echo "$DELTA" | sed -n '3p')"
MEASURED_CORRELATOR_CHURN_DELTA_RSS_KB="$(echo "$DELTA" | sed -n '4p')"

echo ""
echo "== RESULTS (Issue #100) =="
echo "MEASURED_BASELINE_CPU_PCT=$MEASURED_BASELINE_CPU_PCT"
echo "MEASURED_BASELINE_RSS_KB=$MEASURED_BASELINE_RSS_KB"
echo "MEASURED_CORRELATOR_IDLE_CPU_PCT=$MEASURED_CORRELATOR_IDLE_CPU_PCT"
echo "MEASURED_CORRELATOR_IDLE_RSS_KB=$MEASURED_CORRELATOR_IDLE_RSS_KB"
echo "MEASURED_CORRELATOR_CHURN_CPU_PCT=$MEASURED_CORRELATOR_CHURN_CPU_PCT"
echo "MEASURED_CORRELATOR_CHURN_RSS_KB=$MEASURED_CORRELATOR_CHURN_RSS_KB"
echo "MEASURED_CORRELATOR_IDLE_TAX_CPU_PCT=$MEASURED_CORRELATOR_IDLE_TAX_CPU_PCT"
echo "MEASURED_CORRELATOR_IDLE_TAX_RSS_KB=$MEASURED_CORRELATOR_IDLE_TAX_RSS_KB"
echo "MEASURED_CORRELATOR_CHURN_DELTA_CPU_PCT=$MEASURED_CORRELATOR_CHURN_DELTA_CPU_PCT"
echo "MEASURED_CORRELATOR_CHURN_DELTA_RSS_KB=$MEASURED_CORRELATOR_CHURN_DELTA_RSS_KB"
echo "WINDOW_SECS=$WINDOW_SECS SETTLE_SECS=$SETTLE_SECS AGENT_COMM=$AGENT_COMM"
echo ""
echo "INTERPRETATION: MEASURED_CORRELATOR_IDLE_TAX_* = correlator-idle − baseline"
echo "  (= open k3s watch + idle nm-cgroup-inotify 200ms poll tax, no pod churn)."
echo "  MEASURED_CORRELATOR_CHURN_DELTA_* = churn − correlator-idle (insert/delete/reconcile)."
echo "== DONE: $PASS_COUNT checks passed =="
