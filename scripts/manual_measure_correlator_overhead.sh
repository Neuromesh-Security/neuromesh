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
# Requires: Linux root, cgroup v2, bpftool, python3 (+ cryptography), curl, kubectl,
#   k3s, pidstat (sysstat), agent binary with orchestrator + identity correlator.
#   PE stub signs schema-3 bundles (Issue #108/#110) — same Cosign-compatible
#   Ed25519 pattern as scripts/manual_verify_policy_bundle_signature.sh.
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
KEY_DIR="${TEST_ROOT}/keys"
PRIV_KEY="${KEY_DIR}/bundle_signing.pem"
PUB_KEY="${KEY_DIR}/bundle.pub"
# TEST-HARNESS-ONLY temporal window for this stub (via NEUROMESH_POLICY_BUNDLE_VALIDITY_SECS).
# Production PE default remains **300s** (Issue #110 / T-PB-04 locked design —
# apps/zt-policy-engine DefaultBundleValidityWindow). This 600s override is NOT a
# production default change; it only keeps mid-phase agent syncs from tripping
# bundle_expired during long pidstat windows. Refreshed on every stub GET.
BUNDLE_VALIDITY_SECS="${NEUROMESH_POLICY_BUNDLE_VALIDITY_SECS:-600}"
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

# Loud ERR trap — set -e silent exits otherwise leave no FAIL: line (see stop_agent).
trap 'ec=$?; echo "ERR: script abort line=$LINENO exit=$ec cmd=${BASH_COMMAND:-?}" >&2' ERR

echo "== Slice 2b-ii correlator overhead measurement preflight (Issue #100) =="
echo "METHODOLOGY: baseline (corr=0 idle) → correlator idle (watch+inotify, no churn) → correlator churn"
echo "AGENT_COMM_FOR_pgrep_x=${AGENT_COMM}  (15-char truncated comm; NOT full binary name)"
echo "NEUROMESH_CORR_OVHD_PHASE1_ONLY=${NEUROMESH_CORR_OVHD_PHASE1_ONLY:-<unset>}  (must be unset for full 3-phase run)"
# Outer `script | tee` without pipefail in the *parent* shell reports tee's
# status (usually 0) even when this script exits non-zero — prefer:
#   set -o pipefail; ./scripts/manual_measure_correlator_overhead.sh 2>&1 | tee /tmp/corr-ovhd.log
#   echo EXIT:$?
test "$(id -u)" -eq 0 || fail "must run as root"
test -x "$AGENT_BIN" || fail "AGENT_BIN not executable: $AGENT_BIN"
test -f /sys/kernel/btf/vmlinux || fail "BTF missing"
command -v bpftool >/dev/null || fail "bpftool required"
command -v python3 >/dev/null || fail "python3 required"
command -v kubectl >/dev/null || fail "kubectl required"
command -v pidstat >/dev/null || fail "pidstat required (apt install sysstat)"
command -v ss >/dev/null || fail "ss required"
command -v curl >/dev/null || fail "curl required"
python3 -c "import cryptography" >/dev/null 2>&1 \
  || fail "python3 cryptography package required (signed PE stub; same as manual_verify_policy_bundle_signature.sh)"
test -f /sys/fs/cgroup/cgroup.controllers || fail "cgroup v2 required"
test -f "$KUBECONFIG" || fail "KUBECONFIG missing: $KUBECONFIG"
test -f "$K8S_CA_FILE" || fail "NEUROMESH_K8S_CA_FILE missing: $K8S_CA_FILE"
if [[ -n "${NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS:-}" ]]; then
  fail "NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS is set — unset it (measurement must not use manual seed)"
fi
mkdir -p "$PIN_ROOT" "$TEST_ROOT" "$KEY_DIR"

# --- port / leftover process hygiene ---
port_in_use() {
  local port="$1"
  ss -ltn "( sport = :${port} )" 2>/dev/null | grep -q LISTEN
}

if pgrep -x "$AGENT_COMM" >/dev/null 2>&1; then
  echo "preflight: killing leftover ${AGENT_COMM} process(es)"
  pkill -x "$AGENT_COMM" || true
  sleep 2
  if pgrep -x "$AGENT_COMM" >/dev/null 2>&1; then
    fail "could not clear leftover agent (pgrep -x ${AGENT_COMM} still matches)"
  fi
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
  # Do NOT pass -h: sysstat documents -h as "no average statistics at the end
  # of the report" (horizontal single-line samples only). We want Average: when
  # available, and we also mean-average per-sample rows as a robust fallback.
  # count = WINDOW_SECS / interval (integer) reports, not wall-clock alone.
  local sample_count
  sample_count="$(python3 -c "print(max(1, int('$WINDOW_SECS') // max(1, int('$PIDSTAT_INTERVAL_SECS'))))")"
  echo "== measure ${phase_label}: pidstat -u -r -p ${measure_pid} ${PIDSTAT_INTERVAL_SECS} ${sample_count} =="
  pidstat_file="${TEST_ROOT}/pidstat_${phase_label}.txt"
  pidstat -u -r -p "$measure_pid" "$PIDSTAT_INTERVAL_SECS" "$sample_count" \
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
cpu_samples = []
rss_samples = []

# Trailing Average: lines (present when -h is NOT used).
cpu_avg_re = re.compile(
    r"^Average:\s+\S+\s+\d+\s+"
    r"([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\b"
)
# Average: UID PID minflt/s majflt/s VSZ RSS %MEM Command
rss_avg_re = re.compile(
    r"^Average:\s+\S+\s+\d+\s+"
    r"([\d.]+)\s+([\d.]+)\s+(\d+)\s+(\d+)\s+([\d.]+)\b"
)

# Per-interval sample rows (with or without -h). Skip headers / blank / comments.
# CPU sample: Time UID PID %usr %system %guest %wait %CPU CPU Command
# (Time may be HH:MM:SS or epoch seconds with -H.)
cpu_sample_re = re.compile(
    r"^\S+\s+\S+\s+\d+\s+"
    r"([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+"
    r"(?:\d+|-)\s+\S+"
)
# Memory sample: Time UID PID minflt/s majflt/s VSZ RSS %MEM Command
rss_sample_re = re.compile(
    r"^\S+\s+\S+\s+\d+\s+"
    r"([\d.]+)\s+([\d.]+)\s+(\d+)\s+(\d+)\s+([\d.]+)\s+\S+"
)

with open(path, "r", errors="replace") as f:
    for raw in f:
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if line.startswith("Linux ") or line.startswith("Average:"):
            if line.startswith("Average:"):
                m_rss = rss_avg_re.match(line)
                m_cpu = cpu_avg_re.match(line)
                if m_rss and int(m_rss.group(3)) > 1000:
                    rss_avgs.append(int(m_rss.group(4)))
                    continue
                if m_cpu:
                    cpu_avgs.append(float(m_cpu.group(5)))
                    continue
                parts = line.split()
                if len(parts) >= 8:
                    try:
                        cpu_avgs.append(float(parts[7]))
                    except ValueError:
                        pass
            continue

        # Distinguish CPU vs memory sample by field shape (VSZ/RSS integers).
        m_rss = rss_sample_re.match(line)
        m_cpu = cpu_sample_re.match(line)
        if m_rss and int(m_rss.group(3)) > 1000:
            rss_samples.append(int(m_rss.group(4)))
            continue
        if m_cpu:
            cpu_samples.append(float(m_cpu.group(5)))
            continue

def mean(xs):
    return sum(xs) / len(xs) if xs else None

if cpu_avgs:
    cpu = cpu_avgs[-1]
    src_cpu = "pidstat_Average"
elif cpu_samples:
    cpu = mean(cpu_samples)
    src_cpu = f"mean_of_{len(cpu_samples)}_samples"
else:
    sys.stderr.write(f"no CPU Average or sample lines parsed from {path}\n")
    sys.exit(2)

if rss_avgs:
    rss = rss_avgs[-1]
    src_rss = "pidstat_Average"
elif rss_samples:
    rss = mean(rss_samples)
    src_rss = f"mean_of_{len(rss_samples)}_samples"
else:
    rss = -1
    src_rss = "missing"

print(f"{cpu:.3f} {int(rss) if rss != -1 else -1} {src_cpu} {src_rss}")
PY
)" || {
    echo "---- pidstat output ----" >&2
    cat "$pidstat_file" >&2 || true
    fail "failed to parse pidstat CPU for ${phase_label}"
  }

  local cpu_pct rss_kb cpu_src rss_src
  cpu_pct="$(echo "$parse" | awk '{print $1}')"
  rss_kb="$(echo "$parse" | awk '{print $2}')"
  cpu_src="$(echo "$parse" | awk '{print $3}')"
  rss_src="$(echo "$parse" | awk '{print $4}')"
  echo "PIDSTAT_PARSE_CPU_SRC=${cpu_src} PIDSTAT_PARSE_RSS_SRC=${rss_src}"
  if [[ "$rss_kb" == "-1" ]]; then
    # Fallback: mean of /proc VmRSS start/end when pidstat -r rows missing.
    rss_kb="$(python3 -c "print(int((int('$rss_start_kb')+int('$rss_end_kb'))/2))")"
    echo "NOTE: pidstat RSS missing; using /proc VmRSS mid=(${rss_start_kb}+${rss_end_kb})/2=${rss_kb}"
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
  # Use if/then — NOT `pgrep && fail` / `port_in_use && fail` as the function's
  # last statement. Under `set -e`, a function whose last command is
  # `false && anything` returns status 1; the caller then aborts the whole
  # script with no FAIL: line (classic bash footgun). That was killing the
  # harness silently right after PHASE 1 measure_window, before PHASE 2.
  if pgrep -x "$AGENT_COMM" >/dev/null 2>&1; then
    fail "agent still running after stop (pgrep -x ${AGENT_COMM})"
  fi
  # Metrics port must free before next launch.
  for _ in $(seq 1 20); do
    port_in_use "$METRICS_PORT" || break
    sleep 0.25
  done
  if port_in_use "$METRICS_PORT"; then
    fail "METRICS_PORT ${METRICS_PORT} still listening after agent stop"
  fi
  return 0
}

start_agent() {
  # $1 = correlator mode: "off" | "on"
  local mode="$1"
  : >"$AGENT_LOG"
  unset NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS || true
  unset NEUROMESH_POLICY_BUNDLE_TOKEN_FILE || true
  export NEUROMESH_ZT_POLICY_ENGINE_URL="http://127.0.0.1:${PE_PORT}"
  export NEUROMESH_POLICY_BUNDLE_TOKEN="$BUNDLE_TOKEN"
  # Issue #108: agent verifies X-Neuromesh-Policy-Bundle-Signature fail-closed.
  # Must be the *policy-bundle* Ed25519 pubkey — not the Cosign bytecode key.
  test -f "$PUB_KEY" || fail "policy-bundle pubkey missing at $PUB_KEY"
  export NEUROMESH_POLICY_BUNDLE_PUBLIC_KEY_PATH="$PUB_KEY"
  export NEUROMESH_BPF_PIN_ROOT="$PIN_ROOT"
  export NEUROMESH_CGROUP_ROOT="${NEUROMESH_CGROUP_ROOT:-/sys/fs/cgroup}"
  export NEUROMESH_SPIFFE_TRUST_DOMAIN="$TRUST_DOMAIN"
  export NEUROMESH_INTEGRITY_EXIT_ON_FAILURE="${NEUROMESH_INTEGRITY_EXIT_ON_FAILURE:-false}"
  # Force info for identity_correlator — a parent RUST_LOG=error hides
  # "starting Slice 2b identity correlator" while still showing the degraded-mode
  # ERROR (KUBERNETES_SERVICE_HOST unset), which looks like a missing start line.
  export RUST_LOG="info,neuromesh::identity_correlator=info,neuromesh::policy_sync=info"

  if [[ "$mode" == "on" ]]; then
    # Host-agent (not in-cluster): KUBERNETES_SERVICE_HOST is never set on the
    # droplet. Same pattern as manual_verify_identity_2bii_correlation.sh —
    # explicit API URL + SA bearer + k3s server CA. Issue #100 measures the
    # FULL K8s-connected correlator (pod watch + inotify), not cgroup-teardown-only.
    test -n "${BEARER_TOKEN:-}" \
      || fail "BEARER_TOKEN empty — scenario 1 must mint neuromesh-agent token before correlator-on"
    test -n "${K8S_API_URL:-}" || fail "K8S_API_URL empty"
    test -f "$K8S_CA_FILE" || fail "K8S_CA_FILE missing: $K8S_CA_FILE"
    export NEUROMESH_IDENTITY_CORRELATOR=1
    export NEUROMESH_NODE_NAME="$NODE_NAME"
    export NEUROMESH_K8S_API_URL="$K8S_API_URL"
    export NEUROMESH_K8S_BEARER_TOKEN="$BEARER_TOKEN"
    export NEUROMESH_K8S_CA_FILE="$K8S_CA_FILE"
    echo "correlator-on K8s env: API_URL=${NEUROMESH_K8S_API_URL} CA=${NEUROMESH_K8S_CA_FILE} token_len=${#BEARER_TOKEN} node=${NEUROMESH_NODE_NAME}"
  else
    unset NEUROMESH_IDENTITY_CORRELATOR || true
    export NEUROMESH_IDENTITY_CORRELATOR=0
    unset NEUROMESH_K8S_API_URL || true
    unset NEUROMESH_K8S_BEARER_TOKEN || true
    unset NEUROMESH_K8S_CA_FILE || true
    # NODE_NAME harmless when correlator off; leave unset for clarity.
    unset NEUROMESH_NODE_NAME || true
  fi

  # Launch with explicit env for correlator-on so K8s vars cannot be dropped by
  # a thin wrapper / unexpected environ scrub between export and exec.
  if [[ "$mode" == "on" ]]; then
    if command -v stdbuf >/dev/null 2>&1; then
      env \
        NEUROMESH_IDENTITY_CORRELATOR=1 \
        NEUROMESH_NODE_NAME="$NODE_NAME" \
        NEUROMESH_K8S_API_URL="$K8S_API_URL" \
        NEUROMESH_K8S_BEARER_TOKEN="$BEARER_TOKEN" \
        NEUROMESH_K8S_CA_FILE="$K8S_CA_FILE" \
        stdbuf -oL -eL "$AGENT_BIN" >"$AGENT_LOG" 2>&1 &
    else
      env \
        NEUROMESH_IDENTITY_CORRELATOR=1 \
        NEUROMESH_NODE_NAME="$NODE_NAME" \
        NEUROMESH_K8S_API_URL="$K8S_API_URL" \
        NEUROMESH_K8S_BEARER_TOKEN="$BEARER_TOKEN" \
        NEUROMESH_K8S_CA_FILE="$K8S_CA_FILE" \
        "$AGENT_BIN" >"$AGENT_LOG" 2>&1 &
    fi
  else
    if command -v stdbuf >/dev/null 2>&1; then
      stdbuf -oL -eL "$AGENT_BIN" >"$AGENT_LOG" 2>&1 &
    else
      "$AGENT_BIN" >"$AGENT_LOG" 2>&1 &
    fi
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

  if [[ "$mode" == "on" ]]; then
    # Prove the running process actually received host-agent K8s credentials
    # (absence → connect() falls through to KUBERNETES_SERVICE_HOST → degraded).
    local environ_dump
    environ_dump="$(tr '\0' '\n' <"/proc/${resolved}/environ" 2>/dev/null || true)"
    echo "$environ_dump" | grep -q '^NEUROMESH_K8S_API_URL=' \
      || fail "agent pid ${resolved} missing NEUROMESH_K8S_API_URL in /proc/environ"
    echo "$environ_dump" | grep -q '^NEUROMESH_K8S_BEARER_TOKEN=' \
      || fail "agent pid ${resolved} missing NEUROMESH_K8S_BEARER_TOKEN in /proc/environ"
    echo "$environ_dump" | grep -q '^NEUROMESH_K8S_CA_FILE=' \
      || fail "agent pid ${resolved} missing NEUROMESH_K8S_CA_FILE in /proc/environ"
  fi

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
    echo "---- signature_missing diagnostic (header names) ----" >&2
    grep -En 'signature_missing diagnostic|response_header_names|response_headers_debug' "$AGENT_LOG" >&2 || true
    echo "---- stub log (request/response wire) ----" >&2
    tail -n 80 "$STUB_LOG" >&2 || true
    fail "agent never synced policy bundle (mode=${mode})"
  }

  if [[ "$mode" == "off" ]]; then
    grep -q "NEUROMESH_IDENTITY_CORRELATOR disabled" "$AGENT_LOG" \
      || fail "expected correlator-disabled log line (mode=off)"
  else
    # spawn_identity_correlator logs this BEFORE connect(); degraded mode does
    # not replace it — it adds a separate ERROR afterward.
    local started=0
    for _ in $(seq 1 60); do
      if grep -q "starting Slice 2b identity correlator" "$AGENT_LOG"; then
        started=1
        break
      fi
      sleep 0.5
    done
    test "$started" -eq 1 || {
      echo "---- agent log ----" >&2
      tail -n 160 "$AGENT_LOG" >&2 || true
      fail "phase correlator_idle: agent never reached 'starting Slice 2b identity correlator' within 30s"
    }
    # Reject cgroup-teardown-only — that is not the Issue #100 measurement target.
    if grep -q "cgroup teardown invalidation ONLY" "$AGENT_LOG"; then
      echo "---- agent log (K8s API degraded) ----" >&2
      grep -nE 'Kubernetes API|KUBERNETES_SERVICE|teardown invalidation ONLY|NEUROMESH_K8S' \
        "$AGENT_LOG" >&2 || true
      fail "correlator entered cgroup-teardown-only degraded mode (K8s API unreachable). \
Host-agent requires NEUROMESH_K8S_API_URL + NEUROMESH_K8S_BEARER_TOKEN + NEUROMESH_K8S_CA_FILE \
(same as manual_verify_identity_2bii_correlation.sh); KUBERNETES_SERVICE_HOST is unset on the droplet."
    fi
    # Positive proof: startup forced_resync only runs when K8sClient::connect succeeded.
    local k8s_ok=0
    for _ in $(seq 1 40); do
      if grep -q "cgroup teardown invalidation ONLY" "$AGENT_LOG"; then
        break
      fi
      if grep -q "forced identity correlator resync" "$AGENT_LOG"; then
        k8s_ok=1
        break
      fi
      sleep 0.5
    done
    test "$k8s_ok" -eq 1 || {
      echo "---- agent log ----" >&2
      tail -n 160 "$AGENT_LOG" >&2 || true
      fail "correlator did not complete K8s-connected startup resync (full API mode required for #100)"
    }
    pass "correlator-on: full K8s-connected mode (start line + startup resync; not degraded)"
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
export BEARER_TOKEN
# Host-agent credentials (agent does NOT read KUBECONFIG) — same as 2b-ii-C.
echo "NEUROMESH_K8S_API_URL=$K8S_API_URL (token minted len=${#BEARER_TOKEN}; CA=$K8S_CA_FILE)"
pass "scenario 1: RBAC + SA token minted"

# --- scenario 2: signed PE stub (schema 3 + temporal + #108 Cosign-compatible sig) ---
# Predates Issue #108/#110 in comment only: body already had schema 3 + not_before/
# not_after, but lacked X-Neuromesh-Policy-Bundle-Signature. Current agent
# sync_once verifies signature fail-closed before temporal/apply — unsigned stub
# would hang at "agent never synced". Pattern matches
# scripts/manual_verify_policy_bundle_signature.sh (Ed25519 + exact body bytes).
echo "== scenario 2: generate Ed25519 policy-bundle keypair + start signed PE stub =="
export KEY_DIR
python3 - <<'PY'
import os, pathlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
key_dir = pathlib.Path(os.environ["KEY_DIR"])
key_dir.mkdir(parents=True, exist_ok=True)
priv = Ed25519PrivateKey.generate()
(key_dir / "bundle_signing.pem").write_bytes(
    priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
)
(key_dir / "bundle.pub").write_bytes(
    priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
)
print("keys ready in", key_dir)
PY
test -f "$PRIV_KEY" && test -f "$PUB_KEY" || fail "policy-bundle keypair missing under $KEY_DIR"

write_spiffe_allow "[\"${EXPECTED_SPIFFE}\"]"
cat >"${TEST_ROOT}/stub_pe_ovhd.py" <<'PY'
"""GET /v1/policy-bundle stub: schema 3 + temporal + Cosign-compatible Ed25519.

IMPORTANT (Issue #100 live diag): emit the ENTIRE status+header block as one
atomic write. Do NOT use BaseHTTPRequestHandler.send_response/send_header for the
200 path — a live agent saw ONLY content-type (no server/date/content-length/
signature) while curl against the same process saw the signature. There is no
User-Agent/Accept conditional in this handler; the 200 path always includes the
signature. Atomic wire bytes + ThreadingHTTPServer + Connection:close remove
http.server buffering/keep-alive ambiguity. Every request logs path, selected
request headers, and the exact response header block to stderr (STUB_LOG).
"""
from __future__ import annotations

import base64
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives.serialization import load_pem_private_key

TOKEN = os.environ.get("NEUROMESH_POLICY_BUNDLE_TOKEN", "slice2bii-corr-ovhd-token")
SPIFFE_FILE = os.environ["SPIFFE_ALLOW_FILE"]
PORT = int(os.environ["PE_PORT"])
PRIV_PATH = os.environ["NEUROMESH_POLICY_BUNDLE_SIGNING_KEY_PATH"]
VALIDITY = int(os.environ.get("NEUROMESH_POLICY_BUNDLE_VALIDITY_SECS", "600"))

with open(PRIV_PATH, "rb") as f:
    PRIV = load_pem_private_key(f.read(), password=None)


def rfc3339(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def bundle_obj():
    now = time.time()
    with open(SPIFFE_FILE, "r", encoding="utf-8") as f:
        spiffe_ids = json.load(f)
    version = "sha256:corr-ovhd-" + str(
        abs(hash(json.dumps(spiffe_ids, sort_keys=True))) % (10**12)
    )
    return {
        "schema_version": 3,
        "version": version,
        "not_before": rfc3339(now),
        "not_after": rfc3339(now + VALIDITY),
        "deny_path_prefixes": ["/tmp/", "/dev/shm/", "/var/tmp/"],
        "identity_allow_exceptions": {
            "scope_path_prefix": "/tmp/",
            "spiffe_ids": spiffe_ids,
            "issued_at": rfc3339(now),
            "expires_at": rfc3339(now + 3600),
        },
    }


def atomic_response(handler: BaseHTTPRequestHandler, code: int, body: bytes, extra_headers: list[tuple[str, str]]):
    """Write status + ALL headers + body in one flush; force Connection: close."""
    reason = {200: "OK", 401: "Unauthorized", 404: "Not Found"}.get(code, "Error")
    lines = [f"HTTP/1.1 {code} {reason}"]
    for k, v in extra_headers:
        # Reject CR/LF in values so we can never emit a folded/forged header line.
        if "\r" in v or "\n" in v or "\r" in k or "\n" in k:
            raise ValueError(f"illegal CR/LF in header {k!r}")
        lines.append(f"{k}: {v}")
    lines.append("Connection: close")
    lines.append(f"Content-Length: {len(body)}")
    lines.append("")
    head = ("\r\n".join(lines) + "\r\n").encode("ascii")
    sys.stderr.write(
        f"[stub] RESPONSE code={code} header_block={head!r} body_len={len(body)}\n"
    )
    sys.stderr.flush()
    handler.wfile.write(head + body)
    handler.wfile.flush()
    handler.close_connection = True


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("[stub-access] " + (fmt % args) + "\n")
        sys.stderr.flush()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        ua = self.headers.get("User-Agent", "")
        accept = self.headers.get("Accept", "")
        conn = self.headers.get("Connection", "")
        auth = self.headers.get("Authorization", "")
        # Log EVERY request — proves whether agent hit this process and with what headers.
        sys.stderr.write(
            f"[stub] REQUEST path={self.path!r} normalized={path!r} "
            f"User-Agent={ua!r} Accept={accept!r} Connection={conn!r} "
            f"Authorization_present={bool(auth)} "
            f"ALL_REQ_HEADERS={list(self.headers.items())!r}\n"
        )
        sys.stderr.flush()

        if path != "/v1/policy-bundle":
            atomic_response(self, 404, b"not found\n", [("Content-Type", "text/plain")])
            return
        if auth != f"Bearer {TOKEN}":
            atomic_response(
                self,
                401,
                b"unauthorized\n",
                [
                    ("Content-Type", "text/plain"),
                    ("WWW-Authenticate", 'Bearer realm="neuromesh-policy-bundle"'),
                ],
            )
            return

        # Unconditional signed 200 — no User-Agent / Accept / Connection branches.
        body = (json.dumps(bundle_obj(), separators=(",", ":")) + "\n").encode()
        sig = base64.b64encode(PRIV.sign(body)).decode("ascii")
        atomic_response(
            self,
            200,
            body,
            [
                ("X-Neuromesh-Policy-Bundle-Signature", sig),
                ("Content-Type", "application/json"),
            ],
        )


ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
PY

export PE_PORT BUNDLE_TOKEN
NEUROMESH_POLICY_BUNDLE_TOKEN="$BUNDLE_TOKEN" PE_PORT="$PE_PORT" \
  SPIFFE_ALLOW_FILE="$SPIFFE_FILE" \
  NEUROMESH_POLICY_BUNDLE_SIGNING_KEY_PATH="$PRIV_KEY" \
  NEUROMESH_POLICY_BUNDLE_VALIDITY_SECS="$BUNDLE_VALIDITY_SECS" \
  python3 "${TEST_ROOT}/stub_pe_ovhd.py" >"$STUB_LOG" 2>&1 &
STUB_PID=$!
sleep 0.5
kill -0 "$STUB_PID" || fail "PE stub failed to start (see $STUB_LOG)"
HDRS="${TEST_ROOT}/stub_headers.txt"
BODY="${TEST_ROOT}/stub_body.json"
HTTP_CODE="$(curl -sS -D "$HDRS" -o "$BODY" -w '%{http_code}' \
  -H "Authorization: Bearer ${BUNDLE_TOKEN}" \
  "http://127.0.0.1:${PE_PORT}/v1/policy-bundle")"
[[ "$HTTP_CODE" == "200" ]] || fail "stub GET /v1/policy-bundle HTTP $HTTP_CODE"
grep -qi '^X-Neuromesh-Policy-Bundle-Signature:' "$HDRS" \
  || fail "stub missing X-Neuromesh-Policy-Bundle-Signature (agent would signature_missing)"
python3 - <<PY || fail "stub signature/schema check failed"
import base64, json
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
body = open(r"$BODY", "rb").read()
doc = json.loads(body)
assert doc.get("schema_version") == 3, doc
assert doc.get("not_before") and doc.get("not_after"), doc
sig = None
for line in open(r"$HDRS", "r", encoding="utf-8", errors="replace"):
    if line.lower().startswith("x-neuromesh-policy-bundle-signature:"):
        sig = line.split(":", 1)[1].strip()
        break
assert sig, "signature header missing"
pub = load_pem_public_key(open(r"$PUB_KEY", "rb").read())
try:
    pub.verify(base64.b64decode(sig), body)
except InvalidSignature as e:
    raise SystemExit(f"signature does not verify: {e}") from e
print("stub Cosign-compatible Ed25519 + schema 3 temporal OK")
PY
# reqwest-like client preflight (Accept + User-Agent) — must see signature too.
python3 - <<PY || fail "reqwest-like urllib preflight missing signature header"
import urllib.request
url = "http://127.0.0.1:${PE_PORT}/v1/policy-bundle"
req = urllib.request.Request(
    url,
    headers={
        "Authorization": "Bearer ${BUNDLE_TOKEN}",
        "Accept": "*/*",
        "User-Agent": "reqwest/0.12.0",
        "Connection": "keep-alive",
    },
    method="GET",
)
with urllib.request.urlopen(req, timeout=5) as resp:
    names = [k.lower() for k in resp.headers.keys()]
    print("urllib_reqwest_like_header_names=", names)
    if "x-neuromesh-policy-bundle-signature" not in names:
        raise SystemExit(f"signature absent for reqwest-like client; got {names}")
    body = resp.read()
    assert body, "empty body"
print("reqwest-like urllib preflight OK")
PY
pass "scenario 2: signed schema-3 PE stub up on :${PE_PORT}"

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
echo "phase1: calling stop_agent after baseline measure..."
stop_agent
echo "phase1: stop_agent returned OK"
pass "phase 1 complete (baseline)"

# Diag mode: stop after phase 1 (capture signature_missing header dump without
# running correlator idle/churn windows). Unset for a full Issue #100 run.
if [[ "${NEUROMESH_CORR_OVHD_PHASE1_ONLY:-}" == "1" ]]; then
  echo "NEUROMESH_CORR_OVHD_PHASE1_ONLY=1 — exiting after phase 1"
  echo "== DONE: $PASS_COUNT checks passed (phase-1-only) =="
  exit 0
fi

echo "phase1→2 transition: starting correlator-on idle phase (PHASE1_ONLY unset)"
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
