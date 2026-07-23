#!/usr/bin/env bash
# Manual verification for Issue #44 Phase 2 — runtime integrity monitor.
# Requires: Linux, root, CONFIG_BPF_LSM, bpffs, Cosign attestation material
# already configured for the agent (same as manual_verify_lsm_pin.sh).
#
# Scenario: start agent with a short integrity interval + alert-only (so the
# shell can observe metrics), remove a deny-map pin while the agent runs, and
# confirm agent_integrity_failure_total{reason="pinned_map"} increments.
set -euo pipefail

PIN_ROOT="${NEUROMESH_BPF_PIN_ROOT:-/sys/fs/bpf/neuromesh}"
AGENT_BIN="${AGENT_BIN:-./target/release/agent-ebpf-sensor}"
METRICS_URL="${NEUROMESH_METRICS_URL:-http://127.0.0.1:9090/metrics}"
INTERVAL_SECS="${NEUROMESH_INTEGRITY_INTERVAL_SECS:-30}"

echo "== preflight =="
test -x "$AGENT_BIN"
test -d /sys/fs/bpf
mkdir -p "$PIN_ROOT"

echo "== start agent (integrity interval=${INTERVAL_SECS}s, alert-only) =="
export NEUROMESH_INTEGRITY_INTERVAL_SECS="$INTERVAL_SECS"
export NEUROMESH_INTEGRITY_EXIT_ON_FAILURE=false
"$AGENT_BIN" &
AGENT_PID=$!
cleanup() { kill -TERM "$AGENT_PID" 2>/dev/null || true; wait "$AGENT_PID" 2>/dev/null || true; }
trap cleanup EXIT

# Wait for pins + metrics
for _ in $(seq 1 30); do
  if kill -0 "$AGENT_PID" 2>/dev/null \
    && test -f "$PIN_ROOT/neuromesh_lsm_exec_guard_link" \
    && test -f "$PIN_ROOT/PATH_DENY_LIST" \
    && curl -sf "$METRICS_URL" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
kill -0 "$AGENT_PID"
test -f "$PIN_ROOT/neuromesh_lsm_exec_guard_link"
test -f "$PIN_ROOT/PATH_DENY_LIST"
echo "agent up (pid=$AGENT_PID)"

before="$(curl -sf "$METRICS_URL" | grep -E 'agent_integrity_failure_total\{reason="pinned_map"\}' || true)"
echo "metrics before: ${before:-<none>}"

echo "== tamper: remove PATH_DENY_LIST pin while agent runs =="
rm -f "$PIN_ROOT/PATH_DENY_LIST"
test ! -e "$PIN_ROOT/PATH_DENY_LIST"

echo "== wait up to $((INTERVAL_SECS + 15))s for integrity tick =="
deadline=$((SECONDS + INTERVAL_SECS + 15))
found=0
while (( SECONDS < deadline )); do
  if curl -sf "$METRICS_URL" | grep -E 'agent_integrity_failure_total\{reason="pinned_map"\}' | grep -vq ' 0$'; then
    found=1
    break
  fi
  sleep 2
done

after="$(curl -sf "$METRICS_URL" | grep -E 'agent_integrity_failure_total\{reason="pinned_map"\}' || true)"
echo "metrics after: ${after:-<none>}"

if [[ "$found" -ne 1 ]]; then
  echo "FAIL: integrity monitor did not report pinned_map failure within window" >&2
  exit 1
fi
echo "PASS: Phase 2 integrity detected missing PATH_DENY_LIST pin"
echo "ALL MANUAL INTEGRITY CHECKS PASSED"
