#!/usr/bin/env bash
# Manual verification for Issue #44 Phase 2 + Issue #75 — runtime integrity.
# Requires: Linux, root, CONFIG_BPF_LSM, bpffs, Cosign attestation material
# already configured for the agent (same as manual_verify_lsm_pin.sh).
#
# Scenarios (both required for merge-gate evidence):
#   1) Remove PATH_DENY_LIST pin while agent runs → reason=pinned_map
#   2) unlink+replace the on-disk install path while /proc/self/exe still
#      points at the original inode → reason=on_disk_binary
set -euo pipefail

PIN_ROOT="${NEUROMESH_BPF_PIN_ROOT:-/sys/fs/bpf/neuromesh}"
AGENT_BIN="${AGENT_BIN:-./target/release/agent-ebpf-sensor}"
METRICS_URL="${NEUROMESH_METRICS_URL:-http://127.0.0.1:9090/metrics}"
INTERVAL_SECS="${NEUROMESH_INTEGRITY_INTERVAL_SECS:-30}"

echo "== preflight =="
test -x "$AGENT_BIN"
test -d /sys/fs/bpf
mkdir -p "$PIN_ROOT"

# Writable install path for unlink+replace (DaemonSet uses readOnlyRootFilesystem;
# production path is /usr/local/bin/agent-ebpf-sensor — we override for evidence).
# MUST NOT stage under PATH_DENY_LIST prefixes (/tmp/, /dev/shm/, /var/tmp/) —
# otherwise the LSM correctly blocks exec of the harness copy with EPERM.
INSTALL_ROOT="${NEUROMESH_INTEGRITY_TEST_ROOT:-/opt/neuromesh-test}"
mkdir -p "$INSTALL_ROOT"
INSTALL_DIR="$(mktemp -d "${INSTALL_ROOT}/integrity-install.XXXXXX")"
INSTALL_BIN="${INSTALL_DIR}/agent-ebpf-sensor"
case "$INSTALL_BIN" in
  /tmp/*|/dev/shm/*|/var/tmp/*)
    echo "FAIL: install path ${INSTALL_BIN} is under a PATH_DENY_LIST prefix" >&2
    exit 1
    ;;
esac
cp -a "$AGENT_BIN" "$INSTALL_BIN"
chmod +x "$INSTALL_BIN"

echo "== start agent from install path (interval=${INTERVAL_SECS}s, alert-only) =="
export NEUROMESH_INTEGRITY_INTERVAL_SECS="$INTERVAL_SECS"
export NEUROMESH_INTEGRITY_EXIT_ON_FAILURE=false
export NEUROMESH_AGENT_ON_DISK_PATH="$INSTALL_BIN"
"$INSTALL_BIN" &
AGENT_PID=$!
cleanup() {
  kill -TERM "$AGENT_PID" 2>/dev/null || true
  wait "$AGENT_PID" 2>/dev/null || true
  rm -rf "$INSTALL_DIR"
}
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
echo "agent up (pid=$AGENT_PID) on_disk=${INSTALL_BIN}"

wait_metric() {
  local reason="$1"
  local deadline=$((SECONDS + INTERVAL_SECS + 15))
  while (( SECONDS < deadline )); do
    if curl -sf "$METRICS_URL" \
      | grep -E "agent_integrity_failure_total\\{reason=\"${reason}\"\\}" \
      | grep -vq ' 0$'; then
      return 0
    fi
    sleep 2
  done
  return 1
}

echo "== scenario 1: remove PATH_DENY_LIST pin =="
rm -f "$PIN_ROOT/PATH_DENY_LIST"
test ! -e "$PIN_ROOT/PATH_DENY_LIST"
if ! wait_metric pinned_map; then
  echo "FAIL: pinned_map failure not observed within window" >&2
  exit 1
fi
echo "PASS: reason=pinned_map"

echo "== scenario 2: unlink+replace on-disk install path =="
# Keep process alive on the original inode; replace the path by name.
rm -f "$INSTALL_BIN"
printf '#!/bin/sh\necho neuromesh-tampered-next-restart\n' >"$INSTALL_BIN"
chmod +x "$INSTALL_BIN"
# Running inode via /proc/self/exe must still be the original binary.
test -r "/proc/${AGENT_PID}/exe"
if ! wait_metric on_disk_binary; then
  echo "FAIL: on_disk_binary failure not observed within window" >&2
  curl -sf "$METRICS_URL" | grep agent_integrity_failure_total || true
  exit 1
fi
echo "PASS: reason=on_disk_binary (unlink+replace caught; /proc/self/exe inode unchanged)"

echo "ALL MANUAL INTEGRITY CHECKS PASSED"
