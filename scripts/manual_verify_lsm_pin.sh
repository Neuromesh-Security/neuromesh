#!/usr/bin/env bash
# Manual verification for Issue #44 PR A — LSM link + PATH_DENY map pinning.
# Run on a Linux host/VM/kind node with CONFIG_BPF_LSM, bpffs, and CAP_BPF.
# This environment (Windows + Docker Desktop) cannot prove kill -9 survival.
set -euo pipefail

PIN_ROOT="${NEUROMESH_BPF_PIN_ROOT:-/sys/fs/bpf/neuromesh}"
AGENT_BIN="${AGENT_BIN:-./target/release/agent-ebpf-sensor}"
DENY_PROBE="${DENY_PROBE:-/tmp/neuromesh-pin-e2e-payload.sh}"

echo "== preflight =="
test -d /sys/fs/bpf
test -f /sys/kernel/btf/vmlinux
mount | grep -q 'bpf\|bpffs' || mount -t bpf bpf /sys/fs/bpf || true
mkdir -p "$PIN_ROOT"

echo "== start agent =="
"$AGENT_BIN" &
AGENT_PID=$!
sleep 3
kill -0 "$AGENT_PID"
test -f "$PIN_ROOT/neuromesh_lsm_exec_guard_link"
test -f "$PIN_ROOT/PATH_DENY_LIST"
test -f "$PIN_ROOT/PATH_DENY_COUNT"
echo "pins present under $PIN_ROOT"

echo "== deny while agent alive =="
printf '#!/bin/sh\necho should-not-run\n' >"$DENY_PROBE"
chmod +x "$DENY_PROBE"
if "$DENY_PROBE"; then
  echo "FAIL: blacklisted path executed while agent running" >&2
  kill -9 "$AGENT_PID" || true
  exit 1
fi
echo "deny OK (agent alive)"

echo "== kill -9 agent; enforcement must survive =="
kill -9 "$AGENT_PID"
sleep 1
if kill -0 "$AGENT_PID" 2>/dev/null; then
  echo "FAIL: agent still running" >&2
  exit 1
fi
test -f "$PIN_ROOT/neuromesh_lsm_exec_guard_link"
if "$DENY_PROBE"; then
  echo "FAIL: blacklisted path executed AFTER kill -9 (enforcement died with process)" >&2
  exit 1
fi
echo "PASS: deny still fires with no agent process"

echo "== restart handoff =="
"$AGENT_BIN" &
AGENT_PID=$!
sleep 3
kill -0 "$AGENT_PID"
if "$DENY_PROBE"; then
  echo "FAIL: deny broken after restart handoff" >&2
  kill -9 "$AGENT_PID" || true
  exit 1
fi
echo "PASS: clean restart handoff"
kill -TERM "$AGENT_PID" || true
wait "$AGENT_PID" 2>/dev/null || true
echo "ALL MANUAL CHECKS PASSED"
