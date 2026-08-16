#!/usr/bin/env bash
# Live droplet verification for PATH_DENY_KEY_BYTES 16→32 (LSM-adjacent).
#
# Required because this constant sizes the LSM hot-path capture window
# (`read_bprm_path_prefix`) and the deny-list compare loop in `nm_lsm_bprm`.
# Unit tests prove userspace matching / fail-closed reject of over-length
# prefixes; this script proves the *loaded* BPF program still denies bootstrap
# prefixes and can enforce a prefix that was previously impossible
# (16 < len ≤ 32).
#
# Prerequisites: Linux host/VM/droplet with CONFIG_BPF_LSM, bpffs,
# CAP_BPF/CAP_SYS_ADMIN, live `/sys/kernel/btf/vmlinux`, `bpftool`, `xxd`,
# and a built agent binary.
#
# Usage:
#   AGENT_BIN=./target/release/agent-ebpf-sensor \
#     bash scripts/manual_verify_path_deny_key_bytes.sh
set -euo pipefail

PIN_ROOT="${NEUROMESH_BPF_PIN_ROOT:-/sys/fs/bpf/neuromesh}"
AGENT_BIN="${AGENT_BIN:-./target/release/agent-ebpf-sensor}"
# 22-byte prefix: unenforceable under the old 16-byte key; must deny after bump.
LONG_PREFIX="${LONG_PREFIX:-/opt/neuromesh/staging/}"
LONG_PROBE="${LONG_PROBE:-/opt/neuromesh/staging/live-e2e-payload.sh}"
ENTRY_BIN="${ENTRY_BIN:-/tmp/nm_path_deny_entry.bin}"
BOOTSTRAP_PROBES=(
  /tmp/neuromesh-keybytes-e2e.sh
  /dev/shm/neuromesh-keybytes-e2e.sh
  /var/tmp/neuromesh-keybytes-e2e.sh
)

log() { printf '[path-deny-key-bytes] %s\n' "$*"; }
die() { log "FAIL: $*"; exit 1; }

prefix_len() { printf '%s' "$1" | wc -c | tr -d ' '; }

log "== preflight =="
test -x "$AGENT_BIN" || die "AGENT_BIN not executable: $AGENT_BIN"
command -v bpftool >/dev/null || die "bpftool required"
command -v xxd >/dev/null || die "xxd required"
command -v python3 >/dev/null || die "python3 required"
test -d /sys/fs/bpf || die "/sys/fs/bpf missing"
test -f /sys/kernel/btf/vmlinux || die "BTF missing"
mountpoint -q /sys/fs/bpf 2>/dev/null || mount -t bpf bpf /sys/fs/bpf || true
mkdir -p "$PIN_ROOT"

LONG_LEN="$(prefix_len "$LONG_PREFIX")"
if (( LONG_LEN <= 16 || LONG_LEN > 32 )); then
  die "LONG_PREFIX must satisfy 16 < len <= 32 (got ${LONG_LEN}): $LONG_PREFIX"
fi
log "LONG_PREFIX=${LONG_PREFIX} (${LONG_LEN} bytes)"

write_probe() {
  local path="$1"
  mkdir -p "$(dirname "$path")"
  printf '#!/bin/sh\necho should-not-run\n' >"$path"
  chmod +x "$path"
}

expect_denied() {
  local path="$1"
  if "$path" 2>/dev/null; then
    die "expected LSM deny for $path but exec succeeded"
  fi
  log "deny OK: $path"
}

log "== start agent (bootstrap deny list) =="
"$AGENT_BIN" &
AGENT_PID=$!
cleanup() {
  kill -TERM "$AGENT_PID" 2>/dev/null || true
  wait "$AGENT_PID" 2>/dev/null || true
}
trap cleanup EXIT
sleep 3
kill -0 "$AGENT_PID" || die "agent failed to start"
test -f "$PIN_ROOT/PATH_DENY_LIST" || die "PATH_DENY_LIST pin missing"
test -f "$PIN_ROOT/PATH_DENY_COUNT" || die "PATH_DENY_COUNT pin missing"

log "== A: bootstrap prefixes still denied at KEY_BYTES=32 =="
for probe in "${BOOTSTRAP_PROBES[@]}"; do
  write_probe "$probe"
  expect_denied "$probe"
done

log "== B: pack PathDenyEntry (u32 len + [u8;32]) and install at index 3 =="
python3 - "$LONG_PREFIX" "$ENTRY_BIN" <<'PY'
import struct, sys
prefix = sys.argv[1].encode()
out = sys.argv[2]
assert 16 < len(prefix) <= 32, len(prefix)
# Must match neuromesh_common::PathDenyEntry #[repr(C)]: u32 + [u8; 32] = 36.
entry = struct.pack("<I", len(prefix)) + prefix.ljust(32, b"\0")
assert len(entry) == 36, len(entry)
open(out, "wb").write(entry)
print(f"wrote {out} ({len(entry)} bytes, prefix_len={len(prefix)})")
PY

# Bootstrap occupies slots 0..2; COUNT becomes 4 after this insert.
VALUE_BYTES=$(xxd -p -c 1 "$ENTRY_BIN" | tr '\n' ' ')
bpftool map update pinned "$PIN_ROOT/PATH_DENY_LIST" \
  key hex 03 00 00 00 \
  value hex ${VALUE_BYTES}
bpftool map update pinned "$PIN_ROOT/PATH_DENY_COUNT" \
  key hex 00 00 00 00 \
  value hex 04 00 00 00

log "== C: ${LONG_LEN}-byte prefix now enforceable (was impossible at KEY_BYTES=16) =="
write_probe "$LONG_PROBE"
expect_denied "$LONG_PROBE"

log "ALL LIVE CHECKS PASSED (bootstrap deny + 16<len≤32 deny)"
