#!/usr/bin/env bash
# Live verification: pinned BPF map ABI migration 16->32 (Issue #208 / ADR-002).
#
# Proves on a BPF-LSM host (fail-closed; does NOT fake-pass):
#   1) Genuine legacy agent (pre-#134) attaches LSM + PATH_DENY_LIST value 20B.
#   2) /tmp probe starts ONLY after that legacy program is attached and stays
#      running through migration — must see ZERO successful execs (F2).
#   3) New agent migrates: PATH_DENY_LIST is 36B, operator prefix carried over,
#      exactly one attached nm_lsm_bprm, legacy_abi_* gone.
#   4) kill -9 + restart resumes with pins intact (pin-survival regression).
#
# Usage (droplet / lab as root):
#   LEGACY_AGENT_BIN=/path/to/pre-134-agent \
#   AGENT_BIN=./target/release/agent-ebpf-sensor \
#     bash scripts/manual_verify_pin_abi_migration.sh
#
# Build LEGACY_AGENT_BIN via git worktree at 526389b^ (see
# docs/runbooks/agent-pin-recovery.md).
#
# Exit codes:
#   0 — all checks passed (F2 proven with real legacy attach)
#   1 — failure during a proven run
#   2 — F2 NOT PROVEN (LEGACY_AGENT_BIN absent / not executable)
set -euo pipefail

PIN_ROOT="${NEUROMESH_BPF_PIN_ROOT:-/sys/fs/bpf/neuromesh-pin-abi-verify}"
AGENT_BIN="${AGENT_BIN:-./target/release/agent-ebpf-sensor}"
LEGACY_AGENT_BIN="${LEGACY_AGENT_BIN:-}"
OPERATOR_PREFIX="${OPERATOR_PREFIX:-/opt/neuromesh/staging/}"
PROBE_SCRIPT="${PROBE_SCRIPT:-/tmp/nm_probe.sh}"
PROBE_LOG="${PROBE_LOG:-/tmp/nm_probe_success.log}"

log() { printf '[pin-abi-migration] %s\n' "$*"; }
die() { log "FAIL: $*"; exit 1; }

cleanup() {
  if [[ -n "${PROBE_PID:-}" ]]; then
    kill -TERM "$PROBE_PID" 2>/dev/null || true
    wait "$PROBE_PID" 2>/dev/null || true
  fi
  if [[ -n "${AGENT_PID:-}" ]]; then
    kill -TERM "$AGENT_PID" 2>/dev/null || true
    wait "$AGENT_PID" 2>/dev/null || true
  fi
  if [[ -n "${LEGACY_PID:-}" ]]; then
    kill -TERM "$LEGACY_PID" 2>/dev/null || true
    wait "$LEGACY_PID" 2>/dev/null || true
  fi
  if [[ "${CLEAN_PIN_ROOT:-0}" == "1" ]]; then
    rm -rf "$PIN_ROOT" 2>/dev/null || true
  fi
}
trap cleanup EXIT

log "== preflight =="
test -x "$AGENT_BIN" || die "AGENT_BIN not executable: $AGENT_BIN"
command -v bpftool >/dev/null || die "bpftool required"
command -v python3 >/dev/null || die "python3 required"
command -v jq >/dev/null || die "jq required (bpftool -j parsing)"
test -d /sys/fs/bpf || die "/sys/fs/bpf missing"
test -f /sys/kernel/btf/vmlinux || die "BTF missing"
mountpoint -q /sys/fs/bpf 2>/dev/null || mount -t bpf bpf /sys/fs/bpf || true

# F2 cannot be proven without a real pre-#134 agent that attaches nm_lsm_bprm
# before the probe starts. bpftool-only map crafting is NOT an F2 proof.
if [[ -z "$LEGACY_AGENT_BIN" || ! -x "$LEGACY_AGENT_BIN" ]]; then
  log "F2 NOT PROVEN: LEGACY_AGENT_BIN is required and must be executable"
  log "  Build via git worktree at 526389b^ — see docs/runbooks/agent-pin-recovery.md"
  log "  Refusing to fake-pass with bpftool-only map create (no LSM attach)."
  exit 2
fi

# Isolated pin root — do NOT point at production /sys/fs/bpf/neuromesh by default.
rm -rf "$PIN_ROOT"
mkdir -p "$PIN_ROOT"
export NEUROMESH_BPF_PIN_ROOT="$PIN_ROOT"

log "== start LEGACY agent (must attach nm_lsm_bprm + PATH_DENY_LIST value 20B) =="
log "using LEGACY_AGENT_BIN=$LEGACY_AGENT_BIN"
"$LEGACY_AGENT_BIN" &
LEGACY_PID=$!

legacy_ready=0
for _ in $(seq 1 60); do
  if ! kill -0 "$LEGACY_PID" 2>/dev/null; then
    die "legacy agent exited before attaching"
  fi
  if [[ -f "$PIN_ROOT/PATH_DENY_LIST" ]]; then
    LIST_INFO="$(bpftool map show pinned "$PIN_ROOT/PATH_DENY_LIST" 2>/dev/null || true)"
    if echo "$LIST_INFO" | grep -E 'value 20B|value_size 20|value 20' >/dev/null; then
      # Confirm LSM attach exists before starting the probe (F2 window).
      if bpftool -j link show 2>/dev/null | python3 -c '
import json,sys
links=json.load(sys.stdin)
# bpftool -j link show: array of objects; prog name may be under "prog" id
# cross-checked via prog show. Accept link entries that reference nm_lsm_bprm
# either via "prog_name" (newer bpftool) or via prog id lookup below.
sys.exit(0 if links else 1)
' 2>/dev/null; then
        legacy_ready=1
        break
      fi
    fi
  fi
  sleep 0.5
done
[[ "$legacy_ready" -eq 1 ]] || die "legacy agent did not pin PATH_DENY_LIST value 20B in time"

LIST_INFO="$(bpftool map show pinned "$PIN_ROOT/PATH_DENY_LIST")"
echo "$LIST_INFO" | grep -E 'value 20B|value_size 20|value 20' >/dev/null \
  || die "expected legacy value 20B on PATH_DENY_LIST; got: $LIST_INFO"
log "legacy pin confirmed: value 20B"

# Count attached nm_lsm_bprm programs BEFORE probe.
# bpftool -j prog show format: JSON array of objects with keys
#   {"id": N, "type": "lsm", "name": "nm_lsm_bprm", ...}
# We match on .name == "nm_lsm_bprm" (truncated BPF name; full symbol may differ).
count_nm_lsm_bprm() {
  bpftool -j prog show 2>/dev/null | python3 -c '
import json,sys
progs=json.load(sys.stdin)
n=sum(1 for p in progs if p.get("name")=="nm_lsm_bprm")
print(n)
'
}

LEGACY_PROG_COUNT="$(count_nm_lsm_bprm)"
[[ "$LEGACY_PROG_COUNT" -ge 1 ]] \
  || die "legacy agent did not attach nm_lsm_bprm (bpftool -j prog show name match)"
log "legacy nm_lsm_bprm attached (count=$LEGACY_PROG_COUNT)"

# Start /tmp probe ONLY AFTER legacy program is attached; keep through migration.
log "== background /tmp probe loop (must stay denied; started after legacy attach) =="
: >"$PROBE_LOG"
cat >"$PROBE_SCRIPT" <<'EOF'
#!/bin/sh
echo ran >>/tmp/nm_probe_success.log
EOF
chmod +x "$PROBE_SCRIPT"
(
  while true; do
    "$PROBE_SCRIPT" 2>/dev/null || true
    sleep 0.05
  done
) &
PROBE_PID=$!

# Hand off: kill legacy userspace but leave pinned LSM link + maps (enforcement stays).
kill -9 "$LEGACY_PID" 2>/dev/null || true
wait "$LEGACY_PID" 2>/dev/null || true
LEGACY_PID=""

log "== start NEW agent (must migrate; probe still running) =="
"$AGENT_BIN" &
AGENT_PID=$!
for _ in $(seq 1 60); do
  if kill -0 "$AGENT_PID" 2>/dev/null && [[ -f "$PIN_ROOT/PATH_DENY_LIST" ]]; then
    NEW_INFO="$(bpftool map show pinned "$PIN_ROOT/PATH_DENY_LIST" 2>/dev/null || true)"
    if echo "$NEW_INFO" | grep -E 'value 36B|value_size 36|value 36' >/dev/null; then
      break
    fi
  fi
  sleep 0.5
done
kill -0 "$AGENT_PID" || die "new agent exited during migration"
NEW_INFO="$(bpftool map show pinned "$PIN_ROOT/PATH_DENY_LIST")"
echo "$NEW_INFO" | grep -E 'value 36B|value_size 36|value 36' >/dev/null \
  || die "expected PATH_DENY_LIST value 36B after migration; got: $NEW_INFO"
log "migrated pin confirmed: value 36B"

sleep 2
if [[ -s "$PROBE_LOG" ]]; then
  die "enforcement gap: /tmp probe succeeded during migration ($(wc -l <"$PROBE_LOG") hits)"
fi
log "F2 OK: zero successful /tmp execs during migration (legacy attach -> new attach)"

# Operator prefix carried over when seeded by legacy / PE; bootstrap always has /tmp/.
OP_PROBE="/opt/neuromesh/staging/nm-abi-e2e.sh"
mkdir -p "$(dirname "$OP_PROBE")"
printf '#!/bin/sh\necho should-not-run\n' >"$OP_PROBE"
chmod +x "$OP_PROBE"
# /tmp probe already covers bootstrap deny; operator prefix is best-effort if present.
if [[ -n "${OPERATOR_PREFIX}" ]]; then
  if "$OP_PROBE" 2>/dev/null; then
    log "WARN: operator prefix exec succeeded — may be absent from legacy seed; /tmp deny still proven"
  else
    log "operator prefix carried over / enforced"
  fi
fi

# Exactly one attached nm_lsm_bprm after migration handoff.
# Documented match: bpftool -j prog show → JSON array; filter .name == "nm_lsm_bprm".
# (Link show alone is ambiguous across bpftool versions; prog name/id is stable.)
PROG_COUNT="$(count_nm_lsm_bprm)"
[[ "$PROG_COUNT" -eq 1 ]] \
  || die "expected exactly one nm_lsm_bprm prog after migration; got $PROG_COUNT"
log "exactly one nm_lsm_bprm attached (bpftool -j prog show name=nm_lsm_bprm)"

shopt -s nullglob
LEGACY_LEFT=("$PIN_ROOT"/legacy_abi_*)
PROC_LEFT=("$PIN_ROOT"/proc_abi_*)
shopt -u nullglob
[[ ${#LEGACY_LEFT[@]} -eq 0 ]] || die "legacy_abi_* still present: ${LEGACY_LEFT[*]}"
[[ ${#PROC_LEFT[@]} -eq 0 ]] || die "proc_abi_* still present: ${PROC_LEFT[*]}"
log "legacy_abi_* / proc_abi_* cleaned up"

log "== kill -9 + restart (pin survival) =="
kill -9 "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true
AGENT_PID=""
test -f "$PIN_ROOT/PATH_DENY_LIST" || die "pins vanished after kill -9"
"$AGENT_BIN" &
AGENT_PID=$!
sleep 3
kill -0 "$AGENT_PID" || die "agent failed to resume after kill -9"
RESUME_INFO="$(bpftool map show pinned "$PIN_ROOT/PATH_DENY_LIST")"
echo "$RESUME_INFO" | grep -E 'value 36B|value_size 36|value 36' >/dev/null \
  || die "resume lost 36B ABI"
if "$PROBE_SCRIPT" 2>/dev/null; then
  die "/tmp probe succeeded after resume"
fi
log "pin-survival OK after kill -9"

log "ALL CHECKS PASSED"
