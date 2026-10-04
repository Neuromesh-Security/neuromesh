#!/usr/bin/env bash
# Live verification: pinned BPF map ABI migration 16→32 (Issue #208 / ADR-002).
#
# HONEST SCOPE (non-vacuous F2):
#   This script proves a no-enforcement-gap migration ONLY when:
#     - LEGACY_AGENT_BIN is a real pre-#134 agent that attaches nm_lsm_bprm, and
#     - the host starts with zero nm_lsm_bprm programs, and
#     - a /tmp probe succeeds BEFORE attach (positive control) and fails AFTER
#       legacy attach (negative control), then stays denied through migration.
#   bpftool-only map crafting is NOT an F2 proof (exit 2).
#
# Checks (R3):
#   1) Preflight: zero nm_lsm_bprm on the host
#   2) Positive then negative probe control (probe works; then denied)
#   3) Legacy attach proven via link prog_id ↔ prog name cross-ref
#   4) Wait /healthz + legacy_abi_* gone + legacy prog id gone
#   5) Exactly one NEW nm_lsm_bprm id after migration
#   6) F3: dump legacy LIST+COUNT before handoff; after migrate assert entry-set equality + COUNT
#   7) No WARN-only /opt side-effect probe (fail-closed on /tmp only)
#   8) PROBE_LOG path is consistent (probe script writes to $PROBE_LOG)
#   9) Refuse rm -rf of production pin root; parse bytes_value via bpftool -j
#
# Usage (BPF-LSM lab VM as root; isolated pin root):
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
#   2 — F2 NOT PROVEN (missing LEGACY_AGENT_BIN / unclean host / bad pin root)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARSER="${PARSER:-$SCRIPT_DIR/pin_abi_verify_parsers.py}"

PIN_ROOT="${NEUROMESH_BPF_PIN_ROOT:-/sys/fs/bpf/neuromesh-pin-abi-verify}"
AGENT_BIN="${AGENT_BIN:-./target/release/agent-ebpf-sensor}"
LEGACY_AGENT_BIN="${LEGACY_AGENT_BIN:-}"
PROBE_SCRIPT="${PROBE_SCRIPT:-/tmp/nm_probe.sh}"
PROBE_LOG="${PROBE_LOG:-/tmp/nm_probe_success.log}"
HEALTHZ_URL="${HEALTHZ_URL:-http://127.0.0.1:9090/healthz}"
PRODUCTION_PIN_ROOT="/sys/fs/bpf/neuromesh"
MAP_DUMP_DIR="${MAP_DUMP_DIR:-/tmp/nm_pin_abi_map_dump}"

log() { printf '[pin-abi-migration] %s\n' "$*"; }
die() { log "FAIL: $*"; exit 1; }
not_proven() { log "F2 NOT PROVEN: $*"; exit 2; }

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
  if [[ "${CLEAN_PIN_ROOT:-0}" == "1" && -n "${PIN_ROOT:-}" ]]; then
    # Never wipe production — guard again in cleanup.
    if [[ "$PIN_ROOT" != "$PRODUCTION_PIN_ROOT" && "$PIN_ROOT" != "/" ]]; then
      rm -rf "$PIN_ROOT" 2>/dev/null || true
    fi
  fi
}
trap cleanup EXIT

nm_lsm_ids() {
  bpftool -j prog show 2>/dev/null | python3 -c '
import json, sys
progs = json.load(sys.stdin)
ids = sorted(int(p["id"]) for p in progs if p.get("name") == "nm_lsm_bprm" and "id" in p)
print(" ".join(str(i) for i in ids))
'
}

count_nm_lsm_bprm() {
  local ids=()
  # shellcheck disable=SC2207
  read -r -a ids <<< "$(nm_lsm_ids)"
  echo "${#ids[@]}"
}

# Cross-ref: at least one bpf link whose prog_id resolves to name nm_lsm_bprm.
attached_nm_lsm_via_prog_id() {
  bpftool -j link show 2>/dev/null | python3 -c '
import json, sys, subprocess
links = json.load(sys.stdin)
progs = json.loads(subprocess.check_output(["bpftool", "-j", "prog", "show"], text=True))
by_id = {int(p["id"]): p for p in progs if "id" in p}
for link in links:
    pid = link.get("prog_id")
    if pid is None:
        continue
    prog = by_id.get(int(pid))
    if prog and prog.get("name") == "nm_lsm_bprm":
        sys.exit(0)
sys.exit(1)
'
}

pinned_bytes_value() {
  local pin="$1"
  bpftool -j map show pinned "$pin" | python3 -c '
import json, sys
info = json.load(sys.stdin)
# bpftool may return a single object or a one-element list.
if isinstance(info, list):
    if not info:
        sys.exit(1)
    info = info[0]
val = info.get("bytes_value")
if val is None:
    sys.exit(1)
print(int(val))
'
}

wait_healthz() {
  local _i
  for _i in $(seq 1 60); do
    if curl -fsS "$HEALTHZ_URL" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

log "== preflight =="
test -x "$AGENT_BIN" || die "AGENT_BIN not executable: $AGENT_BIN"
command -v bpftool >/dev/null || die "bpftool required"
command -v python3 >/dev/null || die "python3 required"
test -f "$PARSER" || die "parser helper missing: $PARSER"
command -v jq >/dev/null || die "jq required (bpftool -j parsing)"
command -v curl >/dev/null || die "curl required (healthz wait)"
test -d /sys/fs/bpf || die "/sys/fs/bpf missing"
test -f /sys/kernel/btf/vmlinux || die "BTF missing"
mountpoint -q /sys/fs/bpf 2>/dev/null || mount -t bpf bpf /sys/fs/bpf || true

# (9) Refuse production pin root — never rm -rf live enforcement pins.
if [[ "$PIN_ROOT" == "$PRODUCTION_PIN_ROOT" ]]; then
  not_proven "PIN_ROOT must not be production $PRODUCTION_PIN_ROOT (refuse rm -rf)"
fi
case "$PIN_ROOT" in
  /|/sys|/sys/fs|/sys/fs/bpf) not_proven "PIN_ROOT too broad: $PIN_ROOT" ;;
esac

# F2 cannot be proven without a real pre-#134 agent that attaches nm_lsm_bprm
# before the probe starts. bpftool-only map crafting is NOT an F2 proof.
if [[ -z "$LEGACY_AGENT_BIN" || ! -x "$LEGACY_AGENT_BIN" ]]; then
  not_proven "LEGACY_AGENT_BIN is required and must be executable (see docs/runbooks/agent-pin-recovery.md)"
fi

# (1) Preflight: zero nm_lsm_bprm — otherwise "exactly one" is vacuous/ambiguous.
PRE_COUNT="$(count_nm_lsm_bprm)"
[[ "$PRE_COUNT" -eq 0 ]] \
  || not_proven "host already has $PRE_COUNT nm_lsm_bprm program(s); need a clean lab VM"

# Isolated pin root only.
rm -rf "$PIN_ROOT"
mkdir -p "$PIN_ROOT"
export NEUROMESH_BPF_PIN_ROOT="$PIN_ROOT"
CLEAN_PIN_ROOT=1

# (8) Probe script must append to the same PROBE_LOG the harness checks.
log "== probe control (positive then negative) =="
: >"$PROBE_LOG"
# Embed absolute PROBE_LOG path; keep probe script /bin/sh-safe.
PROBE_LOG_Q="$(printf '%q' "$PROBE_LOG")"
cat >"$PROBE_SCRIPT" <<EOF
#!/bin/sh
echo ran >>${PROBE_LOG_Q}
EOF
chmod +x "$PROBE_SCRIPT"

# (2) Positive control: without LSM, /tmp probe must succeed (probe is wired).
if ! "$PROBE_SCRIPT" 2>/dev/null; then
  die "positive control failed: probe script could not exec before LSM attach"
fi
[[ -s "$PROBE_LOG" ]] || die "positive control failed: PROBE_LOG empty after successful probe"
: >"$PROBE_LOG"
log "positive control OK: probe can succeed before attach"

log "== start LEGACY agent (must attach nm_lsm_bprm + PATH_DENY_LIST bytes_value=20) =="
log "using LEGACY_AGENT_BIN=$LEGACY_AGENT_BIN"
"$LEGACY_AGENT_BIN" &
LEGACY_PID=$!

legacy_ready=0
for _ in $(seq 1 60); do
  if ! kill -0 "$LEGACY_PID" 2>/dev/null; then
    die "legacy agent exited before attaching"
  fi
  if [[ -f "$PIN_ROOT/PATH_DENY_LIST" ]]; then
    bv="$(pinned_bytes_value "$PIN_ROOT/PATH_DENY_LIST" 2>/dev/null || true)"
    if [[ "$bv" == "20" ]] && attached_nm_lsm_via_prog_id; then
      legacy_ready=1
      break
    fi
  fi
  sleep 0.5
done
[[ "$legacy_ready" -eq 1 ]] \
  || die "legacy agent did not pin PATH_DENY_LIST bytes_value=20 with attached nm_lsm_bprm in time"

LIST_BV="$(pinned_bytes_value "$PIN_ROOT/PATH_DENY_LIST")"
[[ "$LIST_BV" -eq 20 ]] || die "expected bytes_value=20 on PATH_DENY_LIST; got $LIST_BV"
log "legacy pin confirmed: bytes_value=$LIST_BV"

# (3) Attached via prog_id cross-ref (already required in wait loop; re-assert).
attached_nm_lsm_via_prog_id \
  || die "legacy nm_lsm_bprm not attached (link prog_id cross-ref failed)"
LEGACY_IDS=()
# shellcheck disable=SC2207
read -r -a LEGACY_IDS <<< "$(nm_lsm_ids)"
[[ "${#LEGACY_IDS[@]}" -ge 1 ]] || die "legacy nm_lsm_bprm id list empty"
LEGACY_PROG_ID="${LEGACY_IDS[0]}"
log "legacy nm_lsm_bprm attached via prog_id cross-ref (ids=${LEGACY_IDS[*]})"

# (2) Negative control: after attach, single probe must be denied.
if "$PROBE_SCRIPT" 2>/dev/null; then
  die "negative control failed: /tmp probe succeeded while legacy LSM attached"
fi
[[ ! -s "$PROBE_LOG" ]] || die "negative control failed: PROBE_LOG non-empty under legacy deny"
log "negative control OK: probe denied under legacy attach"

# F3 baseline: dump legacy LIST+COUNT (bpftool -j) before handoff.
mkdir -p "$MAP_DUMP_DIR"
bpftool -j map dump pinned "$PIN_ROOT/PATH_DENY_LIST" \
  >"$MAP_DUMP_DIR/legacy_PATH_DENY_LIST.json"
bpftool -j map dump pinned "$PIN_ROOT/PATH_DENY_COUNT" \
  >"$MAP_DUMP_DIR/legacy_PATH_DENY_COUNT.json"
LEGACY_COUNT0="$(python3 "$PARSER" count0 "$MAP_DUMP_DIR/legacy_PATH_DENY_COUNT.json")"
[[ "$LEGACY_COUNT0" -gt 0 ]] \
  || die "F3 baseline: legacy PATH_DENY_COUNT[0] empty/zero"
log "F3 baseline: legacy dumps under $MAP_DUMP_DIR (COUNT[0]=$LEGACY_COUNT0)"

# Background probe loop through migration (F2 window).
log "== background /tmp probe loop (must stay denied; started after legacy attach) =="
: >"$PROBE_LOG"
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

# (4) Wait healthz + legacy_abi gone + legacy prog id gone.
migrated=0
for _ in $(seq 1 90); do
  if ! kill -0 "$AGENT_PID" 2>/dev/null; then
    die "new agent exited during migration"
  fi
  if [[ -f "$PIN_ROOT/PATH_DENY_LIST" ]]; then
    bv="$(pinned_bytes_value "$PIN_ROOT/PATH_DENY_LIST" 2>/dev/null || true)"
    shopt -s nullglob
    legacy_left=("$PIN_ROOT"/legacy_abi_*)
    shopt -u nullglob
    cur_ids=()
    # shellcheck disable=SC2207
    read -r -a cur_ids <<< "$(nm_lsm_ids)"
    legacy_id_gone=1
    for id in "${cur_ids[@]:-}"; do
      if [[ "$id" == "$LEGACY_PROG_ID" ]]; then
        legacy_id_gone=0
        break
      fi
    done
    if [[ "$bv" == "36" ]] \
      && [[ ${#legacy_left[@]} -eq 0 ]] \
      && [[ "$legacy_id_gone" -eq 1 ]] \
      && curl -fsS "$HEALTHZ_URL" >/dev/null 2>&1; then
      migrated=1
      break
    fi
  fi
  sleep 0.5
done
[[ "$migrated" -eq 1 ]] \
  || die "migration did not converge (healthz + bytes_value=36 + legacy_abi gone + legacy prog id gone)"

wait_healthz || die "healthz not ready at $HEALTHZ_URL"
NEW_BV="$(pinned_bytes_value "$PIN_ROOT/PATH_DENY_LIST")"
[[ "$NEW_BV" -eq 36 ]] || die "expected PATH_DENY_LIST bytes_value=36; got $NEW_BV"
log "migrated pin confirmed: bytes_value=$NEW_BV; healthz OK; legacy staging/prog id gone"

sleep 1
if [[ -s "$PROBE_LOG" ]]; then
  die "enforcement gap: /tmp probe succeeded during migration ($(wc -l <"$PROBE_LOG") hits)"
fi
log "F2 OK: zero successful /tmp execs during migration (legacy attach → new attach)"

# (5) Exactly one NEW nm_lsm_bprm id (not the legacy id).
NEW_IDS=()
# shellcheck disable=SC2207
read -r -a NEW_IDS <<< "$(nm_lsm_ids)"
[[ "${#NEW_IDS[@]}" -eq 1 ]] \
  || die "expected exactly one nm_lsm_bprm after migration; got ${#NEW_IDS[@]} (${NEW_IDS[*]})"
[[ "${NEW_IDS[0]}" != "$LEGACY_PROG_ID" ]] \
  || die "nm_lsm_bprm id unchanged from legacy ($LEGACY_PROG_ID) — handoff not proven"
attached_nm_lsm_via_prog_id \
  || die "post-migration nm_lsm_bprm not attached (prog_id cross-ref)"
log "exactly one new nm_lsm_bprm id=${NEW_IDS[0]} (legacy was $LEGACY_PROG_ID)"

shopt -s nullglob
LEGACY_LEFT=("$PIN_ROOT"/legacy_abi_*)
PROC_LEFT=("$PIN_ROOT"/proc_abi_*)
shopt -u nullglob
[[ ${#LEGACY_LEFT[@]} -eq 0 ]] || die "legacy_abi_* still present: ${LEGACY_LEFT[*]}"
[[ ${#PROC_LEFT[@]} -eq 0 ]] || die "proc_abi_* still present: ${PROC_LEFT[*]}"
log "legacy_abi_* / proc_abi_* cleaned up"

# (6) F3: assert entry continuity (legacy dump vs post-migrate dump).
mkdir -p "$MAP_DUMP_DIR"
bpftool -j map dump pinned "$PIN_ROOT/PATH_DENY_LIST" \
  >"$MAP_DUMP_DIR/new_PATH_DENY_LIST.json"
bpftool -j map dump pinned "$PIN_ROOT/PATH_DENY_COUNT" \
  >"$MAP_DUMP_DIR/new_PATH_DENY_COUNT.json"
bpftool -j map show pinned "$PIN_ROOT/PATH_DENY_LIST" >"$MAP_DUMP_DIR/PATH_DENY_LIST.show.json"
bpftool -j map show pinned "$PIN_ROOT/PATH_DENY_COUNT" >"$MAP_DUMP_DIR/PATH_DENY_COUNT.show.json"
COUNT_BV="$(pinned_bytes_value "$PIN_ROOT/PATH_DENY_COUNT")"
[[ "$COUNT_BV" -eq 4 ]] || die "expected PATH_DENY_COUNT bytes_value=4; got $COUNT_BV"
python3 "$PARSER" f3_continuity \
  "$MAP_DUMP_DIR/legacy_PATH_DENY_LIST.json" \
  "$MAP_DUMP_DIR/legacy_PATH_DENY_COUNT.json" \
  "$MAP_DUMP_DIR/new_PATH_DENY_LIST.json" \
  "$MAP_DUMP_DIR/new_PATH_DENY_COUNT.json" \
  || die "F3: entry continuity / COUNT mismatch (see $MAP_DUMP_DIR)"
log "F3 OK: legacy LIST identities == new LIST; COUNT matched (dumps under $MAP_DUMP_DIR)"

# (7) No WARN-only /opt side-effect probe — /tmp deny is the sole F2 oracle.

log "== kill -9 + restart (pin survival) =="
kill -9 "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true
AGENT_PID=""
test -f "$PIN_ROOT/PATH_DENY_LIST" || die "pins vanished after kill -9"
"$AGENT_BIN" &
AGENT_PID=$!
wait_healthz || die "healthz not ready after resume"
RESUME_BV="$(pinned_bytes_value "$PIN_ROOT/PATH_DENY_LIST")"
[[ "$RESUME_BV" -eq 36 ]] || die "resume lost bytes_value=36 (got $RESUME_BV)"
# Background loop may still be running — assert empty before truncating.
[[ ! -s "$PROBE_LOG" ]] \
  || die "PROBE_LOG non-empty before truncate ($(wc -l <"$PROBE_LOG") hits since migrated check)"
: >"$PROBE_LOG"
if "$PROBE_SCRIPT" 2>/dev/null; then
  die "/tmp probe succeeded after resume"
fi
[[ ! -s "$PROBE_LOG" ]] || die "PROBE_LOG non-empty after resume probe"
log "pin-survival OK after kill -9"

log "ALL CHECKS PASSED (F2 proven; bytes_value 20→36; exactly one new nm_lsm_bprm)"
