#!/usr/bin/env bash
# Fail CI if any Neuromesh BPF map/program object name exceeds BPF_OBJ_NAME_LEN-1
# (15 usable characters) or if two names collide under 15-char truncation.
#
# Uses find/grep/sed/awk only (no ripgrep) so Production CI Lint works on stock
# ubuntu-latest runners.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MAX=15
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

collect() {
  # C maps: `} NAME SEC(".maps");`
  find "$ROOT/apps/agent-ebpf-sensor" -type f \( -name '*.c' -o -name '*.h' \) -print0 \
    | xargs -0 grep -hE '\}[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]+SEC\("\.maps"\)' 2>/dev/null \
    | sed -E 's/.*\}[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]+SEC\("\.maps"\).*/\1/' || true

  # C programs: `int NAME(` on the line after `SEC("…")`
  find "$ROOT/apps/agent-ebpf-sensor" -type f -name '*.c' -print0 \
    | xargs -0 awk '
        /^SEC\("/ { want=1; next }
        want && $0 ~ /^int[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\(/ {
          sub(/^int[[:space:]]+/, "", $0)
          sub(/[[:space:]]*\(.*/, "", $0)
          print $0
          want=0
          next
        }
        want && $0 !~ /^[[:space:]]*$/ && $0 !~ /^\/\// { want=0 }
      ' 2>/dev/null || true

  # Rust eBPF maps: `static NAME: RingBuf|Array|HashMap`
  find "$ROOT/apps/agent-ebpf-sensor/ebpf/src" -type f -name '*.rs' -print0 \
    | xargs -0 grep -hE 'static[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*:[[:space:]]*(RingBuf|Array|HashMap)' 2>/dev/null \
    | sed -E 's/.*static[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*:.*/\1/' || true

  # Rust LSM entry: `pub fn NAME` on/after `#[lsm…]`
  find "$ROOT/apps/agent-ebpf-sensor/ebpf/src" -type f -name '*.rs' -print0 \
    | xargs -0 awk '
        /#\[lsm/ { want=1; next }
        want && $0 ~ /pub[[:space:]]+fn[[:space:]]+[A-Za-z_]/ {
          line=$0
          sub(/.*pub[[:space:]]+fn[[:space:]]+/, "", line)
          sub(/[[:space:]]*\(.*/, "", line)
          print line
          want=0
          next
        }
        want && $0 !~ /^[[:space:]]*$/ && $0 !~ /^[[:space:]]*\/\// && $0 !~ /^[[:space:]]*#/ { want=0 }
      ' 2>/dev/null || true

  # Central string constants: bpf_obj_name("NAME")
  find "$ROOT/packages/neuromesh-common/src" -type f -name '*.rs' -print0 \
    | xargs -0 grep -ohE 'bpf_obj_name\("[A-Za-z_][A-Za-z0-9_]*"\)' 2>/dev/null \
    | sed -E 's/bpf_obj_name\("([A-Za-z_][A-Za-z0-9_]*)"\)/\1/' || true
}

collect | sed '/^$/d' | sort -u >"$TMP"

if [[ ! -s "$TMP" ]]; then
  echo "ERROR: lint_bpf_obj_names found zero BPF object names — scanner broken?" >&2
  exit 2
fi

echo "== BPF object names (max ${MAX} chars) =="
fail=0
declare -A trunc_owner=()

while IFS= read -r name; do
  [[ -z "$name" ]] && continue
  len=${#name}
  printf '  %-20s len=%d\n' "$name" "$len"
  if (( len > MAX )); then
    echo "FAIL: BPF object name '$name' has $len chars (limit $MAX)" >&2
    fail=1
  fi
  trunc="${name:0:MAX}"
  if [[ -n "${trunc_owner[$trunc]:-}" && "${trunc_owner[$trunc]}" != "$name" ]]; then
    echo "FAIL: truncation collision: '$name' and '${trunc_owner[$trunc]}' → '$trunc'" >&2
    fail=1
  fi
  trunc_owner[$trunc]="$name"
done <"$TMP"

required=(
  PATH_DENY_LIST
  PATH_DENY_COUNT
  ID_ALLOW_CGROUP
  ID_EXCEPT_VALID
  PROCESS_EVENTS
  RLIMIT_BUCKET
  RLIMIT_DROPS
  CAPTURE_FAILS
  NETWORK_EVENTS
  DROPPED_EVENTS
  TELEM_RINGBUF
  TELEMETRY_STATS
  nm_lsm_bprm
  nm_proc_events
  nm_execveat
  nm_tcp_connect
)
for want in "${required[@]}"; do
  if ! grep -qxF "$want" "$TMP"; then
    echo "FAIL: expected BPF object name '$want' not found in scan" >&2
    fail=1
  fi
done

legacy=(
  IDENTITY_ALLOW_CGROUPS
  IDENTITY_EXCEPTIONS_VALID
  RATE_LIMIT_BUCKET
  RATE_LIMIT_DROPS
  CAPTURE_FAILURES
  TELEMETRY_RINGBUF
  neuromesh_lsm_exec_guard
  neuromesh_process_events
  neuromesh_tcp_connect
)
for bad in "${legacy[@]}"; do
  if grep -qxF "$bad" "$TMP"; then
    echo "FAIL: legacy over-length BPF name '$bad' still present" >&2
    fail=1
  fi
done

if (( fail != 0 )); then
  echo "BPF object name lint FAILED" >&2
  exit 1
fi

echo "OK: $(wc -l <"$TMP") BPF object names, all ≤${MAX} chars, no truncation collisions"
