#!/usr/bin/env bash
# Fail CI if any Neuromesh BPF map/program object name exceeds BPF_OBJ_NAME_LEN-1
# (15 usable characters) or if two names collide under 15-char truncation.
#
# Sources scanned:
#   - Rust eBPF #[map] statics + #[lsm] / pub fn program entrypoints
#   - C SEC(".maps") map structs + SEC(...) int program symbols
#   - neuromesh_common ALL_BPF_OBJECT_NAMES (via cargo test)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MAX=15
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

collect() {
  # C maps: `} NAME SEC(".maps");`
  rg -No --glob '*.c' --glob '*.h' \
    '\}[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]+SEC\("\.maps"\)' \
    -r '$1' "$ROOT/apps/agent-ebpf-sensor" || true

  # C programs: `int NAME(` immediately after a SEC("…") line (heuristic: all
  # `SEC("tracepoint|kprobe|…")` followed by `int name(`).
  rg -No --glob '*.c' \
    'SEC\("[^"]+"\)[[:space:]]*\n[[:space:]]*int[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*\(' \
    -U -r '$1' "$ROOT/apps/agent-ebpf-sensor" || true

  # Rust eBPF maps: `static NAME:` (after #[map] — accept all static ALL_CAPS
  # map-like names in ebpf/src; exclude OFFSET globals via allowlist of known maps
  # by matching HashMap/Array/RingBuf typed statics).
  rg -No --glob '**/ebpf/src/**/*.rs' \
    'static[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*:[[:space:]]*(RingBuf|Array|HashMap)' \
    -r '$1' "$ROOT/apps/agent-ebpf-sensor" || true

  # Rust eBPF LSM entry: `pub fn NAME(` under #[lsm(...)]
  rg -No --glob '**/ebpf/src/**/*.rs' \
    '#\[lsm[^\]]*\][[:space:]]*\n[[:space:]]*pub[[:space:]]+fn[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)' \
    -U -r '$1' "$ROOT/apps/agent-ebpf-sensor" || true

  # Central string constants in neuromesh-common (bpf_obj_name("…") / MAP/PROG).
  rg -No --glob '**/neuromesh-common/src/lib.rs' \
    'bpf_obj_name\("([A-Za-z_][A-Za-z0-9_]*)"\)' \
    -r '$1' "$ROOT/packages" || true
}

collect | sort -u >"$TMP"

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

# Required names that must appear (guards against accidental rename drift /
# scanner missing a source).
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
  nm_tcp_connect
)
for want in "${required[@]}"; do
  if ! grep -qxF "$want" "$TMP"; then
    echo "FAIL: expected BPF object name '$want' not found in scan" >&2
    fail=1
  fi
done

# Forbid known over-length legacy names if they reappear.
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
