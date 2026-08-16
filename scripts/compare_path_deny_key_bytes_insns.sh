#!/usr/bin/env bash
# Compare nm_lsm_bprm-related BPF instruction counts at KEY_BYTES=16 vs 32.
# Temporary local tool for the PATH_DENY_KEY_BYTES sprint — run in Docker/CI Linux.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMMON="$ROOT/packages/neuromesh-common/src/lib.rs"
EBPF_DIR="$ROOT/apps/agent-ebpf-sensor/ebpf"
export CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER="${CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER:-bpf-linker}"

count_insns() {
  local label="$1"
  local obj="$EBPF_DIR/target/bpfel-unknown-none/release/agent-ebpf-sensor-ebpf"
  llvm-objdump -d "$obj" > /tmp/nm_disasm.txt
  python3 - "$label" <<'PY'
import sys
from pathlib import Path
label = sys.argv[1]
text = Path("/tmp/nm_disasm.txt").read_text(errors="replace").splitlines()
sections = {}
cur = None
for line in text:
    if line.startswith("Disassembly of section"):
        cur = line.split()[-1].strip(":")
        sections[cur] = 0
        continue
    if cur is None:
        continue
    s = line.lstrip()
    if not s:
        continue
    first = s.split()[0]
    if first.endswith(":") and all(c in "0123456789abcdefABCDEF" for c in first[:-1]):
        sections[cur] = sections.get(cur, 0) + 1
total = sum(sections.values())
print(f"LABEL={label} TOTAL_INSNS={total}")
for k, v in sorted(sections.items(), key=lambda kv: -kv[1])[:25]:
    print(f"  {v:6d}  {k}")
PY
}

set_key_bytes() {
  local n="$1"
  python3 - "$COMMON" "$n" <<'PY'
from pathlib import Path
import re, sys
path, n = Path(sys.argv[1]), sys.argv[2]
text = path.read_text()
text2, count = re.subn(
    r"pub const PATH_DENY_KEY_BYTES: usize = \d+;",
    f"pub const PATH_DENY_KEY_BYTES: usize = {n};",
    text,
    count=1,
)
assert count == 1, count
path.write_text(text2)
print(f"set PATH_DENY_KEY_BYTES={n}")
PY
}

build_ebpf() {
  (
    cd "$EBPF_DIR"
    cargo +nightly-2026-07-17 build \
      --package agent-ebpf-sensor-ebpf \
      --target bpfel-unknown-none \
      -Z build-std=core \
      --release
  )
}

echo "== baseline 16 =="
set_key_bytes 16
build_ebpf
count_insns BASELINE_16 | tee /tmp/nm_insn_16.txt

echo "== headroom 32 =="
set_key_bytes 32
build_ebpf
count_insns HEADROOM_32 | tee /tmp/nm_insn_32.txt

echo "== delta =="
python3 <<'PY'
import re
from pathlib import Path
def total(p):
    m = re.search(r"TOTAL_INSNS=(\d+)", Path(p).read_text())
    return int(m.group(1))
a, b = total("/tmp/nm_insn_16.txt"), total("/tmp/nm_insn_32.txt")
print(f"BASELINE_16={a} HEADROOM_32={b} DELTA={b-a} ({(b-a)*100/a:.2f}%)")
# Kernel classic BPF complexity limit is 1e6; even unprivileged is far above these counts.
assert b < 100_000, b
assert abs(b - a) / a < 0.50, (a, b)  # expect modest growth, not a cliff
print("OK: insn growth modest and well under verifier complexity ceiling")
PY
