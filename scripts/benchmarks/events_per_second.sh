#!/usr/bin/env bash
# Micro-benchmark gate for Fast Path detection throughput (events/sec).
set -euo pipefail

readonly BASELINE_EPS="${NEUROMESH_PERF_BASELINE_EPS:-100000}"
readonly REGRESSION_PCT="${NEUROMESH_PERF_REGRESSION_PCT:-5}"
readonly MIN_EPS=$((BASELINE_EPS * (100 - REGRESSION_PCT) / 100))
readonly BENCH_OUTPUT="$(mktemp)"

log() {
  printf '[perf-regression] %s\n' "$*"
}

cleanup() {
  rm -f "${BENCH_OUTPUT}"
}
trap cleanup EXIT

log "Running detection_pipeline benchmark (release)..."
cargo bench -p agent-ebpf-sensor --bench detection_pipeline -- --noplot 2>&1 | tee "${BENCH_OUTPUT}"

read -r EPS UNIT <<<"$(python3 - "${BENCH_OUTPUT}" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text()

match = re.search(
    r"rule_engine/evaluate_10k_benign_paths.*?thrpt:\s*\[([^\]]+)\]",
    text,
    re.S,
)
if not match:
    raise SystemExit("unable to locate rule_engine/evaluate_10k_benign_paths throughput")

parts = match.group(1).split()
if len(parts) < 4:
    raise SystemExit(f"unexpected thrpt format: {match.group(1)!r}")

median_value = float(parts[1])
median_unit = parts[2]

multipliers = {
    "elem/s": 1.0,
    "Kelem/s": 1_000.0,
    "Melem/s": 1_000_000.0,
    "Gelem/s": 1_000_000_000.0,
}
if median_unit not in multipliers:
    raise SystemExit(f"unsupported throughput unit: {median_unit}")

eps = int(median_value * multipliers[median_unit])
print(eps, median_unit)
PY
)"

log "Measured throughput: ${EPS} events/sec (from benchmark median ${UNIT})"
log "Baseline: ${BASELINE_EPS} eps | floor (${REGRESSION_PCT}% regression): ${MIN_EPS} eps"

if [[ "${EPS}" -lt "${MIN_EPS}" ]]; then
  log "ERROR: performance regression detected (${EPS} < ${MIN_EPS})"
  exit 1
fi

log "Performance gate passed."
