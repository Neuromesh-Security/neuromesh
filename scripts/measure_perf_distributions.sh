#!/usr/bin/env bash
# Statistical distributions for identity invalidation latency + execve EPS.
#
# Wraps EXISTING measurement mechanisms — does not reimplement timing logic:
#   - Identity: scripts/manual_verify_identity_2bii_correlation.sh
#     (parses MEASURED_INSERT_LATENCY_MS / MEASURED_DELETE_INVALIDATION_LATENCY_MS /
#      MEASURED_REVOKE_LATENCY_MS from each full trial stdout)
#   - EPS: EXECVE_STRESS_TIER=standard cargo test … standard_tier
#     (parses average_eps from "[execve-stress] complete …" lines)
#
# Defaults (override with env):
#   PERF_DIST_IDENTITY_N=15
#   PERF_DIST_EPS_N=30
#   PERF_DIST_MODE=all|identity|eps
#   PERF_DIST_OUT_DIR=/tmp/neuromesh-perf-dist-<ts>
#
# Honesty: with these N values, report min/p50/p90/max/mean. Do NOT treat
# empirical "p99" as meaningful — see docs/performance-baseline.md §2.3.3.
#
# Usage (droplet, root for identity):
#   sudo -E bash scripts/measure_perf_distributions.sh
#   sudo -E PERF_DIST_MODE=identity bash scripts/measure_perf_distributions.sh
#   PERF_DIST_MODE=eps bash scripts/measure_perf_distributions.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

IDENTITY_N="${PERF_DIST_IDENTITY_N:-15}"
EPS_N="${PERF_DIST_EPS_N:-30}"
MODE="${PERF_DIST_MODE:-all}"
OUT_DIR="${PERF_DIST_OUT_DIR:-/tmp/neuromesh-perf-dist-$(date +%Y%m%dT%H%M%S)}"
IDENTITY_SCRIPT="${PERF_DIST_IDENTITY_SCRIPT:-$ROOT/scripts/manual_verify_identity_2bii_correlation.sh}"
AGENT_BIN="${AGENT_BIN:-$ROOT/target/release/agent-ebpf-sensor}"
SETTLE_SECS="${PERF_DIST_SETTLE_SECS:-3}"

mkdir -p "$OUT_DIR"
SUMMARY_JSON="$OUT_DIR/summary.json"
SUMMARY_MD="$OUT_DIR/summary.md"
RAW_DIR="$OUT_DIR/raw"
mkdir -p "$RAW_DIR"

WALL_START_NS="$(date +%s%N)"

fail() { echo "FAIL: $*" >&2; exit 1; }
info() { echo; echo "== $* =="; }

command -v python3 >/dev/null || fail "python3 required"
[[ "$IDENTITY_N" =~ ^[0-9]+$ && "$IDENTITY_N" -ge 1 ]] || fail "PERF_DIST_IDENTITY_N must be >=1"
[[ "$EPS_N" =~ ^[0-9]+$ && "$EPS_N" -ge 1 ]] || fail "PERF_DIST_EPS_N must be >=1"

case "$MODE" in
  all|identity|eps) ;;
  *) fail "PERF_DIST_MODE must be all|identity|eps (got '$MODE')" ;;
esac

compute_stats() {
  # stdin: one float per line; argv1: metric name; argv2: sample count expected
  python3 - "$1" "$2" <<'PY'
import math, sys
name, n_expected = sys.argv[1], int(sys.argv[2])
vals = []
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    vals.append(float(line))
vals.sort()
n = len(vals)
if n == 0:
    print(f"EMPTY metric={name}", file=sys.stderr)
    sys.exit(2)

def percentile(p: float) -> float:
    """Linear interpolation (inclusive) — same class as numpy percentile(method='linear')."""
    if n == 1:
        return vals[0]
    rank = (p / 100.0) * (n - 1)
    lo = int(math.floor(rank))
    hi = int(math.ceil(rank))
    if lo == hi:
        return vals[lo]
    w = rank - lo
    return vals[lo] * (1 - w) + vals[hi] * w

mean = sum(vals) / n
p50 = percentile(50)
p90 = percentile(90)
p99_raw = percentile(99)
# Fortune-500 honesty: p99 needs ~100 independent samples for a non-degenerate estimate.
p99_ok = n >= 100
out = {
    "metric": name,
    "n": n,
    "n_expected": n_expected,
    "min": vals[0],
    "p50": p50,
    "p90": p90,
    "p99": p99_raw if p99_ok else None,
    "p99_status": "ok" if p99_ok else "insufficient_sample_size",
    "max": vals[-1],
    "mean": mean,
    "samples": vals,
}
import json
print(json.dumps(out))
PY
}

run_identity() {
  info "identity distribution N=${IDENTITY_N} (wraps manual_verify_identity_2bii_correlation.sh)"
  test "$(id -u)" -eq 0 || fail "identity mode requires root (same as 2b-ii-C script)"
  test -x "$IDENTITY_SCRIPT" || fail "missing $IDENTITY_SCRIPT"
  test -x "$AGENT_BIN" || fail "AGENT_BIN not executable: $AGENT_BIN (build release agent first)"

  : >"$RAW_DIR/identity_insert_ms.txt"
  : >"$RAW_DIR/identity_delete_ms.txt"
  : >"$RAW_DIR/identity_revoke_ms.txt"
  : >"$RAW_DIR/identity_delete_winner.txt"

  local i trial_log rc
  for i in $(seq 1 "$IDENTITY_N"); do
    trial_log="$RAW_DIR/identity_trial_${i}.log"
    echo "---- identity trial ${i}/${IDENTITY_N} ----"
    # Unique pod name per trial avoids delete races if a prior wait hung.
    export NEUROMESH_2BIIC_POD_NAME="nm-2biic-dist-${i}"
    set +e
    bash "$IDENTITY_SCRIPT" >"$trial_log" 2>&1
    rc=$?
    set -e
    if [[ "$rc" -ne 0 ]]; then
      echo "WARN: identity trial ${i} exit=${rc} — capturing partial metrics if any" >&2
      tail -n 40 "$trial_log" >&2 || true
    fi
    python3 - "$trial_log" "$RAW_DIR" "$i" <<'PY' || fail "failed to parse identity trial $i"
import re, sys
path, raw, i = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path, errors="replace").read()
def grab(key):
    m = re.search(rf"^{re.escape(key)}=([0-9]+(?:\.[0-9]+)?)\s*$", text, re.M)
    return m.group(1) if m else None
ins, dele, rev = grab("MEASURED_INSERT_LATENCY_MS"), grab("MEASURED_DELETE_INVALIDATION_LATENCY_MS"), grab("MEASURED_REVOKE_LATENCY_MS")
win = None
m = re.search(r"^DELETE_INVALIDATION_PATH_WINNER=(\S+)\s*$", text, re.M)
if m:
    win = m.group(1)
missing = [k for k, v in [("insert", ins), ("delete", dele), ("revoke", rev)] if v is None]
if missing:
    raise SystemExit(f"trial {i} missing keys: {missing}")
open(f"{raw}/identity_insert_ms.txt", "a").write(ins + "\n")
open(f"{raw}/identity_delete_ms.txt", "a").write(dele + "\n")
open(f"{raw}/identity_revoke_ms.txt", "a").write(rev + "\n")
if win:
    open(f"{raw}/identity_delete_winner.txt", "a").write(f"{i}:{win}\n")
print(f"trial {i}: insert={ins}ms delete={dele}ms revoke={rev}ms winner={win}")
PY
    sleep "$SETTLE_SECS"
  done
}

run_eps() {
  info "EPS distribution N=${EPS_N} (wraps EXECVE_STRESS_TIER=standard standard_tier)"
  command -v cargo >/dev/null || fail "cargo required"

  : >"$RAW_DIR/eps_average.txt"
  local i trial_log rc
  for i in $(seq 1 "$EPS_N"); do
    trial_log="$RAW_DIR/eps_trial_${i}.log"
    echo "---- eps trial ${i}/${EPS_N} ----"
    set +e
    env EXECVE_STRESS_TIER=standard \
      cargo test -p agent-ebpf-sensor --test execve_stress_test standard_tier \
      -- --ignored --nocapture >"$trial_log" 2>&1
    rc=$?
    set -e
    if [[ "$rc" -ne 0 ]]; then
      echo "WARN: eps trial ${i} exit=${rc}" >&2
      tail -n 40 "$trial_log" >&2 || true
      fail "eps trial ${i} failed (exit ${rc})"
    fi
    python3 - "$trial_log" "$RAW_DIR" "$i" <<'PY' || fail "failed to parse eps trial $i"
import re, sys
path, raw, i = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path, errors="replace").read()
# [execve-stress] complete spawned=24860 failed=0 elapsed=30.48s average_eps=816 target_eps=100000 workers=128
m = re.search(r"\[execve-stress\] complete\b.*?average_eps=([0-9]+(?:\.[0-9]+)?)", text)
if not m:
    raise SystemExit(f"trial {i}: no average_eps in log")
eps = m.group(1)
open(f"{raw}/eps_average.txt", "a").write(eps + "\n")
print(f"trial {i}: average_eps={eps}")
PY
    sleep "$SETTLE_SECS"
  done
}

RESULTS_JSONL="$RAW_DIR/stats.jsonl"
: >"$RESULTS_JSONL"

if [[ "$MODE" == "all" || "$MODE" == "identity" ]]; then
  run_identity
  compute_stats identity_insert_latency_ms "$IDENTITY_N" <"$RAW_DIR/identity_insert_ms.txt" | tee -a "$RESULTS_JSONL"
  compute_stats identity_delete_invalidation_latency_ms "$IDENTITY_N" <"$RAW_DIR/identity_delete_ms.txt" | tee -a "$RESULTS_JSONL"
  compute_stats identity_revoke_latency_ms "$IDENTITY_N" <"$RAW_DIR/identity_revoke_ms.txt" | tee -a "$RESULTS_JSONL"
fi

if [[ "$MODE" == "all" || "$MODE" == "eps" ]]; then
  run_eps
  compute_stats execve_standard_average_eps "$EPS_N" <"$RAW_DIR/eps_average.txt" | tee -a "$RESULTS_JSONL"
fi

WALL_END_NS="$(date +%s%N)"
WALL_SECS="$(python3 -c "print(f'{(int('$WALL_END_NS')-int('$WALL_START_NS'))/1e9:.1f}')")"

python3 - "$RESULTS_JSONL" "$SUMMARY_JSON" "$SUMMARY_MD" "$WALL_SECS" "$OUT_DIR" "$IDENTITY_N" "$EPS_N" "$MODE" <<'PY'
import json, sys
from pathlib import Path
src, sj, sm, wall, out_dir, id_n, eps_n, mode = sys.argv[1:9]
rows = []
for line in Path(src).read_text().splitlines():
    if line.strip():
        rows.append(json.loads(line))
summary = {
    "mode": mode,
    "identity_n": int(id_n),
    "eps_n": int(eps_n),
    "wall_clock_secs": float(wall),
    "out_dir": out_dir,
    "metrics": rows,
    "notes": [
        "single-node only; multi-node distribution out of scope",
        "p99 omitted unless n>=100 (insufficient_sample_size)",
        "identity timings reuse manual_verify_identity_2bii_correlation.sh",
        "eps timings reuse EXECVE_STRESS_TIER=standard standard_tier",
    ],
}
Path(sj).write_text(json.dumps(summary, indent=2) + "\n")
lines = [
    "# Neuromesh perf distribution summary",
    "",
    f"- mode: `{mode}`",
    f"- identity N: **{id_n}**",
    f"- EPS N: **{eps_n}**",
    f"- wall-clock: **{wall}s**",
    f"- out_dir: `{out_dir}`",
    "",
    "| Metric | n | min | p50 | p90 | p99 | max | mean |",
    "|--------|---|-----|-----|-----|-----|-----|------|",
]
for r in rows:
    p99 = r["p99"]
    p99_s = f"{p99:.3f}" if p99 is not None else "insufficient N"
    lines.append(
        f"| `{r['metric']}` | {r['n']} | {r['min']:.3f} | {r['p50']:.3f} | {r['p90']:.3f} | {p99_s} | {r['max']:.3f} | {r['mean']:.3f} |"
    )
lines += [
    "",
    "p99 column: only populated when n≥100; otherwise marked insufficient.",
    "Envelope: **single-node**; multi-node would differ.",
    "",
]
Path(sm).write_text("\n".join(lines))
print(Path(sm).read_text())
print(f"SUMMARY_JSON={sj}")
print(f"SUMMARY_MD={sm}")
print(f"WALL_CLOCK_SECS={wall}")
PY

echo "DONE: samples written under $OUT_DIR"
