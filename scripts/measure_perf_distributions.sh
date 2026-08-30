#!/usr/bin/env bash
# Statistical distributions for identity invalidation latency + execve EPS.
#
# Wraps EXISTING measurement mechanisms — does not reimplement timing logic:
#   - Identity: scripts/manual_verify_identity_2bii_correlation.sh
#   - EPS: EXECVE_STRESS_TIER=standard cargo test … standard_tier
#
# Defaults (override with env):
#   PERF_DIST_IDENTITY_N=15
#   PERF_DIST_EPS_N=30
#   PERF_DIST_MODE=all|identity|eps
#   PERF_DIST_OUT_DIR=/tmp/neuromesh-perf-dist-<ts>
#   AGENT_BIN — absolute path preferred; default <repo>/target/release/agent-ebpf-sensor
#   NEUROMESH_COSIGN_PUBLIC_KEY_PATH / BYTECODE_MANIFEST{,_SIG}_PATH — see preflight
#   NEUROMESH_2BIIC_POD_IMAGE — required if neuromesh-validate-pods VWC is installed
#   NEUROMESH_NODE_NAME — auto-detected from kubectl if unset/wrong
#
# Usage (droplet, root for identity):
#   sudo -E bash scripts/measure_perf_distributions.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

IDENTITY_N="${PERF_DIST_IDENTITY_N:-15}"
EPS_N="${PERF_DIST_EPS_N:-30}"
MODE="${PERF_DIST_MODE:-all}"
OUT_DIR="${PERF_DIST_OUT_DIR:-/tmp/neuromesh-perf-dist-$(date +%Y%m%dT%H%M%S)}"
IDENTITY_SCRIPT="${PERF_DIST_IDENTITY_SCRIPT:-$ROOT/scripts/manual_verify_identity_2bii_correlation.sh}"
SETTLE_SECS="${PERF_DIST_SETTLE_SECS:-3}"
PIN_ROOT="${NEUROMESH_BPF_PIN_ROOT:-/sys/fs/bpf/neuromesh}"
PE_PORT="${NEUROMESH_IDENTITY_TEST_PE_PORT:-18082}"
CI_COSIGN_PUB="$ROOT/deploy/kubernetes/ci-cosign.pub"
RBAC_YAML="$ROOT/deploy/kubernetes/neuromesh-agent-correlator-rbac.yaml"
DEFAULT_COSIGN_PUB="/etc/neuromesh/cosign/cosign.pub"
DEFAULT_MANIFEST="/etc/neuromesh/bytecode-manifest.json"
DEFAULT_MANIFEST_SIG="/etc/neuromesh/bytecode-manifest.sig"

mkdir -p "$OUT_DIR"
SUMMARY_JSON="$OUT_DIR/summary.json"
SUMMARY_MD="$OUT_DIR/summary.md"
RAW_DIR="$OUT_DIR/raw"
mkdir -p "$RAW_DIR"

WALL_START_NS="$(date +%s%N)"

fail() {
  echo "FAIL: $*" >&2
  echo "FAIL_HINT: OUT_DIR=$OUT_DIR (trial logs under $RAW_DIR if any)" >&2
  exit 1
}
info() { echo; echo "== $* =="; }
warn() { echo "WARN: $*" >&2; }

# ---------------------------------------------------------------------------
# Lab residue cleanup — identity leaves agent/stub/pods/pins; EPS must not
# inherit a live agent or port conflicts (state bleeding class).
# ---------------------------------------------------------------------------
kill_matching_pids() {
  local pattern="$1"
  local pids
  pids="$(pgrep -f "$pattern" 2>/dev/null || true)"
  if [[ -z "$pids" ]]; then
    return 0
  fi
  # shellcheck disable=SC2086
  kill -TERM $pids 2>/dev/null || true
  sleep 1
  # shellcheck disable=SC2086
  kill -KILL $pids 2>/dev/null || true
}

cleanup_lab_residue() {
  local reason="$1"
  info "cleanup_lab_residue ($reason)"

  # Host agent binary name from release builds.
  if pgrep -x agent-ebpf-sensor >/dev/null 2>&1; then
    warn "killing leftover agent-ebpf-sensor process(es)"
    pkill -TERM -x agent-ebpf-sensor 2>/dev/null || true
    sleep 1
    pkill -KILL -x agent-ebpf-sensor 2>/dev/null || true
  fi

  # PE stubs from 2b-ii / other harnesses (python on PE_PORT).
  kill_matching_pids "stub_pe_2biic.py"
  kill_matching_pids "signed_bundle_stub.py"
  if command -v fuser >/dev/null 2>&1; then
    fuser -k "${PE_PORT}/tcp" 2>/dev/null || true
  fi

  if command -v kubectl >/dev/null 2>&1 && [[ -n "${KUBECONFIG:-}" || -f /etc/rancher/k3s/k3s.yaml ]]; then
    export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
    kubectl delete pod -A -l neuromesh.io/slice=2b-ii-C --ignore-not-found --wait=false >/dev/null 2>&1 || true
    # Also catch unique nm-2biic-dist-* names if label missing on a hung apply.
    kubectl get pods -A -o json 2>/dev/null \
      | python3 -c '
import json,sys,subprocess
try:
  data=json.load(sys.stdin)
except Exception:
  sys.exit(0)
for it in data.get("items",[]):
  name=it["metadata"]["name"]
  ns=it["metadata"]["namespace"]
  if name.startswith("nm-2biic-") or name.startswith("nm-2biic-dist-"):
    subprocess.run(["kubectl","-n",ns,"delete","pod",name,"--ignore-not-found","--wait=false"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
' || true
  fi

  # Do NOT rm BPF pins here: LSM pins are designed to survive agent exit.
  # Next identity trial reuses/resumes them; wiping mid-soak can weaken deny.
  echo "cleanup done (pins under $PIN_ROOT retained by design)"
}

resolve_agent_bin() {
  local cand="${AGENT_BIN:-$ROOT/target/release/agent-ebpf-sensor}"
  # Relative paths are relative to repo root (we already cd'd).
  if [[ "$cand" != /* ]]; then
    cand="$ROOT/${cand#./}"
  fi
  if [[ ! -e "$cand" ]]; then
    fail "AGENT_BIN does not exist: $cand — build with: cargo build -p agent-ebpf-sensor --release (from $ROOT)"
  fi
  if [[ ! -x "$cand" ]]; then
    fail "AGENT_BIN exists but is not executable: $cand (mode $(stat -c %a "$cand" 2>/dev/null || echo '?')) — chmod +x or rebuild"
  fi
  AGENT_BIN="$cand"
  export AGENT_BIN
  echo "AGENT_BIN=$AGENT_BIN"
}

resolve_attestation_paths() {
  # Bytecode Cosign material for host-agent runs (container defaults are /etc/neuromesh/…).
  if [[ -z "${NEUROMESH_COSIGN_PUBLIC_KEY_PATH:-}" ]]; then
    if [[ -s "$DEFAULT_COSIGN_PUB" ]]; then
      export NEUROMESH_COSIGN_PUBLIC_KEY_PATH="$DEFAULT_COSIGN_PUB"
      echo "NEUROMESH_COSIGN_PUBLIC_KEY_PATH defaulted to $DEFAULT_COSIGN_PUB"
    elif [[ -s "$CI_COSIGN_PUB" ]]; then
      export NEUROMESH_COSIGN_PUBLIC_KEY_PATH="$CI_COSIGN_PUB"
      warn "NEUROMESH_COSIGN_PUBLIC_KEY_PATH defaulted to repo ci-cosign.pub ($CI_COSIGN_PUB)"
      warn "bytecode-manifest.sig MUST be signed with the matching CI private key or attestation will fail-closed"
    else
      fail "NEUROMESH_COSIGN_PUBLIC_KEY_PATH is unset; also missing $DEFAULT_COSIGN_PUB and $CI_COSIGN_PUB — set the env var to the Cosign PEM used to sign bytecode-manifest.sig"
    fi
  fi
  if [[ ! -s "$NEUROMESH_COSIGN_PUBLIC_KEY_PATH" ]]; then
    fail "NEUROMESH_COSIGN_PUBLIC_KEY_PATH=$NEUROMESH_COSIGN_PUBLIC_KEY_PATH is missing or empty"
  fi
  # Refuse known lab attest key that does not verify CI-signed material.
  case "$NEUROMESH_COSIGN_PUBLIC_KEY_PATH" in
    *neuromesh-attest-lab*)
      fail "refusing lab attest Cosign key at $NEUROMESH_COSIGN_PUBLIC_KEY_PATH — use /etc/neuromesh/cosign/cosign.pub or $CI_COSIGN_PUB"
      ;;
  esac
  if [[ "$NEUROMESH_COSIGN_PUBLIC_KEY_PATH" == "$HOME/cosign.pub" \
     || "$NEUROMESH_COSIGN_PUBLIC_KEY_PATH" == "$HOME/neuromesh-attest-lab/cosign/cosign.pub" ]]; then
    fail "refusing lab attest Cosign key at $NEUROMESH_COSIGN_PUBLIC_KEY_PATH — use /etc/neuromesh/cosign/cosign.pub or $CI_COSIGN_PUB"
  fi

  if [[ -z "${NEUROMESH_BYTECODE_MANIFEST_PATH:-}" ]]; then
    if [[ -s "$DEFAULT_MANIFEST" ]]; then
      export NEUROMESH_BYTECODE_MANIFEST_PATH="$DEFAULT_MANIFEST"
    else
      fail "NEUROMESH_BYTECODE_MANIFEST_PATH unset and $DEFAULT_MANIFEST missing — extract from agent image (docker cp …:/etc/neuromesh/bytecode-manifest.json) or set the env var"
    fi
  fi
  if [[ ! -s "$NEUROMESH_BYTECODE_MANIFEST_PATH" ]]; then
    fail "NEUROMESH_BYTECODE_MANIFEST_PATH=$NEUROMESH_BYTECODE_MANIFEST_PATH missing or empty"
  fi

  if [[ -z "${NEUROMESH_BYTECODE_MANIFEST_SIG_PATH:-}" ]]; then
    if [[ -s "$DEFAULT_MANIFEST_SIG" ]]; then
      export NEUROMESH_BYTECODE_MANIFEST_SIG_PATH="$DEFAULT_MANIFEST_SIG"
    else
      fail "NEUROMESH_BYTECODE_MANIFEST_SIG_PATH unset and $DEFAULT_MANIFEST_SIG missing — extract bytecode-manifest.sig from the agent image or set the env var"
    fi
  fi
  if [[ ! -s "$NEUROMESH_BYTECODE_MANIFEST_SIG_PATH" ]]; then
    fail "NEUROMESH_BYTECODE_MANIFEST_SIG_PATH=$NEUROMESH_BYTECODE_MANIFEST_SIG_PATH missing or empty"
  fi

  echo "attestation: pub=$NEUROMESH_COSIGN_PUBLIC_KEY_PATH"
  echo "attestation: manifest=$NEUROMESH_BYTECODE_MANIFEST_PATH"
  echo "attestation: sig=$NEUROMESH_BYTECODE_MANIFEST_SIG_PATH"
}

resolve_node_name() {
  export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
  if [[ ! -f "$KUBECONFIG" ]]; then
    fail "KUBECONFIG file missing: $KUBECONFIG (set KUBECONFIG to your kubeconfig path)"
  fi
  local actual
  actual="$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  if [[ -z "$actual" ]]; then
    fail "kubectl could not read node name (KUBECONFIG=$KUBECONFIG) — is k3s running?"
  fi
  if [[ -z "${NEUROMESH_NODE_NAME:-}" ]]; then
    export NEUROMESH_NODE_NAME="$actual"
    echo "NEUROMESH_NODE_NAME defaulted to kubectl node: $NEUROMESH_NODE_NAME"
  elif [[ "$NEUROMESH_NODE_NAME" != "$actual" ]]; then
    warn "NEUROMESH_NODE_NAME=$NEUROMESH_NODE_NAME does not match kubectl node=$actual — overriding to $actual (2b-ii pods use nodeName pinning)"
    export NEUROMESH_NODE_NAME="$actual"
  else
    echo "NEUROMESH_NODE_NAME=$NEUROMESH_NODE_NAME (matches kubectl)"
  fi
}

check_admission_webhook_vs_pod_image() {
  local vwc="neuromesh-validate-pods"
  if ! kubectl get validatingwebhookconfiguration "$vwc" >/dev/null 2>&1; then
    echo "admission: VWC $vwc not installed — default busybox:1.36 OK for 2b-ii pods"
    return 0
  fi
  # failurePolicy Ignore does NOT override an explicit DENY from a healthy webhook.
  local img="${NEUROMESH_2BIIC_POD_IMAGE:-busybox:1.36}"
  if [[ "$img" == "busybox:1.36" || "$img" == busybox* ]]; then
    if [[ "${PERF_DIST_ALLOW_UNSIGNED_POD_IMAGE:-0}" == "1" ]]; then
      warn "VWC $vwc is installed and NEUROMESH_2BIIC_POD_IMAGE=$img looks unsigned — PERF_DIST_ALLOW_UNSIGNED_POD_IMAGE=1 set; pods may stay Pending/Denied"
      return 0
    fi
    fail "ValidatingWebhookConfiguration $vwc is installed. 2b-ii creates pods with image '$img' which Cosign will DENY (Ignore only covers webhook transport failure, not explicit deny). Fix: export NEUROMESH_2BIIC_POD_IMAGE to a Cosign-signed image that provides /bin/sleep, or set PERF_DIST_ALLOW_UNSIGNED_POD_IMAGE=1 to override (not recommended)"
  fi
  export NEUROMESH_2BIIC_POD_IMAGE="$img"
  echo "admission: VWC present; using NEUROMESH_2BIIC_POD_IMAGE=$NEUROMESH_2BIIC_POD_IMAGE"
}

preflight() {
  info "preflight (mode=$MODE)"
  command -v python3 >/dev/null || fail "python3 not found on PATH"
  [[ "$IDENTITY_N" =~ ^[0-9]+$ && "$IDENTITY_N" -ge 1 ]] \
    || fail "PERF_DIST_IDENTITY_N must be a positive integer (got '$IDENTITY_N')"
  [[ "$EPS_N" =~ ^[0-9]+$ && "$EPS_N" -ge 1 ]] \
    || fail "PERF_DIST_EPS_N must be a positive integer (got '$EPS_N')"
  case "$MODE" in
    all|identity|eps) ;;
    *) fail "PERF_DIST_MODE must be all|identity|eps (got '$MODE')" ;;
  esac

  if [[ ! -f "$IDENTITY_SCRIPT" ]]; then
    fail "identity script missing: $IDENTITY_SCRIPT"
  fi
  # Prefer bash invocation over +x bit (droplet checkout may lack executable bit).
  if [[ ! -r "$IDENTITY_SCRIPT" ]]; then
    fail "identity script not readable: $IDENTITY_SCRIPT"
  fi
  if [[ ! -f "$RBAC_YAML" ]]; then
    fail "correlator RBAC manifest missing: $RBAC_YAML (required by 2b-ii scenario 1)"
  fi

  if [[ "$MODE" == "all" || "$MODE" == "identity" ]]; then
    test "$(id -u)" -eq 0 || fail "identity mode requires root (uid=$(id -u)); re-run: sudo -E bash $ROOT/scripts/measure_perf_distributions.sh"
    resolve_agent_bin
    resolve_attestation_paths
    resolve_node_name
    check_admission_webhook_vs_pod_image
    command -v bpftool >/dev/null || fail "bpftool not found on PATH (required by 2b-ii map checks)"
    command -v kubectl >/dev/null || fail "kubectl not found on PATH"
    test -f /sys/kernel/btf/vmlinux || fail "kernel BTF missing: /sys/kernel/btf/vmlinux"
    test -f /sys/fs/cgroup/cgroup.controllers || fail "cgroup v2 required: /sys/fs/cgroup/cgroup.controllers missing"
    python3 -c "import cryptography" >/dev/null 2>&1 \
      || fail "python3 'cryptography' package missing (2b-ii signs PE stub with Ed25519) — pip install cryptography"
  fi

  if [[ "$MODE" == "all" || "$MODE" == "eps" ]]; then
    if ! command -v cargo >/dev/null 2>&1; then
      fail "cargo not found on PATH (got PATH=$PATH). Under sudo, use sudo -E or export a root PATH that includes rustup (e.g. \$HOME/.cargo/bin)"
    fi
    echo "cargo=$(command -v cargo)"
  fi

  echo "ROOT=$ROOT"
  echo "OUT_DIR=$OUT_DIR"
  echo "IDENTITY_SCRIPT=$IDENTITY_SCRIPT"
  echo "PIN_ROOT=$PIN_ROOT"
  echo "PE_PORT=$PE_PORT"
}

compute_stats() {
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
    print(f"EMPTY metric={name} (expected n>={n_expected})", file=sys.stderr)
    sys.exit(2)

def percentile(p: float) -> float:
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

  : >"$RAW_DIR/identity_insert_ms.txt"
  : >"$RAW_DIR/identity_delete_ms.txt"
  : >"$RAW_DIR/identity_revoke_ms.txt"
  : >"$RAW_DIR/identity_delete_winner.txt"

  local i trial_log rc
  for i in $(seq 1 "$IDENTITY_N"); do
    cleanup_lab_residue "before identity trial ${i}/${IDENTITY_N}"
    trial_log="$RAW_DIR/identity_trial_${i}.log"
    echo "---- identity trial ${i}/${IDENTITY_N} ----"
    export NEUROMESH_2BIIC_POD_NAME="nm-2biic-dist-${i}"
    # Propagate attestation + node + image into the child (2b-ii reads these).
    set +e
    # shellcheck disable=SC2086
    env \
      AGENT_BIN="$AGENT_BIN" \
      NEUROMESH_BPF_PIN_ROOT="$PIN_ROOT" \
      NEUROMESH_NODE_NAME="$NEUROMESH_NODE_NAME" \
      NEUROMESH_COSIGN_PUBLIC_KEY_PATH="$NEUROMESH_COSIGN_PUBLIC_KEY_PATH" \
      NEUROMESH_BYTECODE_MANIFEST_PATH="$NEUROMESH_BYTECODE_MANIFEST_PATH" \
      NEUROMESH_BYTECODE_MANIFEST_SIG_PATH="$NEUROMESH_BYTECODE_MANIFEST_SIG_PATH" \
      NEUROMESH_2BIIC_POD_NAME="$NEUROMESH_2BIIC_POD_NAME" \
      NEUROMESH_2BIIC_POD_IMAGE="${NEUROMESH_2BIIC_POD_IMAGE:-busybox:1.36}" \
      KUBECONFIG="$KUBECONFIG" \
      bash "$IDENTITY_SCRIPT" >"$trial_log" 2>&1
    rc=$?
    set -e
    if [[ "$rc" -ne 0 ]]; then
      echo "---- identity trial ${i} FAILED exit=${rc}; last 80 lines of $trial_log ----" >&2
      tail -n 80 "$trial_log" >&2 || true
      cleanup_lab_residue "after failed identity trial ${i}"
      fail "identity trial ${i}/${IDENTITY_N} failed with exit=${rc}; full log: $trial_log"
    fi
    python3 - "$trial_log" "$RAW_DIR" "$i" <<'PY' || fail "identity trial $i: failed to parse MEASURED_* keys from $trial_log"
import re, sys
path, raw, i = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path, errors="replace").read()
def grab(key):
    m = re.search(rf"^{re.escape(key)}=([0-9]+(?:\.[0-9]+)?)\s*$", text, re.M)
    return m.group(1) if m else None
ins = grab("MEASURED_INSERT_LATENCY_MS")
dele = grab("MEASURED_DELETE_INVALIDATION_LATENCY_MS")
rev = grab("MEASURED_REVOKE_LATENCY_MS")
win = None
m = re.search(r"^DELETE_INVALIDATION_PATH_WINNER=(\S+)\s*$", text, re.M)
if m:
    win = m.group(1)
missing = [k for k, v in [("MEASURED_INSERT_LATENCY_MS", ins), ("MEASURED_DELETE_INVALIDATION_LATENCY_MS", dele), ("MEASURED_REVOKE_LATENCY_MS", rev)] if v is None]
if missing:
    raise SystemExit(f"trial {i} log {path} missing keys: {missing}")
open(f"{raw}/identity_insert_ms.txt", "a").write(ins + "\n")
open(f"{raw}/identity_delete_ms.txt", "a").write(dele + "\n")
open(f"{raw}/identity_revoke_ms.txt", "a").write(rev + "\n")
if win:
    open(f"{raw}/identity_delete_winner.txt", "a").write(f"{i}:{win}\n")
print(f"trial {i}: insert={ins}ms delete={dele}ms revoke={rev}ms winner={win}")
PY
    cleanup_lab_residue "after identity trial ${i}"
    sleep "$SETTLE_SECS"
  done
}

run_eps() {
  info "EPS distribution N=${EPS_N} (wraps EXECVE_STRESS_TIER=standard standard_tier)"
  cleanup_lab_residue "before EPS phase"

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
      echo "---- eps trial ${i} FAILED exit=${rc}; last 80 lines of $trial_log ----" >&2
      tail -n 80 "$trial_log" >&2 || true
      fail "eps trial ${i}/${EPS_N} failed with exit=${rc}; full log: $trial_log"
    fi
    python3 - "$trial_log" "$RAW_DIR" "$i" <<'PY' || fail "eps trial $i: no average_eps in $trial_log"
import re, sys
path, raw, i = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path, errors="replace").read()
m = re.search(r"\[execve-stress\] complete\b.*?average_eps=([0-9]+(?:\.[0-9]+)?)", text)
if not m:
    raise SystemExit(f"trial {i}: no '[execve-stress] complete … average_eps=' in {path}")
eps = m.group(1)
open(f"{raw}/eps_average.txt", "a").write(eps + "\n")
print(f"trial {i}: average_eps={eps}")
PY
    sleep "$SETTLE_SECS"
  done
}

# ---- main ----
preflight

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

cleanup_lab_residue "final"
echo "DONE: samples written under $OUT_DIR"
