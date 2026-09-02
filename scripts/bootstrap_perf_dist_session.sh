#!/usr/bin/env bash
# One-shot bootstrap for measure_perf_distributions.sh on the neuromesh-dev-lab droplet.
#
# Prepares attestation, builds the agent if needed, cleans stale lab state, and
# starts (or reuses) tmux session "perfdist" running the measurement harness.
#
# Usage (as root, one command):
#   bash /root/neuromesh/scripts/bootstrap_perf_dist_session.sh
#
# Optional overrides (export before running):
#   COSIGN_PASSWORD          — required non-interactive password for operator key
#   PERF_DIST_LOG            — default /tmp/perf-dist-run.log
#   PERF_DIST_BOOTSTRAP_ATT  — default /opt/neuromesh-host-attest
#
# Stdout: exactly one reconnect line on success. All diagnostics go to stderr.
set -euo pipefail

REPO="/root/neuromesh"
ATT="${PERF_DIST_BOOTSTRAP_ATT:-/opt/neuromesh-host-attest}"
SESSION="perfdist"
LOG="${PERF_DIST_LOG:-/tmp/perf-dist-run.log}"
COSIGN_BIN="${COSIGN_BIN:-/usr/local/bin/cosign}"
COSIGN_VERSION="${COSIGN_VERSION:-2.4.3}"

OPERATOR_KEY="${ATT}/operator.key"
OPERATOR_PUB="${ATT}/operator.pub"
MANIFEST="${ATT}/bytecode-manifest.json"
MANIFEST_SIG="${ATT}/bytecode-manifest.sig"
SESSION_ENV="${ATT}/perfdist-session.env"

AGENT_BIN="${REPO}/target/release/agent-ebpf-sensor"
SYS_EXEC="${REPO}/apps/agent-ebpf-sensor/target/bpf/sys_exec.bpf.o"
NET_FILTER="${REPO}/apps/agent-ebpf-sensor/target/bpf/network_filter.bpf.o"
ENFORCEMENT="${REPO}/apps/agent-ebpf-sensor/ebpf/target/bpfel-unknown-none/release/agent-ebpf-sensor-ebpf"

BPF_PIN_ROOT="/sys/fs/bpf/neuromesh"
KUBECONFIG="/etc/rancher/k3s/k3s.yaml"
K8S_CA="/var/lib/rancher/k3s/server/tls/server-ca.crt"
SIGNED_POD_IMAGE="ghcr.io/neuromesh-security/neuromesh-agent-ebpf-sensor@sha256:413424ce5ec990e97b58014daa05ae8addab27de5afcac74904eb28fdcd5de2d"

log() { echo "bootstrap: $*" >&2; }
die() { echo "bootstrap: ERROR: $*" >&2; exit 1; }

finish() {
  echo "Session started. Reconnect anytime with: tmux attach -t ${SESSION}"
}

require_root() {
  [[ "$(id -u)" -eq 0 ]] || die "must run as root (uid=$(id -u))"
}

cd_repo() {
  [[ -d "$REPO" ]] || die "repo missing at $REPO"
  cd "$REPO" || die "cannot cd to $REPO"
  log "cd $REPO"
}

setup_path() {
  local cargo_bin="/root/.cargo/bin"
  export PATH="${cargo_bin}:/usr/local/bin:/usr/bin:/bin:${PATH:-}"
}

ensure_cosign() {
  if [[ -x "$COSIGN_BIN" ]]; then
    return 0
  fi
  log "installing cosign ${COSIGN_VERSION} to ${COSIGN_BIN}"
  curl -fsSL \
    "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64" \
    -o "$COSIGN_BIN"
  chmod +x "$COSIGN_BIN"
}

ensure_tmux() {
  if command -v tmux >/dev/null 2>&1; then
    return 0
  fi
  log "installing tmux"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq tmux
  command -v tmux >/dev/null || die "tmux install failed"
}

ensure_rust_toolchain() {
  if ! command -v cargo >/dev/null 2>&1; then
    die "cargo not on PATH (expected /root/.cargo/bin) — install rustup for root first"
  fi
  if ! rustup toolchain list 2>/dev/null | grep -q 'nightly-2026-07-17'; then
    log "installing pinned nightly toolchain"
    rustup toolchain install nightly-2026-07-17 --component rust-src
  fi
  if ! command -v bpf-linker >/dev/null 2>&1; then
    log "installing bpf-linker 0.10.4"
    cargo install bpf-linker --version 0.10.4 --locked
  fi
}

build_agent_if_missing() {
  if [[ -x "$AGENT_BIN" \
     && -f "$SYS_EXEC" \
     && -f "$NET_FILTER" \
     && -f "$ENFORCEMENT" ]]; then
    log "agent binary and BPF artifacts present — skip build"
    return 0
  fi
  log "building agent (orchestrator + eBPF bytecode)"
  ensure_rust_toolchain
  cargo +nightly-2026-07-17 build --package agent-ebpf-sensor-ebpf \
    --manifest-path "${REPO}/apps/agent-ebpf-sensor/ebpf/Cargo.toml" \
    --target bpfel-unknown-none -Z build-std=core --release
  cargo build -p agent-ebpf-sensor --features orchestrator --release
  [[ -x "$AGENT_BIN" ]] || die "build finished but $AGENT_BIN missing or not executable"
  chmod +x "$AGENT_BIN" 2>/dev/null || true
}

manifest_matches_artifacts() {
  local tmp
  tmp="$(mktemp)"
  bash "${REPO}/scripts/ci/generate_bytecode_manifest.sh" \
    --sys-exec "$SYS_EXEC" \
    --network-filter "$NET_FILTER" \
    --enforcement "$ENFORCEMENT" \
    --git-sha "$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo unknown)" \
    --out "$tmp"
  if [[ -f "$MANIFEST" ]] && cmp -s "$tmp" "$MANIFEST"; then
    rm -f "$tmp"
    return 0
  fi
  rm -f "$tmp"
  return 1
}

verify_attestation_blob() {
  [[ -s "$OPERATOR_PUB" && -s "$MANIFEST" && -s "$MANIFEST_SIG" ]] || return 1
  "$COSIGN_BIN" verify-blob \
    --key "$OPERATOR_PUB" \
    --signature "$MANIFEST_SIG" \
    "$MANIFEST" >/dev/null 2>&1
}

attestation_valid() {
  [[ -s "$OPERATOR_KEY" ]] || return 1
  verify_attestation_blob || return 1
  manifest_matches_artifacts || return 1
  return 0
}

ensure_operator_keypair() {
  mkdir -p "$ATT"
  chmod 700 "$ATT"
  if [[ -s "$OPERATOR_KEY" && -s "$OPERATOR_PUB" ]]; then
    log "reusing operator Cosign keypair"
    return 0
  fi
  log "generating operator Cosign keypair"
  export COSIGN_PASSWORD="${COSIGN_PASSWORD:-neuromesh-perf-dist-operator-lab}"
  rm -f "$OPERATOR_KEY" "$OPERATOR_PUB"
  "$COSIGN_BIN" generate-key-pair --output-key-prefix "${ATT}/operator"
  chmod 600 "$OPERATOR_KEY"
  chmod 644 "$OPERATOR_PUB"
}

regenerate_attestation() {
  ensure_operator_keypair
  export COSIGN_PASSWORD="${COSIGN_PASSWORD:-neuromesh-perf-dist-operator-lab}"
  log "writing bytecode manifest"
  bash "${REPO}/scripts/ci/generate_bytecode_manifest.sh" \
    --sys-exec "$SYS_EXEC" \
    --network-filter "$NET_FILTER" \
    --enforcement "$ENFORCEMENT" \
    --git-sha "$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo unknown)" \
    --out "$MANIFEST"
  log "signing bytecode manifest"
  "$COSIGN_BIN" sign-blob \
    --key "$OPERATOR_KEY" \
    --yes \
    --tlog-upload=false \
    --output-signature "$MANIFEST_SIG" \
    "$MANIFEST"
  verify_attestation_blob || die "cosign verify-blob failed immediately after sign"
  log "attestation ready at $ATT"
}

ensure_attestation() {
  mkdir -p "$ATT"
  chmod 700 "$ATT"
  if attestation_valid; then
    log "reusing valid operator attestation"
    return 0
  fi
  log "attestation missing, stale, or invalid — regenerating"
  regenerate_attestation
}

resolve_node_name() {
  [[ -f "$KUBECONFIG" ]] || die "KUBECONFIG missing: $KUBECONFIG"
  local node
  node="$(kubectl --kubeconfig="$KUBECONFIG" get nodes -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  [[ -n "$node" ]] || die "kubectl could not read node name — is k3s running?"
  echo "$node"
}

cleanup_stale_lab_state() {
  log "cleaning stale agent / stubs / pods / pins"

  if pgrep -x agent-ebpf-sensor >/dev/null 2>&1; then
    pkill -TERM -x agent-ebpf-sensor 2>/dev/null || true
    sleep 1
    pkill -KILL -x agent-ebpf-sensor 2>/dev/null || true
  fi

  pkill -f 'stub_pe_2biic.py' 2>/dev/null || true
  pkill -f 'signed_bundle_stub.py' 2>/dev/null || true
  if command -v fuser >/dev/null 2>&1; then
    fuser -k 18082/tcp 2>/dev/null || true
  fi

  if command -v kubectl >/dev/null 2>&1 && [[ -f "$KUBECONFIG" ]]; then
    kubectl --kubeconfig="$KUBECONFIG" delete pod -A -l neuromesh.io/slice=2b-ii-C \
      --ignore-not-found --wait=false >/dev/null 2>&1 || true
    kubectl --kubeconfig="$KUBECONFIG" get pods -A -o json 2>/dev/null \
      | python3 -c '
import json, subprocess, sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for it in data.get("items", []):
    name = it["metadata"]["name"]
    ns = it["metadata"]["namespace"]
    if name.startswith("nm-2biic-") or name.startswith("nm-2biic-dist-"):
        subprocess.run(
            ["kubectl", "--kubeconfig", sys.argv[1], "-n", ns, "delete", "pod", name,
             "--ignore-not-found", "--wait=false"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
' "$KUBECONFIG" || true
  fi

  if [[ -d "$BPF_PIN_ROOT" ]]; then
    find "$BPF_PIN_ROOT" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true
  fi
}

write_session_env() {
  local node_name
  node_name="$(resolve_node_name)"
  mkdir -p "$ATT"
  cat >"$SESSION_ENV" <<EOF
# Generated by bootstrap_perf_dist_session.sh — sourced by tmux session ${SESSION}
export PATH="/root/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
export REPO="${REPO}"
export AGENT_BIN="${AGENT_BIN}"
export NEUROMESH_COSIGN_PUBLIC_KEY_PATH="${OPERATOR_PUB}"
export NEUROMESH_BYTECODE_MANIFEST_PATH="${MANIFEST}"
export NEUROMESH_BYTECODE_MANIFEST_SIG_PATH="${MANIFEST_SIG}"
export NEUROMESH_BPF_PIN_ROOT="${BPF_PIN_ROOT}"
export NEUROMESH_IDENTITY_TEST_ROOT="/opt/neuromesh-test-2biic"
export NEUROMESH_IDENTITY_TEST_PE_PORT="18082"
export NEUROMESH_K8S_API_URL="https://127.0.0.1:6443"
export NEUROMESH_K8S_CA_FILE="${K8S_CA}"
export NEUROMESH_2BIIC_POD_IMAGE="${SIGNED_POD_IMAGE}"
export KUBECONFIG="${KUBECONFIG}"
export NEUROMESH_NODE_NAME="${node_name}"
unset NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS
EOF
  chmod 600 "$SESSION_ENV"
  log "wrote ${SESSION_ENV} (NEUROMESH_NODE_NAME=${node_name})"
}

write_launcher() {
  local launcher="${ATT}/run-perf-dist.sh"
  cat >"$launcher" <<EOF
#!/usr/bin/env bash
set -euo pipefail
set -a
source "${SESSION_ENV}"
set +a
cd "${REPO}"
exec bash scripts/measure_perf_distributions.sh 2>&1 | tee -a "${LOG}"
EOF
  chmod 700 "$launcher"
  log "wrote ${launcher}"
}

measurement_running() {
  pgrep -f '[m]easure_perf_distributions\.sh' >/dev/null 2>&1
}

start_tmux_session() {
  if measurement_running; then
    log "measure_perf_distributions.sh already running — not starting a duplicate"
    if ! tmux has-session -t "$SESSION" 2>/dev/null; then
      log "note: measurement is running outside tmux session ${SESSION}"
    fi
    return 0
  fi

  if tmux has-session -t "$SESSION" 2>/dev/null; then
    log "tmux session ${SESSION} exists but measurement not running — replacing session"
    tmux kill-session -t "$SESSION" 2>/dev/null || true
  fi

  tmux new-session -d -s "$SESSION" "${ATT}/run-perf-dist.sh"
  sleep 1
  tmux has-session -t "$SESSION" 2>/dev/null || die "failed to create tmux session ${SESSION}"
  log "started tmux session ${SESSION} (log ${LOG})"
}

main() {
  require_root
  setup_path
  cd_repo
  ensure_cosign
  ensure_tmux
  build_agent_if_missing
  ensure_attestation
  cleanup_stale_lab_state
  write_session_env
  write_launcher
  start_tmux_session
  finish
}

main "$@"
