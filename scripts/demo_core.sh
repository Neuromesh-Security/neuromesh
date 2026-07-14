#!/usr/bin/env bash
# =============================================================================
# Neuromesh eBPF Sensor Core — Production Demo Wrapper (v0.1.0-core)
# =============================================================================
# End-to-end demo lifecycle:
#   1. Validate Linux + root privileges
#   2. Build Rust enforcement bytecode + user-space orchestrator (optional skip)
#   3. Start agent-ebpf-sensor in background
#   4. Wait for BPF map pin + Prometheus readiness
#   5. Execute scripts/simulate_attack.sh
#   6. Display captured LSM block telemetry and detection alerts
#   7. Graceful teardown (SIGTERM → drain → cleanup)
#
# Usage:
#   sudo ./scripts/demo_core.sh
#   sudo ./scripts/demo_core.sh --skip-build
#
# Environment:
#   NEUROMESH_METRICS_PORT     Prometheus port (default: 9090)
#   NEUROMESH_BPF_PIN_ROOT     BPF map pin path (default: /sys/fs/bpf/neuromesh)
#   NEUROMESH_DEMO_LOG         Agent log file (default: mktemp)
#   RUST_LOG                   Agent log level (default: info)
# =============================================================================

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly AGENT_BIN="${REPO_ROOT}/target/release/agent-ebpf-sensor"
readonly ENFORCEMENT_ELF="${REPO_ROOT}/apps/agent-ebpf-sensor/ebpf/target/bpfel-unknown-none/release/agent-ebpf-sensor-ebpf"
readonly SIMULATE_SCRIPT="${SCRIPT_DIR}/simulate_attack.sh"
readonly METRICS_PORT="${NEUROMESH_METRICS_PORT:-9090}"
readonly BPF_PIN_ROOT="${NEUROMESH_BPF_PIN_ROOT:-/sys/fs/bpf/neuromesh}"
readonly READY_TIMEOUT_SECS="${NEUROMESH_DEMO_READY_TIMEOUT:-120}"

# Populated at runtime.
SKIP_BUILD=0
LOG_FILE=""
AGENT_PID=""
DEMO_STARTED=0

if [[ -t 1 ]]; then
    readonly C_RESET='\033[0m'
    readonly C_RED='\033[0;31m'
    readonly C_GREEN='\033[0;32m'
    readonly C_YELLOW='\033[1;33m'
    readonly C_BLUE='\033[0;34m'
    readonly C_CYAN='\033[0;36m'
    readonly C_BOLD='\033[1m'
else
    readonly C_RESET='' C_RED='' C_GREEN='' C_YELLOW='' C_BLUE='' C_CYAN='' C_BOLD=''
fi

log_info()  { printf '%b[demo-core] %s%b\n' "${C_BLUE}" "$*" "${C_RESET}"; }
log_ok()    { printf '%b[demo-core] ✓ %s%b\n' "${C_GREEN}" "$*" "${C_RESET}"; }
log_warn()  { printf '%b[demo-core] ⚠ %s%b\n' "${C_YELLOW}" "$*" "${C_RESET}" >&2; }
log_error() { printf '%b[demo-core] ✗ %s%b\n' "${C_RED}" "$*" "${C_RESET}" >&2; }
log_step()  { printf '\n%b[demo-core] ▶ %s%b\n' "${C_BOLD}${C_CYAN}" "$*" "${C_RESET}"; }

die() {
    log_error "$*"
    exit 1
}

# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------

stop_agent() {
    if [[ -z "${AGENT_PID}" ]]; then
        return 0
    fi

    if kill -0 "${AGENT_PID}" 2>/dev/null; then
        log_info "Sending SIGTERM to agent (pid=${AGENT_PID})..."
        kill -TERM "${AGENT_PID}" 2>/dev/null || true

        local waited=0
        while kill -0 "${AGENT_PID}" 2>/dev/null && [[ ${waited} -lt 15 ]]; do
            sleep 1
            waited=$((waited + 1))
        done

        if kill -0 "${AGENT_PID}" 2>/dev/null; then
            log_warn "Agent did not exit gracefully — sending SIGKILL."
            kill -KILL "${AGENT_PID}" 2>/dev/null || true
            wait "${AGENT_PID}" 2>/dev/null || true
        else
            wait "${AGENT_PID}" 2>/dev/null || true
            log_ok "Agent exited cleanly (graceful shutdown + BPF link release)."
        fi
    fi

    AGENT_PID=""
}

cleanup() {
    local exit_code=$?
    if [[ ${DEMO_STARTED} -eq 1 ]]; then
        log_step "Teardown"
        stop_agent
        if [[ -n "${LOG_FILE}" && -f "${LOG_FILE}" ]]; then
            log_info "Full agent log preserved at: ${LOG_FILE}"
        fi
    fi
    exit "${exit_code}"
}

trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------

parse_args() {
    local skip=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --skip-build)
                skip=1
                shift
                ;;
            --help|-h)
                cat <<EOF
Usage: sudo $(basename "$0") [--skip-build]

  --skip-build   Skip cargo build (use existing target/release/agent-ebpf-sensor)

Requires: Linux, root, bpffs mounted at /sys/fs/bpf, BTF at /sys/kernel/btf/vmlinux
EOF
                exit 0
                ;;
            *)
                die "Unknown argument: $1 (try --help)"
                ;;
        esac
    done
    SKIP_BUILD="${skip}"
}

require_linux() {
    [[ "$(uname -s)" == "Linux" ]] || die "Demo requires native Linux (eBPF cannot attach in Docker Desktop / WSL without kernel support)."
}

require_root() {
    [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Run as root: sudo ${SCRIPT_DIR}/demo_core.sh"
}

require_bpffs() {
    [[ -d /sys/fs/bpf ]] || die "bpffs not mounted at /sys/fs/bpf — mount bpf filesystem before demo."
}

require_btf() {
    [[ -f /sys/kernel/btf/vmlinux ]] || die "BTF not available at /sys/kernel/btf/vmlinux — required for LSM attach."
}

require_toolchain() {
    command -v cargo >/dev/null 2>&1 || die "cargo not found in PATH."
    command -v curl >/dev/null 2>&1 || die "curl required for readiness checks."
}

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

build_sensor() {
    log_step "Build eBPF Sensor Core artifacts"

    export CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER="${CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER:-bpf-linker}"

    if ! command -v bpf-linker >/dev/null 2>&1; then
        log_warn "bpf-linker not found — installing via cargo (may take a minute)..."
        cargo install bpf-linker --locked
    fi

    log_info "Building Rust enforcement bytecode (agent-ebpf-sensor-ebpf)..."
    (
        cd "${REPO_ROOT}"
        cargo +nightly build --package agent-ebpf-sensor-ebpf \
            --target bpfel-unknown-none -Z build-std=core --release
    )

    [[ -f "${ENFORCEMENT_ELF}" ]] || die "Enforcement ELF missing: ${ENFORCEMENT_ELF}"

    log_info "Building user-space orchestrator (orchestrator feature)..."
    (
        cd "${REPO_ROOT}"
        cargo build -p agent-ebpf-sensor --features orchestrator --release
    )

    [[ -x "${AGENT_BIN}" ]] || die "Orchestrator binary missing: ${AGENT_BIN}"
    log_ok "Build complete: ${AGENT_BIN}"
}

# ---------------------------------------------------------------------------
# Agent lifecycle
# ---------------------------------------------------------------------------

start_agent() {
    log_step "Start agent-ebpf-sensor (background)"

    LOG_FILE="${NEUROMESH_DEMO_LOG:-$(mktemp -t neuromesh-demo-agent.XXXXXX.log)}"
    log_info "Agent log file: ${LOG_FILE}"

    export RUST_LOG="${RUST_LOG:-info}"
    export NEUROMESH_METRICS_PORT="${METRICS_PORT}"
    export NEUROMESH_BPF_PIN_ROOT="${BPF_PIN_ROOT}"

    # Preserve caller environment (sudo -E recommended).
    "${AGENT_BIN}" >"${LOG_FILE}" 2>&1 &
    AGENT_PID=$!

    log_ok "Agent started (pid=${AGENT_PID})"
}

agent_log_contains() {
    local pattern="$1"
    [[ -f "${LOG_FILE}" ]] && grep -q "${pattern}" "${LOG_FILE}" 2>/dev/null
}

wait_for_agent_ready() {
    log_step "Wait for BPF map initialization and hook attach"

    local elapsed=0
    while [[ ${elapsed} -lt ${READY_TIMEOUT_SECS} ]]; do
        # Primary: orchestrator readiness log lines.
        if agent_log_contains "XDR enforcement armed" \
            && agent_log_contains "Process visibility armed"; then
            log_ok "Agent hooks armed (LSM + execve tracepoint + tcp_connect)."
            break
        fi

        # Agent crash detection.
        if ! kill -0 "${AGENT_PID}" 2>/dev/null; then
            log_error "Agent process exited unexpectedly. Last 30 log lines:"
            tail -n 30 "${LOG_FILE}" >&2 || true
            die "Agent failed to start — inspect ${LOG_FILE}"
        fi

        sleep 1
        elapsed=$((elapsed + 1))
    done

    if [[ ${elapsed} -ge ${READY_TIMEOUT_SECS} ]]; then
        log_error "Timed out waiting for agent readiness (${READY_TIMEOUT_SECS}s)."
        tail -n 40 "${LOG_FILE}" >&2 || true
        die "Agent did not reach ready state."
    fi

    # Secondary: BPF map pin directory populated.
    local pin_wait=0
    while [[ ${pin_wait} -lt 30 ]]; do
        if [[ -e "${BPF_PIN_ROOT}/PROCESS_EVENTS" ]]; then
            log_ok "BPF maps pinned under ${BPF_PIN_ROOT}"
            break
        fi
        sleep 1
        pin_wait=$((pin_wait + 1))
    done

    if [[ ! -e "${BPF_PIN_ROOT}/PROCESS_EVENTS" ]]; then
        log_warn "PROCESS_EVENTS not yet visible under ${BPF_PIN_ROOT} — continuing (first-boot pin may lag)."
    fi

    # Tertiary: Prometheus metrics endpoint.
    local metrics_wait=0
    while [[ ${metrics_wait} -lt 30 ]]; do
        if curl -sf "http://127.0.0.1:${METRICS_PORT}/metrics" 2>/dev/null \
            | grep -q 'agent_uptime_seconds'; then
            log_ok "Prometheus /metrics responding on :${METRICS_PORT}"
            return 0
        fi
        sleep 1
        metrics_wait=$((metrics_wait + 1))
    done

    log_warn "Prometheus endpoint not yet reachable — proceeding with simulation anyway."
}

# ---------------------------------------------------------------------------
# Simulation + telemetry display
# ---------------------------------------------------------------------------

run_simulation() {
    log_step "Execute attack simulation"
    [[ -x "${SIMULATE_SCRIPT}" ]] || chmod +x "${SIMULATE_SCRIPT}"

    set +e
    "${SIMULATE_SCRIPT}"
    local sim_exit=$?
    set -e

    if [[ ${sim_exit} -ne 0 ]]; then
        log_warn "simulate_attack.sh exited with code ${sim_exit} — review output below."
    else
        log_ok "Attack simulation completed."
    fi

    # Allow RingBuf events to flush to stdout.
    sleep 3
}

display_telemetry() {
    log_step "Captured sensor telemetry"

    if [[ ! -f "${LOG_FILE}" ]]; then
        log_warn "No agent log file to display."
        return 0
    fi

    echo
    printf '%b── LSM enforcement log lines ──%b\n' "${C_BOLD}" "${C_RESET}"
    grep -E 'blocked execution|Neuromesh XDR|bprm_check_security' "${LOG_FILE}" 2>/dev/null \
        | tail -n 20 || log_info "(no LSM kernel log lines in agent output — check aya_log routing)"

    echo
    printf '%b── Detection alerts (JSON) ──%b\n' "${C_BOLD}" "${C_RESET}"
    if grep -E '^\{"timestamp"' "${LOG_FILE}" 2>/dev/null | tail -n 20; then
        :
    else
        log_warn "No JSON alert lines captured yet."
        log_info "Searching for CRITICAL_ALERT / BEHAVIOR_ALERT string fragments..."
        grep -E 'CRITICAL_ALERT|BEHAVIOR_ALERT|NEUROMESH-EXEC' "${LOG_FILE}" 2>/dev/null | tail -n 20 \
            || log_warn "No detection alerts found — confirm LSM attach and spawn burst threshold."
    fi

    echo
    printf '%b── Telemetry health ──%b\n' "${C_BOLD}" "${C_RESET}"
    grep -E 'Telemetry Health|ebpf_events_' "${LOG_FILE}" 2>/dev/null | tail -n 10 \
        || log_info "(health metrics not yet emitted — 5s sampling interval)"

    echo
    printf '%b── Prometheus snapshot ──%b\n' "${C_BOLD}" "${C_RESET}"
    if curl -sf "http://127.0.0.1:${METRICS_PORT}/metrics" 2>/dev/null \
        | grep -E '^(ebpf_events_|agent_uptime)' | head -n 10; then
        :
    else
        log_warn "Could not scrape /metrics on :${METRICS_PORT}"
    fi
}

print_summary() {
    log_step "Demo summary"
    log_ok "v0.1.0-core eBPF Sensor Core demo complete."
    log_info "Review checklist:"
    log_info "  • LSM denied execution from /tmp/, /dev/shm/, /var/tmp/"
    log_info "  • CRITICAL_ALERT JSON (NEUROMESH-EXEC-BLACKLIST-PATH)"
    log_info "  • BEHAVIOR_ALERT JSON (NEUROMESH-EXEC-SPAWN-BURST)"
    log_info "  • Prometheus counters: ebpf_events_processed_total / ebpf_events_dropped_total"
    log_info "Full agent log: ${LOG_FILE}"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    parse_args "$@"

    log_info "Neuromesh eBPF Sensor Core — enterprise demo (v0.1.0-core)"
    log_info "Repository: ${REPO_ROOT}"

    require_linux
    require_root
    require_bpffs
    require_btf
    require_toolchain

    DEMO_STARTED=1

    if [[ "${SKIP_BUILD}" -eq 0 ]]; then
        build_sensor
    else
        log_info "Skipping build (--skip-build)."
        [[ -x "${AGENT_BIN}" ]] || die "Binary not found: ${AGENT_BIN}. Run without --skip-build."
    fi

    start_agent
    wait_for_agent_ready
    run_simulation
    display_telemetry
    print_summary
}

main "$@"
