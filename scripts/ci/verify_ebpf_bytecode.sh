#!/usr/bin/env bash
# Load compiled eBPF bytecode through the kernel verifier (bpftool prog loadall).
# Fails CI when the verifier rejects any program in the object file.
set -euo pipefail

readonly BPF_OBJECT="${1:?usage: verify_ebpf_bytecode.sh <path-to-bytecode>}"
readonly PIN_ROOT="${2:-/sys/fs/bpf/neuromesh-ci-verify}"

log() {
  printf '[ebpf-verifier] %s\n' "$*"
}

if [[ ! -f "${BPF_OBJECT}" ]]; then
  log "ERROR: bytecode artifact not found: ${BPF_OBJECT}"
  exit 1
fi

ensure_bpftool() {
  if command -v bpftool >/dev/null 2>&1; then
    return 0
  fi

  local linux_tools_dir="/usr/lib/linux-tools/$(uname -r)"
  if [[ -x "${linux_tools_dir}/bpftool" ]]; then
    sudo ln -sf "${linux_tools_dir}/bpftool" /usr/local/bin/bpftool
    return 0
  fi

  log "ERROR: bpftool not found in PATH"
  exit 1
}

ensure_bpftool

log "Runner kernel: $(uname -r)"
log "Bytecode: ${BPF_OBJECT}"
log "Pin root: ${PIN_ROOT}"

sudo mkdir -p /sys/fs/bpf
if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
  sudo mount -t bpf bpf /sys/fs/bpf || true
fi

sudo rm -rf "${PIN_ROOT}"
sudo mkdir -p "${PIN_ROOT}"

set +e
LOAD_OUTPUT="$(sudo bpftool prog loadall "${BPF_OBJECT}" "${PIN_ROOT}" 2>&1)"
LOAD_STATUS=$?
set -e

printf '%s\n' "${LOAD_OUTPUT}"

if [[ ${LOAD_STATUS} -ne 0 ]]; then
  log "ERROR: kernel verifier rejected eBPF bytecode (exit ${LOAD_STATUS})"
  exit "${LOAD_STATUS}"
fi

LOADED_COUNT="$(sudo bpftool prog show pinned "${PIN_ROOT}" 2>/dev/null | grep -c '^[0-9]' || true)"
if [[ "${LOADED_COUNT}" -lt 1 ]]; then
  log "ERROR: bpftool loadall succeeded but no programs were pinned under ${PIN_ROOT}"
  exit 1
fi

log "Verifier accepted ${LOADED_COUNT} program(s)."
sudo rm -rf "${PIN_ROOT}"
