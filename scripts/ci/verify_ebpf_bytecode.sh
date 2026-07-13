#!/usr/bin/env bash
# Load compiled eBPF bytecode through the kernel verifier (Aya loader).
# Fails CI when the verifier rejects any program in the object file.
set -euo pipefail

readonly BPF_OBJECT="${1:?usage: verify_ebpf_bytecode.sh <path-to-bytecode>}"
readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

log() {
  printf '[ebpf-verifier] %s\n' "$*"
}

if [[ ! -f "${BPF_OBJECT}" ]]; then
  log "ERROR: bytecode artifact not found: ${BPF_OBJECT}"
  exit 1
fi

cd "${ROOT_DIR}"
cargo run -q -p agent-ebpf-sensor --bin verify-ebpf --release -- "${BPF_OBJECT}"
