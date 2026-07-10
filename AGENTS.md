# AGENTS.md

## Cursor Cloud specific instructions

### What actually builds/runs today
Neuromesh Security is an early alpha. Only one component is currently buildable/runnable:
`apps/agent-ebpf-sensor` (Rust) — a user-space orchestrator plus a kernel-space eBPF hook
(`apps/agent-ebpf-sensor/ebpf`). The `ebpf` crate is a Cargo workspace member of the
sensor (`apps/agent-ebpf-sensor/Cargo.toml`).

The other paths are empty placeholders and are NOT buildable: `apps/zt-policy-engine`
(Go, no `go.mod`), `packages/crypto-core` (empty `Cargo.toml`). `packages/proto-definitions`
is just a `.proto` schema (no codegen wired in). The README mentions Kafka / a Python-Mojo
AI engine / Kubernetes, but none of that is implemented in-repo yet, so it is not needed to
build or run what exists.

### Toolchain notes (already provisioned in the VM snapshot)
- Rust **nightly** is the default toolchain (required: eBPF needs `-Z build-std` and the repo
  uses edition2024 transitive deps that stable cargo 1.83 cannot parse). `rust-src` is installed.
- `bpf-linker` is installed (built against system LLVM 18) and is required to link eBPF bytecode.
- System build deps are installed: `clang llvm-18-dev libelf-dev libpcap-dev protobuf-compiler
  cmake build-essential libcurl4-openssl-dev zlib1g-dev libssl-dev libsasl2-dev libzstd-dev`.
- GOTCHA: the default `cc`/`c++` alternatives were switched to **gcc/g++**. `rdkafka-sys` builds
  librdkafka via cmake, and the distro's default `c++` (clang++) fails to find `-lstdc++`. gcc
  links it correctly. Do not switch `cc`/`c++` back to clang. (eBPF still uses `clang` directly.)

### Build / run / lint commands
Run from `apps/agent-ebpf-sensor/`:
- Build kernel-space eBPF hook (produces a `Linux BPF` ELF with a `tracepoint` program):
  `cargo build -p agent-ebpf-sensor-ebpf --manifest-path ebpf/Cargo.toml --target bpfel-unknown-none -Z build-std=core --release`
  (The README references `cargo xtask build-ebpf`, but there is no `xtask` crate — use the
  command above. Build the eBPF crate explicitly; a bare `cargo build` at the workspace root
  tries to build the `no_std` eBPF crate for the host target and fails.)
- Build user-space sensor: `cargo build -p agent-ebpf-sensor`
- Run the sensor (currently a stub that prints a boot line): `cargo run -p agent-ebpf-sensor`
- Lint: `cargo clippy -p agent-ebpf-sensor`

### Testing notes
There are no automated tests yet. This is a CLI/kernel project with no GUI, so verify via the
build + run commands above (terminal-driven). Actually loading BPF into the kernel is not
implemented in code (`src/main.rs` does not load the eBPF object), and `bpftool` is unavailable
for the custom VM kernel — so end-to-end kernel injection cannot be demonstrated here.
