# Release Notes — `v0.1.0-core`

**Tag:** `v0.1.0-core`  
**Date:** 2026-07-14  
**Component:** eBPF Sensor Core (`apps/agent-ebpf-sensor`)  
**Previous milestone:** `v0.1.0-alpha` (architecture narrative)  
**Audience:** Security engineering, platform engineering, SOC operations

---

## Summary

`v0.1.0-core` is the first **engineering-grade** release of the Neuromesh eBPF Sensor Core. It delivers synchronous LSM enforcement on ephemeral execution paths, high-volume execve visibility with kernel-side rate limiting, outbound TCP connect telemetry, bounded user-space backpressure, Prometheus observability, and a kernel-independent test suite with documented MITRE ATT&CK traceability.

This release prioritizes **verifiable runtime behavior** over marketing claims. Documentation, threat models, and performance baselines reflect the actual codebase — including known gaps.

---

## Capabilities

### Ring 0 — Kernel programs (runtime-attached)

| Program | Hook | Function |
|---------|------|----------|
| `neuromesh_lsm_exec_guard` | `bprm_check_security` (LSM) | **Denies execution** from `/tmp/`, `/dev/shm/`, `/var/tmp/`; emits enriched `SecurityTelemetryEvent` to `TELEMETRY_RINGBUF` |
| `neuromesh_process_events` | `syscalls/sys_enter_execve` (tracepoint) | High-volume exec visibility; per-CPU token bucket (~500k evt/s); pinned `PROCESS_EVENTS` RingBuf |
| `neuromesh_tcp_connect` | `tcp_connect` (kprobe) | Outbound TCP connect telemetry (pid, uid, dest_ip, dest_port) |

### Ring 3 — User-space orchestrator

| Module | Function |
|--------|----------|
| `RuleEngine` | Whitelist suppression + blacklist path alerts (`NEUROMESH-EXEC-BLACKLIST-PATH`) |
| `DataNormalizer` | Parent-keyed spawn burst detection (`NEUROMESH-EXEC-SPAWN-BURST`) |
| `CorrelationEngine` | PID → process name cache for network event enrichment |
| `process_monitor` / `network_monitor` | Async RingBuf consumers with bounded MPSC backpressure |
| Prometheus `/metrics` | `ebpf_events_processed_total`, `ebpf_events_dropped_total`, `agent_uptime_seconds` |
| Health monitor | 5s sampling of kernel `RATE_LIMIT_DROPS` + user-space channel drops |
| BPF map pinning | `PROCESS_EVENTS`, `RATE_LIMIT_BUCKET` under `/sys/fs/bpf/neuromesh` |

### MITRE ATT&CK coverage (documented)

| Technique | ID | Control |
|-----------|-----|---------|
| User Execution | T1204 | LSM deny on ephemeral staging paths |
| Command and Scripting Interpreter | T1059 | Path classification + spawn burst analysis |
| Unix Shell | T1059.004 | Parent-keyed frequency detection (2s window, threshold 8) |
| Masquerading | T1036 | `comm` + filename in LSM telemetry; PID correlation |
| Endpoint Denial of Service | T1499 | Kernel token bucket + spawn burst alerts |
| Application Layer Protocol | T1071 | `tcp_connect` visibility (partial) |

Full mapping, evasion analysis, and false-positive handling: [`docs/threat-model.md`](threat-model.md).

### Performance baseline

| Layer | Metric | Value | Status |
|-------|--------|-------|--------|
| User-space `RuleEngine` | Median benign evaluation | **115 ns** | Measured (Criterion) |
| User-space `DataNormalizer` | Median spawn ingest | **956 ns** | Measured (Criterion) |
| Kernel execve rate limit | Ceiling | **500k evt/s per CPU** | Implemented |
| End-to-end syscall overhead | p50/p99 delta | _TBD_ | Load-test procedure documented |

Details and reproduction: [`docs/performance-baseline.md`](performance-baseline.md).

### Test and validation harness

| Suite | Scope |
|-------|-------|
| `neuromesh-integration-tests` | RuleEngine, DataNormalizer, pipeline — no kernel |
| `event_parser_fuzz_test` | 50k random-byte decode fuzz iterations |
| `chaos_engineering_test` | MPSC saturation, 50k mock RingBuf drain |
| `execve_stress_test` | 100k / 500k EPS load tiers (`#[ignore]`) |
| `verify-ebpf` + CI verifier matrix | `ubuntu-22.04 / ~6.8-azure`, `ubuntu-24.04 / ~6.17-azure` (two Azure HWE kernels; not real 5.15/6.1 LTS) |

### Demo and simulation

```bash
# Full lifecycle demo (build → start → simulate → teardown)
sudo ./scripts/demo_core.sh

# Attack simulation only (sensor must already be running)
sudo ./scripts/simulate_attack.sh
```

---

## Deployment

Kubernetes DaemonSet: [`deploy/kubernetes/neuromesh-agent.yaml`](../deploy/kubernetes/neuromesh-agent.yaml)

Requirements:

- Linux kernel ≥ 5.8
- `CONFIG_BPF_LSM=y`
- BTF at `/sys/kernel/btf/vmlinux`
- bpffs mounted at `/sys/fs/bpf`
- Privileged pod or `CAP_BPF` + `CAP_SYS_ADMIN` + `CAP_PERFMON`

Production checklist: [`README.md`](../README.md#production-deployment).

---

## Transparency & Next Steps

The following limitations are **known and documented** — not bugs filed under false pretenses.

### C execve tracepoint is a verifier-safe skeleton

`neuromesh_process_events` (`sys_exec.bpf.c`) currently emits **PID only**. Fields for uid, ppid, comm, filename, and timestamp are reserved in `process_event_t` but zeroed at runtime. Full argv/path capture requires a separate verifier-reviewed change to read tracepoint context safely.

**Impact:** High-volume exec visibility exists; correlation registers mostly empty filenames until enrichment lands.

### Rust passive tracepoint not attached

`neuromesh_exec_hook` (Rust tracepoint in `ebpf/src/main.rs`) is compiled and verifier-tested but **not loaded or attached** in the orchestrator. Production passive exec enrichment flows through the C tracepoint; rich lineage telemetry on **all** exec events is a planned follow-up.

### LSM enforcement scope

Blocking applies to path prefixes `/tmp/`, `/dev/shm/`, `/var/tmp/` only. Alternative exec surfaces (`execveat`, `fexecve`) are not monitored. Root attackers with `CAP_BPF` can detach agent programs — no open-source tamper-evident watchdog in this release.

### Hardcoded kernel struct offsets

LSM `ppid` lineage uses best-effort `task_struct` offsets (x86_64, kernel 6.x). Events with `ppid == 0` are excluded from spawn burst detection. Network kprobe uses minimal `vmlinux.h` offsets — ABI drift may affect dest IP/port reads.

### Performance placeholders

User-space micro-benchmarks are measured. Kernel syscall latency delta, burst CPU utilization, and live RingBuf drop rates require execution of the load-test methodology on target hardware — placeholders remain in the performance baseline until CI hardware validation completes.

### Planned for post-core

| Item | Target |
|------|--------|
| Enriched C tracepoint (comm, filename, argv) | v0.1.1 |
| Attach Rust `neuromesh_exec_hook` or consolidate dual tracepoint | v0.1.1 |
| `execveat` tracepoint hook | v0.2.0 |
| Wasm policy hot-path evaluation | v0.2.0 |
| Runtime policy API (no code change for whitelist) | Enterprise |

---

## Upgrade from `v0.1.0-alpha`

| Area | Alpha | Core |
|------|-------|------|
| Documentation | Marketing-oriented README | Engineering README, threat model, performance baseline |
| LSM enforcement | Described | Runtime-attached, demo-validated |
| Execve visibility | Claimed | Implemented with rate limiting + pinning |
| Test suite | Basic | Fuzz, chaos, stress harness |
| Observability | Minimal | Prometheus + health monitor |
| Demo | Manual steps | `demo_core.sh` automated lifecycle |

No database migrations or API breaking changes — this is a sensor and documentation milestone.

---

## Files changed (documentation & demo)

| Path | Description |
|------|-------------|
| `README.md` | eBPF Sensor Core architecture, performance tables, quickstart, production deployment |
| `docs/performance-baseline.md` | Measured + load-test performance methodology |
| `docs/threat-model.md` | MITRE mapping, execve evasion surface, false-positive handling |
| `scripts/simulate_attack.sh` | LSM staging-path simulation (T1204, T1059) |
| `scripts/demo_core.sh` | Full demo lifecycle wrapper |
| `docs/RELEASE_v0.1.0-core.md` | This document |

---

## Verification commands

```bash
# Offline (no root)
cargo test -p neuromesh-integration-tests
cargo test -p agent-ebpf-sensor --test event_parser_fuzz_test
cargo test -p agent-ebpf-sensor --test chaos_engineering_test --features orchestrator

# Live demo (root, Linux)
sudo ./scripts/demo_core.sh
```

---

*Engineering release. Measure before you procure. Review [`docs/threat-model.md`](threat-model.md) residual risks against your threat model before production rollout.*
