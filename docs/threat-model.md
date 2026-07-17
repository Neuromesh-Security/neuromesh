# Neuromesh Threat Model — eBPF Sensor Core

**Status:** Living document  
**Release scope:** `v0.1.0-core`  
**Last updated:** 2026-07-14  
**Component:** `apps/agent-ebpf-sensor` — kernel hooks, telemetry contracts, user-space detection pipeline

---

## 1. Scope and assumptions

### In scope

- C visibility programs: `sys_enter_execve` tracepoint, `tcp_connect` kprobe
- Rust enforcement program: `bprm_check_security` LSM hook
- User-space pipelines: `RuleEngine`, `DataNormalizer`, `CorrelationEngine`, Prometheus health
- Map pinning, rate limiting, and backpressure controls

### Out of scope (v0.1.0-core)

- Rust passive tracepoint `neuromesh_exec_hook` (built, not attached)
- Wasm policy evaluation on hot path (`wasm_policy.rs` scaffold only)
- Slow Path GNN inference (`ai-threat-detector`)
- Full argv/env capture from execve tracepoint context

### Assumptions

- Attackers have unprivileged or compromised user-level access on Linux nodes.
- Living-off-the-land (LotL) binaries (`bash`, `curl`, `python`, `sh`) are present and often whitelisted.
- LSM eBPF is the synchronous enforcement plane; user-space logic must remain correct when tested offline without a kernel.
- Operators monitor `ebpf_events_dropped_total` — unmonitored drops are treated as a production incident.

---

## 2. Assets and impact

| Asset | Description | Impact if compromised |
|-------|-------------|----------------------|
| `PROCESS_EVENTS` RingBuf | High-volume execve telemetry | Missed process visibility, fork-bomb blind spots |
| `TELEMETRY_RINGBUF` | LSM enforcement telemetry | Missed blocks, silent allow of staging-path execution |
| `NETWORK_EVENTS` RingBuf | Outbound TCP connect telemetry | Missed C2 / lateral movement signals |
| `RuleEngine` policies | Whitelist / blacklist path rules | False negatives on staging paths; false positives on admin workflows |
| `DataNormalizer` | Parent-keyed spawn burst detector | Undetected fork bombs, post-exploitation automation |
| `CorrelationEngine` | PID → process name cache | Enriched network events lose process attribution |
| Orchestrator stdout / Kafka | Alert and telemetry export | Tampered or dropped SIEM records |

---

## 3. MITRE ATT&CK mapping — execve telemetry

### Covered techniques (v0.1.0-core)

| Technique | ID | Neuromesh control | Detection signal | Test anchor |
|-----------|-----|-------------------|------------------|-------------|
| Command and Scripting Interpreter | [T1059](https://attack.mitre.org/techniques/T1059/) | LSM path classification + spawn burst analysis | `CRITICAL_ALERT` / `BEHAVIOR_ALERT` JSON | `rule_engine_integration`, `data_normalizer_integration` |
| Unix Shell | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Parent-keyed spawn frequency (`ppid` window) | `NEUROMESH-EXEC-SPAWN-BURST` | `rapid_spawn_burst_triggers_behavior_alert` |
| User Execution | [T1204](https://attack.mitre.org/techniques/T1204/) | LSM deny + blacklist on ephemeral paths | `NEUROMESH-EXEC-BLACKLIST-PATH` | `all_malicious_staging_prefixes_are_flagged` |
| Masquerading | [T1036](https://attack.mitre.org/techniques/T1036/) | `comm` + filename in LSM telemetry; PID correlation for network | Enriched network events | `pipeline_integration::mock_ringbuf_feeds_pipeline_without_kernel` |
| Endpoint Denial of Service | [T1499](https://attack.mitre.org/techniques/T1499/) | Kernel token bucket + spawn burst detection | Rate-limit drops; burst alerts | `execve_stress_test`, `data_normalizer_integration` |
| Non-Standard Port / Application Layer Protocol | [T1571](https://attack.mitre.org/techniques/T1571/) / [T1071](https://attack.mitre.org/techniques/T1071/) | `tcp_connect` kprobe visibility | Correlated network events → Kafka | Network monitor (manual validation) |

### Partially covered / planned

| Technique | ID | Gap | Planned mitigation |
|-----------|-----|-----|-------------------|
| Process Injection | [T1055](https://attack.mitre.org/techniques/T1055/) | No `ptrace`/`memfd_create` hooks | v0.2 hook expansion |
| Impair Defenses | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Attacker with CAP_BPF can detach programs | Agent tamper detection, signed bytecode attestation |
| Hide Artifacts | [T1070](https://attack.mitre.org/techniques/T1070/) | Short-lived processes may evade correlation | Enriched C tracepoint (`neuromesh_exec_hook`) |
| Signed Binary Proxy Execution | [T1218](https://attack.mitre.org/techniques/T1218/) | LotL from whitelisted paths without burst | Wasm policies + Slow Path GNN |

---

## 4. `execve` telemetry — threat surface

The `sys_enter_execve` tracepoint is the highest-volume syscall surface in the agent. Attackers can abuse exec visibility for **evasion**, **denial of service**, and **telemetry poisoning** if controls are absent.

### 4.1 Threat scenarios

| ID | Threat | Description | MITRE alignment |
|----|--------|-------------|-----------------|
| E-01 | **Exec storm / fork bomb** | High-frequency `execve` floods RingBuf and user-space workers | [T1499](https://attack.mitre.org/techniques/T1499/) |
| E-02 | **Visibility evasion** | Sub-second processes exit before PID→name correlation registers | [T1036](https://attack.mitre.org/techniques/T1036/) |
| E-03 | **TOCTOU on argv/path** | User-space reads of `filename` after syscall entry; kernel/userspace views can diverge | [T1059](https://attack.mitre.org/techniques/T1059/) |
| E-04 | **Agent restart blind spot** | Unpinned maps reset rate-limiter state across crashes | Availability |
| E-05 | **Staging path execution** | Payload dropped to `/tmp/`, `/dev/shm/`, `/var/tmp/` and executed | [T1204](https://attack.mitre.org/techniques/T1204/) |
| E-06 | **LotL without burst** | Single invocation of whitelisted binary from benign path | [T1218](https://attack.mitre.org/techniques/T1218/) |
| E-07 | **BPF program tampering** | Root attacker unloads or replaces agent BPF programs | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) |
| E-08 | **Rate-limit exhaustion** | Deliberate exec flood forces kernel drops, creating visibility gaps | [T1499](https://attack.mitre.org/techniques/T1499/) |

### 4.2 Kernel-level evasion risks

| Risk | Mechanism | Current exposure (v0.1.0-core) |
|------|-----------|----------------------------------|
| **Syscall alternative** | Attacker uses `execveat`, `fexecve`, or `clone3` without `execve` | Only `sys_enter_execve` is hooked; `execveat` not monitored |
| **Namespace escape context** | Container breakout before agent deploy | Agent must run on host PID namespace (`hostPID: true`) |
| **BPF hook disable** | `CAP_BPF` + `CAP_SYS_ADMIN` attacker detaches programs | No tamper-evident watchdog in open-source core |
| **Verifier-minimal telemetry** | C tracepoint emits PID-only records | Filename/argv not available for volume path — correlation gap |
| **Hardcoded struct offsets** | `task_struct` ppid via fixed offsets (Rust LSM) | Wrong ppid on unsupported kernels → burst detection miss |
| **Kprobe offset drift** | `tcp_connect` socket field offsets from minimal `vmlinux.h` | Dest IP/port read failure on kernel ABI change |
| **RingBuf loss under load** | Legitimate high exec rate exceeds 500k/sec/CPU | Events dropped by design — attacker can hide in noise |
| **LSM bypass paths** | Execution paths not passing `bprm_check_security` | Kernel-dependent; no agent coverage claim for all exec variants |

### 4.3 Mitigation strategies

| Control | Implementation | Threats addressed |
|---------|----------------|-----------------|
| **Kernel token bucket** | `RATE_LIMIT_BUCKET` per-CPU (~500k evt/s) in `sys_exec.bpf.c` | E-01, E-08 |
| **RingBuf backpressure** | Bounded Tokio MPSC (`NEUROMESH_PROCESS_CHANNEL_CAPACITY`, default 8192) | E-01 |
| **BPFfs map pinning** | `PROCESS_EVENTS` + `RATE_LIMIT_BUCKET` under `/sys/fs/bpf/neuromesh` | E-04 |
| **LSM synchronous deny** | `neuromesh_lsm_exec_guard` returns `-EPERM` for `/tmp/`, `/dev/shm/`, `/var/tmp/` | E-05 |
| **Spawn burst detection** | `DataNormalizer` — 2s window, threshold 8 spawns per `ppid` | E-01, E-06 (partial) |
| **Path whitelist suppression** | Static whitelist: `/bin/ls`, `/bin/cat`, `/usr/bin/git`, `/usr/bin/bash` | False positive reduction |
| **Graceful shutdown** | `CancellationToken` + 500ms drain before BPF link release | Data loss on rolling update |
| **Prometheus + health monitor** | `ebpf_events_dropped_total`, 5s kernel drop sampling | E-08 detection |
| **Fuzz-tested decoders** | `event_parser_fuzz_test` — 50k random-byte iterations | Memory safety in user-space decode |
| **Chaos-tested backpressure** | `chaos_engineering_test` — MPSC saturation, 50k mock RingBuf drain | E-01 resilience validation |

### 4.4 False-positive handling

False positives erode SOC trust. Neuromesh applies layered suppression:

#### RuleEngine (path-based)

| Policy | Paths / prefixes | Behavior |
|--------|------------------|----------|
| **Whitelist (exact match)** | `/bin/ls`, `/bin/cat`, `/usr/bin/git`, `/usr/bin/bash` | `RuleVerdict::Suppressed` — no alert emitted |
| **Blacklist (prefix match)** | `/tmp/`, `/dev/shm/`, `/var/tmp/` | `CRITICAL_ALERT` / `NEUROMESH-EXEC-BLACKLIST-PATH` |
| **Default** | All other paths | Suppressed (no alert on benign paths) |

**Operational guidance:**

- Extend whitelist via code change (v0.1.0-core) — no runtime policy API yet.
- Treat `/tmp/` alerts as **high-confidence staging detections**, not automatic block in user space (block already occurred in LSM for matched paths).
- Document approved temporary execution paths for CI/CD (e.g., package managers writing to `/var/tmp/`) — add to whitelist or relocate artifacts.

#### DataNormalizer (behavior-based)

| Parameter | Default | False-positive scenario | Tuning |
|-----------|---------|------------------------|--------|
| Window | 2 seconds | Build systems spawning many short-lived children | Increase window or threshold |
| Burst threshold | 8 spawns per `ppid` | Parallel test runners | Raise threshold via `with_config()` |
| `ppid == 0` | Ignored | Kernel lineage read failure | Fix offsets; do not alert on orphan events |

**Operational guidance:**

- `BEHAVIOR_ALERT` severity is **`BEHAVIOR_ALERT`** (not `CRITICAL`) — route to triage queue, not auto-remediation.
- Correlate with parent `comm` and `last_binary_path` before escalation.
- CI burst jobs should run with tagged parent processes or excluded nodes.

#### Telemetry volume FPs

| Signal | Cause | Response |
|--------|-------|----------|
| High `ebpf_events_processed_total` without alerts | Normal workload | Baseline per node class |
| `ebpf_events_dropped_total` > 0 | Exec rate exceeds capacity | Scale agent CPU; investigate fork bomb (E-01) |
| Log sampling every 10k events | Info-level process monitor logs | Do not treat sampled logs as security alerts |

---

## 5. Network telemetry (`tcp_connect`)

| Threat | Control | Residual risk |
|--------|---------|---------------|
| C2 over non-TCP protocols | Not visible to kprobe | UDP/ICMP blind spot |
| Connect before agent start | No retroactive visibility | Deploy agent before workload |
| Correlation miss (unknown PID) | Event logged, not Kafka-enqueued | Short-lived process (E-02) |

---

## 6. Test farm coverage

Integration tests run via `cargo test -p neuromesh-integration-tests` **without** a Linux kernel:

```
/tests
  src/fixtures.rs          # Benign / malicious telemetry vectors
  src/mocks.rs             # MockRingBuf + TelemetrySource trait
  tests/
    rule_engine_integration.rs
    data_normalizer_integration.rs
    pipeline_integration.rs
```

### Fixture → ATT&CK traceability

| Fixture vector | MITRE intent | Expected outcome |
|----------------|--------------|------------------|
| `benign_events()` | Baseline admin activity | `RuleVerdict::Suppressed`, no `BEHAVIOR_ALERT` |
| `malicious_blacklist_events()` | T1204 — staging in ephemeral dirs | `CRITICAL_ALERT` / `NEUROMESH-EXEC-BLACKLIST-PATH` |
| `malicious_spawn_burst_events()` | T1059 / T1499 — rapid interpreter chaining | `BEHAVIOR_ALERT` / `NEUROMESH-EXEC-SPAWN-BURST` |
| `mixed_ringbuf_drain()` | Combined kill-chain simulation | Both SIEM and behavioral alerts |

### Offline eBPF mocking

| Kernel construct | Test double | Location |
|------------------|-------------|----------|
| `TELEMETRY_RINGBUF` | `MockRingBuf::from_events(vec![])` | `agent_ebpf_sensor::mocks::ringbuf` |
| Map health counters | `TelemetryHealthStats` on mock drain | `pipeline_integration` |
| Async poll loop | `TelemetrySource` trait | `agent_ebpf_sensor::mocks::telemetry_source` |

---

## 7. Residual risks (v0.1.0-core)

> **Ownership note (2026-07-17):** `Owner`/`Target` columns added below following
> two independent audit findings that High/Medium residual risks were disclosed
> but unowned — an acknowledged-but-unowned finding reads worse in a Fortune 500
> security review than an undisclosed one. `Agent tampering by root` is tracked
> in [#44](https://github.com/Neuromesh-Security/neuromesh/issues/44); the
> remaining Medium-severity rows below are flagged as needing their own issues
> (`Tracked in #TBD`) and are intentionally NOT assigned a real issue number or
> a named owner here until those issues exist — do not treat `#TBD` as a real
> reference.

| Risk | Severity | Notes | Owner | Target |
|------|----------|-------|-------|--------|
| C execve tracepoint emits PID-only | Medium | Full argv capture requires verifier-reviewed `ctx` reads. Planned mitigation: add verifier-reviewed argv capture to the C tracepoint. | Unassigned | Tracked in #TBD — new issue needed |
| `neuromesh_exec_hook` not attached | Low | Rich passive telemetry exists but unused at runtime | — | — |
| Per-CPU drop accounting | Low | `RATE_LIMIT_DROPS` summed across CPUs; NUMA hot spots may dominate | — | — |
| Hardcoded `task_struct` offsets | Medium | `ppid == 0` silently excluded from burst detection. Planned mitigation: replace with CO-RE/BTF-relocatable field access, matching the C tracepoint's approach. | Unassigned | Tracked in #TBD — new issue needed |
| No `execveat` hook | Medium | Alternative exec syscall unmonitored. Planned mitigation: add `execveat` coverage to the tracepoint hook. | Unassigned | Tracked in #TBD — new issue needed |
| LotL single-shot from whitelisted path | Medium | Requires Slow Path / Wasm (future). Planned mitigation: Wasm policy engine + Slow Path GNN correlation (currently scaffold-only, see §3). | Unassigned | Tracked in #TBD — new issue needed |
| Agent tampering by root | High | No open-source tamper detection. Planned mitigation: signed eBPF bytecode attestation + runtime integrity check. | Dragan Flavius (@DraganFlavius) | Tracked in #44, target: v0.2 |
| BTF offset resolver cross-kernel coverage | Medium | Not yet validated on real 5.15/6.1 (or a true non-Azure 6.8) kernels — CI's `"5.15"`/`"6.1"` matrix labels currently both resolve to the same ~6.8-azure runner kernel. Current mitigation: CI fail-closed on GH-hosted ~6.8-azure and ~6.17-azure via the production `verify-ebpf` path; unit tests + one WSL2 5.15.167 fixture cross-checked against bpftool ground truth. Planned mitigation: scoped manual pre-release check on real target hardware for 5.15/6.1 before claiming those specific lines as validated (same disclosure pattern as `execve_stress_test`). | Unassigned | Tracked in #TBD — new issue needed |
| CI coverage gate | Low | ≥70% line coverage on core crates; Ring 0 not measured | — | — |

---

## 8. Validation workflow

### Offline (no root, no kernel)

```bash
cargo test -p neuromesh-integration-tests
cargo test -p agent-ebpf-sensor --lib
cargo test -p agent-ebpf-sensor --test event_parser_fuzz_test
cargo test -p agent-ebpf-sensor --test chaos_engineering_test --features orchestrator
```

### Live (Linux + root)

```bash
cargo build -p agent-ebpf-sensor --features orchestrator --release
sudo -E ./target/release/agent-ebpf-sensor &
./scripts/simulate_attack.sh
curl -s http://127.0.0.1:9090/metrics | grep ebpf_events
```

Expected simulation output:

1. Benign `/bin/ls`, `/bin/cat` — suppressed (no alert)
2. `/tmp/neuromesh-mock-payload.sh` execution — `CRITICAL_ALERT` (T1204)
3. Rapid `/bin/sh` spawn burst — `BEHAVIOR_ALERT` (T1059.004)

---

## 9. Related documents

| Document | Content |
|----------|---------|
| [`adr-001-lsm-vs-tracepoint.md`](architecture-decision-records/adr-001-lsm-vs-tracepoint.md) | Dual-hook design rationale |
| [`performance-baseline.md`](performance-baseline.md) | Latency, drop rate, load-test methodology |
| [`../README.md`](../README.md) | Architecture overview, deployment checklist |

---

*Review this document before each release candidate. Update MITRE mappings when new hooks ship or detection rules change.*
