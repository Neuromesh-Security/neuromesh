# Neuromesh Threat Model

**Status:** Living document  
**Last updated:** 2026-07-14  
**Scope:** User-space detection pipeline (`RuleEngine`, `DataNormalizer`) and eBPF telemetry contracts

## Assumptions

- Attackers have unprivileged or compromised user-level access on Linux nodes.
- Living-off-the-land (LotL) binaries (`bash`, `curl`, `python`) are present and often whitelisted.
- Kernel eBPF enforcement (LSM) is the synchronous control plane; user-space logic must remain correct when tested offline.

## Assets

| Asset | Impact if compromised |
|-------|---------------------|
| RingBuf telemetry stream | Missed detections, false negatives |
| RuleEngine policies | Silent allow of malware staging executions |
| DataNormalizer burst logic | Undetected fork bombs / automated post-exploitation |
| Orchestrator pipeline | Tampered SIEM / Kafka telemetry |

## MITRE ATT&CK Mapping

| Technique | ID | Neuromesh Control | Integration Test Anchor |
|-----------|-----|-------------------|-------------------------|
| Command and Scripting Interpreter | [T1059](https://attack.mitre.org/techniques/T1059/) | Tracepoint + RuleEngine path classification | `rule_engine_integration::lotl_bash_from_legitimate_path_is_not_blacklisted` |
| Unix Shell | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Lineage-aware spawn burst detection | `data_normalizer_integration::rapid_spawn_burst_triggers_behavior_alert` |
| User Execution | [T1204](https://attack.mitre.org/techniques/T1204/) | Blacklist of ephemeral staging directories | `rule_engine_integration::all_malicious_staging_prefixes_are_flagged` |
| Endpoint Denial of Service | [T1499](https://attack.mitre.org/techniques/T1499/) | Parent-keyed spawn frequency analysis | `data_normalizer_integration::rapid_spawn_burst_triggers_behavior_alert` |
| Masquerading | [T1036](https://attack.mitre.org/techniques/T1036/) | `comm` + path correlation in telemetry | `pipeline_integration::mock_ringbuf_feeds_pipeline_without_kernel` |

## Test Farm Coverage

Integration tests run via `cargo test -p neuromesh-integration-tests` **without** a Linux kernel or eBPF loader:

```
/tests
  src/fixtures.rs          # Static benign / malicious telemetry vectors
  src/mocks.rs             # Re-exports MockRingBuf + TelemetrySource trait
  tests/
    rule_engine_integration.rs
    data_normalizer_integration.rs
    pipeline_integration.rs
```

### Fixture → ATT&CK Traceability

| Fixture vector | MITRE intent | Expected outcome |
|----------------|--------------|------------------|
| `benign_events()` | Baseline admin activity | `RuleVerdict::Suppressed`, no `BEHAVIOR_ALERT` |
| `malicious_blacklist_events()` | T1204 — payload staging in `/tmp`, `/dev/shm`, `/var/tmp` | `CRITICAL_ALERT` / `NEUROMESH-EXEC-BLACKLIST-PATH` |
| `malicious_spawn_burst_events()` | T1059 / T1499 — rapid interpreter chaining | `BEHAVIOR_ALERT` / `NEUROMESH-EXEC-SPAWN-BURST` |
| `mixed_ringbuf_drain()` | Combined kill-chain simulation | Both SIEM and behavioral alerts via `TelemetryPipeline` |

## Offline eBPF Mocking Strategy

| Kernel construct | Test double | Location |
|------------------|-------------|----------|
| `TELEMETRY_RINGBUF` | `MockRingBuf::from_events(vec![])` | `agent_ebpf_sensor::mocks::ringbuf` |
| Map health counters | `TelemetryHealthStats` on mock drain | `pipeline_integration` |
| Async poll loop | `TelemetrySource` trait + `StaticTelemetrySource` | `agent_ebpf_sensor::mocks::telemetry_source` |

## `execve` Visibility Threat Surface

The `sys_enter_execve` tracepoint is the highest-volume syscall surface in the agent. Attackers can abuse it for **evasion**, **TOCTOU**, and **endpoint DoS** if the pipeline lacks kernel-side throttling and restart-safe state.

### Threats

| Risk | Description | MITRE alignment |
|------|-------------|-----------------|
| **Exec storm / fork bomb** | High-frequency `execve` floods starve RingBuf consumers and user-space workers | [T1499](https://attack.mitre.org/techniques/T1499/) Endpoint Denial of Service |
| **Visibility evasion** | Rapid short-lived processes may disappear before correlation registers PID → binary path | [T1036](https://attack.mitre.org/techniques/T1036/) Masquerading |
| **TOCTOU on argv/path** | User-space reads of `filename` occur after syscall entry; kernel and userspace views can diverge under race conditions | [T1059](https://attack.mitre.org/techniques/T1059/) Command and Scripting Interpreter |
| **Agent restart data loss** | Unpinned maps reset rate-limiter state and ringbuf backing metadata across crashes | Availability / blind spots after restart |

### Architectural Mitigations

| Control | Implementation | Effect |
|---------|----------------|--------|
| **Kernel token-bucket** | `RATE_LIMIT_BUCKET` per-CPU map (~500k events/sec) in `sys_exec.bpf.c` | Bounds Ring 0 work; excess events increment `RATE_LIMIT_DROPS` instead of unbounded enqueue |
| **Ringbuf backpressure** | Bounded Tokio MPSC (`NEUROMESH_PROCESS_CHANNEL_CAPACITY`, default 8192) with explicit drop + warn | Prevents unbounded user-space memory growth when drain rate < syscall rate |
| **BPFfs map pinning** | `PROCESS_EVENTS` + `RATE_LIMIT_BUCKET` pinned under `/sys/fs/bpf/neuromesh` | Restores rate-limiter and ringbuf map state across agent restarts — zero intentional data loss on controlled recycle |
| **Graceful shutdown** | `CancellationToken` + SIGINT/SIGTERM drain window before BPF link release | Avoids torn-down consumers mid-flight; monitor tasks exit cleanly |
| **Enterprise observability** | Health monitor samples `RATE_LIMIT_DROPS` + channel drops; Prometheus `/metrics` on port 9090 | Unmonitored drops are treated as a production incident — `ebpf_events_dropped_total` surfaces kernel and user-space loss |

### Residual `execve` Risks

- **Verifier-locked skeleton:** `sys_exec.bpf.c` intentionally omits `ctx->args` reads; full argv capture requires a separate verifier-reviewed change.
- **Per-CPU drop accounting:** `RATE_LIMIT_DROPS` is per-CPU; health monitor sums all CPUs but hot NUMA nodes may dominate drops under uneven load.
- **Prometheus scrape gap:** Metrics reflect last health interval; sub-second exec storms require log targets `neuromesh::process_monitor` and `neuromesh::health` for forensic drill-down.

## Residual Risks

- **CO-RE / `ppid` accuracy:** Kernel lineage uses best-effort offsets; `ppid == 0` events are ignored by burst detection.
- **LotL without bursts:** Single whitelisted binary invocations require future Wasm/AI policies (Slow Path).
- **Coverage gate:** CI enforces ≥70% line coverage on core crates; does not yet measure eBPF kernel code (Ring 0).

## Local Developer Workflow

```bash
# No root, no eBPF kernel support required
cargo test -p neuromesh-integration-tests
cargo test -p agent-ebpf-sensor --lib
```

Orchestrator binary (requires eBPF artifact + root):

```bash
cargo build -p agent-ebpf-sensor --features orchestrator --release
```
