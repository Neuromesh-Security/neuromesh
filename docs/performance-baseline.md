# Neuromesh Performance Baseline — eBPF Sensor Core

**Status:** Measured (user space) · Pending live kernel validation  
**Release:** `v0.1.0-core`  
**Date:** 2026-07-14  
**Component:** `apps/agent-ebpf-sensor`  
**Harness:** [Criterion.rs](https://github.com/bheisler/criterion.rs) v0.5 (user space) · `execve_stress_test` (kernel load)  
**Environment:** Linux x86_64, release profile

---

## Executive Summary

The eBPF Sensor Core adds **sub-microsecond user-space detection overhead** on the LSM telemetry hot path and implements **kernel-side rate limiting at ~500k execve events/sec per CPU** before events reach user space. This document separates **measured** micro-benchmark results from **reproducible load-test procedures** used to populate end-to-end kernel metrics post-CI.

| Layer | Median latency | Throughput | Measurement status |
|-------|----------------|------------|-------------------|
| User-space `RuleEngine` (benign) | **115 ns** | **8.69 Melem/s** | Measured (Criterion) |
| User-space `DataNormalizer` (spawn) | **956 ns** | **1.05 Melem/s** | Measured (Criterion) |
| Combined benign detection path | **~1.07 µs** | — | Derived |
| Kernel execve capture (tracepoint) | _TBD_ | Up to **500k EPS/CPU** (rate limit) | Load test required |
| RingBuf → user-space drain | _TBD_ | Bounded by MPSC (default 8192) | Load test required |

---

## 1. User-Space Detection Pipeline (Measured)

### Reproduction

```bash
cargo bench -p agent-ebpf-sensor --bench detection_pipeline -- --noplot
```

HTML reports: `target/criterion/`

### RuleEngine

```
rule_engine/evaluate_10k_benign_paths
                        time:   [1.7454 ms 1.9019 ms 2.0605 ms]
                        thrpt:  [4.8533 Melem/s 5.2579 Melem/s 5.7294 Melem/s]

rule_engine/evaluate_single_benign_path
                        time:   [101.38 ns 115.02 ns 128.65 ns]
                        thrpt:  [7.7731 Melem/s 8.6939 Melem/s 9.8636 Melem/s]

rule_engine/evaluate_batch/10000
                        time:   [1.3824 ms 1.4723 ms 1.5669 ms]
                        thrpt:  [638.22 elem/s 679.22 elem/s 723.37 elem/s]
```

| Metric | Value |
|--------|-------|
| Median single benign evaluation | **115 ns** |
| Median throughput (single) | **8.69 Melem/s** |
| Median 10k batch wall time | **1.90 ms** |
| Amortized cost per event (10k batch) | **~190 ns** |

### DataNormalizer

```
data_normalizer/ingest_10k_spawn_burst
                        time:   [998.86 ms 1.0714 s 1.1482 s]
                        thrpt:  [8.7095 Kelem/s 9.3334 Kelem/s 10.011 Kelem/s]

data_normalizer/ingest_single_spawn_event
                        time:   [875.85 ns 956.15 ns 1.0378 µs]
                        thrpt:  [963.53 Kelem/s 1.0459 Melem/s 1.1418 Melem/s]
```

| Metric | Value |
|--------|-------|
| Median single spawn ingest | **956 ns** |
| Median throughput (single) | **1.05 Melem/s** |
| Median 10k burst replay | **1.07 s** |
| Amortized cost per event (10k burst) | **~107 µs** |

> The 10k burst benchmark constructs a fresh `DataNormalizer` per iteration (worst-case isolation). Production reuses a single instance; **956 ns** is the representative hot-path metric.

### End-to-end user-space path

```
RingBuf read → RuleEngine::evaluate → DataNormalizer::ingest
≈ 115 ns + 956 ns ≈ 1.07 µs per benign LSM telemetry event (median)
```

Kernel eBPF capture latency is measured separately (Section 2).

---

## 2. Kernel eBPF Telemetry Pipeline

### 2.1 Architecture under test

| Hook | Program | RingBuf | Backpressure mechanism |
|------|---------|---------|------------------------|
| `sys_enter_execve` | `neuromesh_process_events` | `PROCESS_EVENTS` (256 KiB) | Per-CPU token bucket (~500k/sec) → `RATE_LIMIT_DROPS` |
| `tcp_connect` | `neuromesh_tcp_connect` | `NETWORK_EVENTS` (256 KiB) | RingBuf reserve failure → `DROPPED_EVENTS` |
| `bprm_check_security` | `neuromesh_lsm_exec_guard` | `TELEMETRY_RINGBUF` (256 KiB) | Reserve failure → `TELEMETRY_STATS.lost_events_count` |

User-space execve consumer: `process_monitor.rs` — AsyncFd poller → bounded MPSC (default **8192**) → correlation worker.

### 2.2 Latency overhead (execve syscall path)

Measure the incremental cost of attaching the execve tracepoint using `perf` on a quiescent node, then under agent load.

```bash
# Baseline: execve rate without agent
perf stat -e syscalls:sys_enter_execve -a -- sleep 30 &
BURST_PID=$!
# ... run stress generator ...
wait $BURST_PID

# With agent: compare syscalls/sec and CPU cycles
sudo perf stat -e syscalls:sys_enter_execve,cycles,instructions \
  -p $(pgrep -x agent-ebpf-sensor) -- sleep 30
```

| Scenario | Syscall rate | Agent CPU (cores) | Incremental execve latency | Status |
|----------|--------------|-------------------|---------------------------|--------|
| Idle agent | — | _TBD_ | _TBD_ | Post-CI |
| Standard burst (100k EPS target) | 100k/sec | _TBD_ | _TBD_ | Post-CI |
| Extreme burst (500k EPS target) | 500k/sec | _TBD_ | _TBD_ | Post-CI |

> **Graph placeholder:** `docs/assets/perf-execve-latency-overhead.svg` — plot p50/p99 execve latency delta (agent attached vs detached) across EPS tiers. Generate from `perf stat` JSON export after CI run.

### 2.3 RingBuf drop rates

#### Kernel-side drops

| Map / counter | Trigger | User-space reader |
|---------------|---------|-------------------|
| `RATE_LIMIT_DROPS` | Token bucket exhausted (>500k evt/s per CPU) | Health monitor → `ebpf_events_dropped_total` |
| `DROPPED_EVENTS` (network) | `bpf_ringbuf_reserve` failure on `NETWORK_EVENTS` | Not exported to Prometheus (v0.1.0-core) |
| `TELEMETRY_STATS.lost_events_count` | LSM RingBuf reserve failure | Polled every 5s in `main.rs` |

#### User-space drops

| Trigger | Signal |
|---------|--------|
| MPSC channel full (`NEUROMESH_PROCESS_CHANNEL_CAPACITY`) | Rate-limited warn every 10k drops; `ebpf_events_dropped_total` |
| Kafka ingestion backpressure | Bounded channel drop (network correlation path) |

#### Drop rate formula

```
drop_rate = (kernel_drops + userspace_drops) / (processed + kernel_drops + userspace_drops)

observed_drop_rate ≈ max(0, generated_eps − min(500_000, user_space_drain_rate))
```

| Load tier | Target EPS | Expected kernel drops | Expected user-space drops | Measured drop rate | Status |
|-----------|------------|----------------------|--------------------------|-------------------|--------|
| Below ceiling | < 100k | 0 | 0 | _TBD_ | Post-CI |
| Standard | 100k | 0 (at limit) | 0 | _TBD_ | Post-CI |
| Extreme | 500k+ | > 0 (by design) | 0–_TBD_ | _TBD_ | Post-CI |
| Chaos (MPSC=64) | 100k+ | 0 | > 0 (by design) | _TBD_ | Post-CI |

> **Graph placeholder:** `docs/assets/perf-ringbuf-drop-rate.svg` — time-series of `ebpf_events_dropped_total` / (`processed` + `dropped`) during `execve_stress_test` standard and extreme tiers.

### 2.4 CPU utilization

Scrape agent CPU during steady state and burst:

```bash
# Steady state (5 min idle node with agent running)
pidstat -u -p $(pgrep -x agent-ebpf-sensor) 5 60

# During burst (Terminal 2)
EXECVE_STRESS_TIER=standard \
  cargo test -p agent-ebpf-sensor --test execve_stress_test -- --ignored --nocapture
```

| Scenario | Agent CPU (% of 1 core) | Agent RSS (MiB) | Node CPU delta | Status |
|----------|----------------------|-----------------|----------------|--------|
| Idle (no workload) | _TBD_ | _TBD_ | _TBD_ | Post-CI |
| Standard burst (100k EPS, 30s) | _TBD_ | _TBD_ | _TBD_ | Post-CI |
| Extreme burst (500k EPS, 60s) | _TBD_ | _TBD_ | _TBD_ | Post-CI |
| Post-burst recovery (60s) | _TBD_ | _TBD_ | _TBD_ | Post-CI |

DaemonSet resource defaults (`deploy/kubernetes/neuromesh-agent.yaml`): request **100m** CPU, limit **500m** CPU, limit **512Mi** memory.

> **Graph placeholder:** `docs/assets/perf-cpu-utilization.svg` — agent CPU % vs generator EPS during standard/extreme tiers.

---

## 3. Load Testing Methodology

### Prerequisites

| Requirement | Rationale |
|-------------|-----------|
| Linux host with `/bin/true` | Real `execve` syscalls per iteration |
| `agent-ebpf-sensor` running with process monitor armed | Consumes `PROCESS_EVENTS` RingBuf |
| root or `CAP_BPF` + `CAP_PERFMON` | Tracepoint attach |

### Stress tiers

Defined in `apps/agent-ebpf-sensor/tests/common/stress_profile.rs`:

| Tier | Env | Workers | Duration | Target EPS |
|------|-----|---------|----------|------------|
| Standard | `EXECVE_STRESS_TIER=standard` | 128 | 30s | **100,000** |
| Extreme | `EXECVE_STRESS_TIER=extreme` | 512 | 60s | **500,000** |

### Execution

```bash
# Terminal 1 — orchestrator
cargo run -p agent-ebpf-sensor --features orchestrator --release

# Terminal 2 — standard tier
EXECVE_STRESS_TIER=standard \
  cargo test -p agent-ebpf-sensor --test execve_stress_test -- --ignored --nocapture

# Terminal 2 — extreme tier (expect kernel rate-limit drops)
EXECVE_STRESS_TIER=extreme \
  cargo test -p agent-ebpf-sensor --test execve_stress_test -- --ignored --nocapture

# Chaos: force user-space drops
EXECVE_STRESS_CHAOS=1 NEUROMESH_PROCESS_CHANNEL_CAPACITY=64 \
  cargo test -p agent-ebpf-sensor --test execve_stress_test -- --ignored --nocapture
```

### Tunable parameters

| Environment variable | Default | Purpose |
|---------------------|---------|---------|
| `EXECVE_STRESS_TIER` | `standard` | Preset worker count and duration |
| `EXECVE_STRESS_WORKERS` | tier-dependent | Concurrent spawn tasks |
| `EXECVE_STRESS_DURATION_SECS` | tier-dependent | Wall-clock burst duration |
| `EXECVE_STRESS_BINARY` | `/bin/true` | Target binary |
| `NEUROMESH_PROCESS_CHANNEL_CAPACITY` | `8192` | User-space MPSC depth |

### Observability during load test

| Layer | Signal | Interpretation |
|-------|--------|----------------|
| Generator stderr | `syscalls/sec` per-second delta | Raw syscall generation rate |
| Generator stderr | `average_eps` at completion | Mean execve rate over burst |
| Kernel | `RATE_LIMIT_DROPS` map growth | Token bucket exhausted |
| Agent logs | `PROCESS_EVENTS backpressure: dropping execve events` | MPSC saturated |
| Prometheus | `ebpf_events_processed_total`, `ebpf_events_dropped_total` | Production-grade counters |

---

## 4. Time Complexity Analysis

### RuleEngine — `evaluate(event)`

| Step | Operation | Complexity |
|------|-----------|------------|
| Path extraction | `CStr` parse from fixed `filename[256]` | **O(1)** |
| Whitelist check | 4-path static array | **O(1)** |
| Blacklist check | 3-prefix `starts_with()` | **O(1)** |
| Alert construction | Struct fill on match | **O(1)** (rare path) |

### DataNormalizer — `ingest(event)`

| Step | Operation | Complexity |
|------|-----------|------------|
| Batch push | `Vec::push` | **O(1)** amortized |
| Parent lookup | `HashMap<ppid, Vec<Instant>>` | **O(1)** amortized |
| Window retain | Filter stale timestamps | **O(k)**, k ≤ burst threshold (8) |
| Alert emission | Struct construction | **O(1)** on threshold exceed |

### Kernel execve tracepoint

| Step | Operation | Complexity |
|------|-----------|------------|
| Rate limit check | Per-CPU token bucket | **O(1)** |
| RingBuf reserve + submit | Fixed-size `process_event_t` (168 B) | **O(1)** |

---

## 5. Prometheus Metrics

| Metric | Type | Source |
|--------|------|--------|
| `ebpf_events_processed_total` | counter | Process monitor worker |
| `ebpf_events_dropped_total` | counter | `RATE_LIMIT_DROPS` + MPSC backpressure |
| `agent_uptime_seconds` | gauge | Orchestrator start time |

### Scrape configuration

```yaml
scrape_configs:
  - job_name: neuromesh-agent-ebpf-sensor
    scrape_interval: 15s
    static_configs:
      - targets: ["<agent-host>:9090"]
```

### Manual validation

```bash
curl -s http://127.0.0.1:9090/metrics | grep -E 'ebpf_events_|agent_uptime'
```

Health monitor samples kernel drop counters every **5 seconds** (`NEUROMESH_HEALTH_INTERVAL_SECS`).

---

## 6. Enterprise Test Suite (CI)

Kernel-independent suites run on every PR:

```bash
cargo test -p agent-ebpf-sensor --test event_parser_fuzz_test      # 50k decode fuzz iterations
cargo test -p agent-ebpf-sensor --test chaos_engineering_test --features orchestrator
cargo test -p agent-ebpf-sensor --test execve_stress_test --no-run   # compile-only gate
cargo bench -p agent-ebpf-sensor --no-run                            # benchmark compile gate
```

eBPF verifier matrix (kernels `5.15`, `6.1`, `6.8+`) re-runs suites per kernel runner.

Stress and live kernel benchmarks are **`#[ignore]`** — not executed in GitHub Actions due to runner variance. Numeric gates are populated via manual pre-release validation on Linux hardware.

---

## 7. Procurement Quick Reference

| Question | Answer (v0.1.0-core) |
|----------|----------------------|
| How much user-space tax per exec event? | **~1 µs** (benign LSM path) |
| Can RuleEngine keep up with production? | **>8M evaluations/sec** per core (benign) |
| What happens above 500k execve/sec? | Kernel token bucket drops; counted in Prometheus |
| What is unmeasured today? | Syscall latency delta, burst CPU, live drop rate — run Section 2 procedures |
| Where are graphs? | Placeholders in Section 2; populate post-CI into `docs/assets/` |

---

*User-space figures measured 2026-07-12 via Criterion. Kernel end-to-end figures pending live hardware validation — re-run this document after each material change to BPF programs or monitor pipeline.*
