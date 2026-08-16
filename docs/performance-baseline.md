# Neuromesh Performance Baseline — eBPF Sensor Core

## Security Correctness — Verified Separately from Performance

This document measures **throughput, latency, CPU, and drop-rate under sustained load** (Sections 1–4 below). Those load/performance figures remain **partially TBD** as documented in the tables and procedures that follow.

It does **not** measure **security correctness** (whether enforcement and detection work at all). That has been **verified live, separately**, via internal engineering checks:

| Verified behavior | Reference |
|-------------------|-----------|
| LSM enforcement survives agent `kill -9` | [Issue #44](https://github.com/Neuromesh-Security/neuromesh/issues/44) / [PR #72](https://github.com/Neuromesh-Security/neuromesh/pull/72), [`scripts/manual_verify_lsm_pin.sh`](../scripts/manual_verify_lsm_pin.sh) |
| Runtime tamper detection of pinned enforcement artifacts | [PR #74](https://github.com/Neuromesh-Security/neuromesh/pull/74) / [PR #76](https://github.com/Neuromesh-Security/neuromesh/pull/76), [`scripts/manual_verify_runtime_integrity.sh`](../scripts/manual_verify_runtime_integrity.sh) |
| Identity-exception allow / deny / scope / TTL correctness (all 7 scenarios) | [PR #79](https://github.com/Neuromesh-Security/neuromesh/pull/79), [`scripts/manual_verify_identity_exception.sh`](../scripts/manual_verify_identity_exception.sh) |

These two categories are **independent**. Security correctness being verified does **not** close the high-throughput performance/load TBDs in this document — those require generating load near the documented EPS tier targets. Three independent live standard-tier stress runs have now been executed (see §2.3–§2.4); they validated **zero-drop correctness and two-phase agent CPU behavior at ~880–962 EPS only**, not kernel rate-limiter behavior near the 500k/CPU ceiling.

For the narrative summary of the same live checks, see [Security Verification](../README.md#security-verification) in the repository README.

---

**Status:** Security correctness verified live (see section above) · §2.3 measured (generator-bound ~880–962 EPS, zero drops, 3 independent runs) · §2.4 measured (two-phase CPU documented; full drain-to-idle not captured) · §2.5 measured (Slice 2b-ii correlator overhead, single droplet run, Issue #100) · Extreme tier / kernel rate-limiter saturation untested pending stronger hardware  
**Release:** `v0.1.0-core`  
**Date:** 2026-08-03  
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
| `sys_enter_execve` | `nm_proc_events` | `PROCESS_EVENTS` (**1 MiB** in `sys_exec.bpf.c`) | Per-CPU token bucket (~500k/sec) → `RATE_LIMIT_DROPS` |
| `sys_enter_execveat` | `nm_execveat` | `PROCESS_EVENTS` (same 1 MiB buffer) | **Same** per-CPU token bucket → `RATE_LIMIT_DROPS` |
| `tcp_connect` | `nm_tcp_connect` | `NETWORK_EVENTS` (256 KiB) | RingBuf reserve failure → `DROPPED_EVENTS` |
| `bprm_check_security` | `nm_lsm_bprm` | `TELEMETRY_RINGBUF` (256 KiB) | Reserve failure → `TELEMETRY_STATS.lost_events_count` |

User-space exec consumer: `process_monitor.rs` — AsyncFd poller → bounded MPSC (default **8192**) → correlation worker.

**Capacity note for the `execveat` attach (Issue #126):** the second tracepoint did **not** require a RingBuf resize. Both exec programs call the same `rate_limit_allow()` against the same `RLIMIT_BUCKET` per-CPU token bucket, so the *aggregate* admitted rate is still one ~500k EPS ceiling rather than one per hook — the figures below remain the governing numbers. At 668 B per record a 1 MiB buffer holds ~1,569 in-flight records, unchanged. `execveat`/`fexecve` are also a small fraction of real exec traffic, and any additional pressure surfaces in the existing `RATE_LIMIT_DROPS` and MPSC backpressure counters rather than silently.

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

#### Capacity impact of ExecEvent v2 (Issue #46 argv)

`PROCESS_EVENTS` is sized at **1 MiB** (`max_entries = 1024 * 1024` in `sys_exec.bpf.c` — not 256 KiB). Approximate in-flight slots if the consumer stalls:

| Schema | `sizeof(ExecEvent)` | ≈ events fitting in 1 MiB | Fill time at 500k EPS (rate-limit ceiling) |
|--------|---------------------|---------------------------|---------------------------------------------|
| v1 (pre-#46) | 408 B | ≈ **2570** | ≈ **5.1 ms** |
| v2 (with 256 B argv) | 668 B | ≈ **1569** | ≈ **3.1 ms** |

That is a **~39% reduction** in ringbuf depth (668/408 ≈ 1.64× bytes/event). Under a real execve burst (the same class of load that drives `DataNormalizer` spawn-burst `BEHAVIOR_ALERT`s), `bpf_ringbuf_reserve` failures become **more likely** if userspace drain lags — this is a real increase in drop risk, not negligible. Primary backpressure remains the per-CPU **500k EPS token bucket** (`RATE_LIMIT_DROPS`); ringbuf depth is the secondary cushion. Operators should watch `ebpf_events_dropped_total` and `PROCESS_EVENTS backpressure` logs after deploying v2.

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
| Below ceiling | < 100k | 0 | 0 | **0%** (measured @ ~880–962 EPS, 3 runs) | Measured (live) |
| Standard | 100k | 0 (at limit) | 0 | **0%** (measured @ ~880–962 EPS achieved; see note) | Measured at low load only |
| Extreme | 500k+ | > 0 (by design) | 0–_TBD_ | _TBD_ | Untested — hardware cannot generate load |
| Chaos (MPSC=64) | 100k+ | 0 | > 0 (by design) | _TBD_ | Untested |

##### Live measurement note (standard tier, Ubuntu 24.04 BPF-LSM host)

Three independent standard-tier harness runs (`EXECVE_STRESS_TIER=standard`, 128 workers, 30s, `/bin/true`) on a **single shared vCPU** droplet:

| Signal | Observed (all three runs) |
|--------|---------------------------|
| Generator `average_eps` | **880–962** (`target_eps=100000`) — ≈0.9–1.0% of target |
| Example run detail | `spawned=28868`, `failed=0`, `elapsed=30.00s`, `average_eps=962` |
| `ebpf_events_dropped_total` | **0** throughout every run (zero kernel / MPSC drops before, during, and after) |
| `ebpf_events_processed_total` | Tracks generator volume (example: 12 → 28897, **Δ 28885**) |

**Reproducibility:** Hitting the same ~900 EPS band with **zero drops on every run** is evidence that this ceiling is a **reproducible generator-side bottleneck** on this hardware class — not a fluke and not a kernel-side drop or rate-limiter problem.

**Root cause (generator-bound, not kernel-bound):** The stress harness issues blocking `Command::new("/bin/true").status()` (full `fork`+`execve`+wait) from async worker tasks. On a single shared vCPU, Tokio effectively serializes that work onto ~one runtime thread, so aggregate spawn rate saturates near ~900 EPS regardless of the 128-worker knob. The agent’s ~500k/CPU token bucket was never approached.

**Interpretation (do not over-read):** These runs validate **zero-drop correctness at low–moderate load only**. They do **not** validate behavior near the **500k/CPU** token-bucket ceiling.

**Still genuinely untested:** extreme tier, kernel rate-limiter drop-by-design behavior, and any procurement claim that assumes sustained ≥100k EPS through the agent. Those require a follow-up on stronger hardware capable of generating sufficient execve load; until then the corresponding rows remain real TBDs — not implied by these results.

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

##### Live measurement (standard tier, concurrent `pidstat`)

`pidstat -u -p $(pgrep -x agent-ebpf-sensor) 5 60` on the same 1-vCPU droplet class (60s window, **12 samples @ 5s**), overlapping a 30s standard-tier burst:

| Phase | Agent CPU (% of 1 core) | Notes | Status |
|-------|-------------------------|-------|--------|
| During 30s burst | **~38–41%** total (`%usr` ~38%, `%wait` ~7–9%) | Agent is **not** CPU-bound during ingest; generator spawn rate remains the limiter | Measured |
| Immediately after burst (remainder of 60s window) | **~92–99.8%** total (`%wait` ~0%) | Near-saturated — consistent with draining a kernel-event backlog emitted during the burst, not idle | Measured |
| Average across all 12 samples | **67.97%** `%usr` · **69.31%** total CPU | Window mixes burst + post-burst drain; do not treat as steady-state load | Measured |
| Idle (no workload) | **0.400%** | Correlator-off baseline from Issue #100 (see §2.5); confirms RingBuf idle-spin fix (#103) remains stable vs pre-fix ~93–97% | Measured (single run) |
| Extreme burst (500k EPS target) | _TBD_ | Untested — hardware cannot generate load | Untested |
| Full drain-to-idle after burst | _TBD_ | **Unknown beyond the 60s window** — sampling ended while agent was still near-saturated; full drain duration not captured | Follow-up |

**Honest limitation:** Post-burst drain duration **beyond the 60s `pidstat` window is unknown**. If precise drain-to-idle figures are ever needed for procurement, re-run with a longer `pidstat` window (or until `%CPU` returns to idle baseline).

DaemonSet resource defaults (`deploy/kubernetes/neuromesh-agent.yaml`): request **100m** CPU, limit **500m** CPU, limit **512Mi** memory.

> **Graph placeholder:** `docs/assets/perf-cpu-utilization.svg` — agent CPU % vs generator EPS during standard/extreme tiers. Two-phase shape (moderate during burst → near-saturation during backlog drain) is the measured pattern at ~900 EPS.

### 2.5 Slice 2b-ii Correlator Overhead

Isolates the Slice 2b-ii identity correlator tax (K8s pod watch + inotify + BPF map churn) from base agent overhead. Measured on the neuromesh-dev-lab droplet with [`scripts/manual_measure_correlator_overhead.sh`](../scripts/manual_measure_correlator_overhead.sh) ([Issue #100](https://github.com/Neuromesh-Security/neuromesh/issues/100)): three sequential `pidstat` windows on the same host, correlator off → correlator on idle (full K8s-connected watch, no pod churn) → correlator on under multi-container pod create/delete churn. Harness exit **EXIT=0**.

| Phase | `MEASURED_*_CPU_PCT` | `MEASURED_*_RSS_KB` |
|-------|----------------------|---------------------|
| Baseline (correlator off, idle) | **0.400** | **82069** |
| Correlator idle (watch armed, no churn) | **0.617** | **91344** |
| Correlator churn (3-container pod create/delete loop) | **3.850** | **98212** |

**Reading the deltas (same run):**

| Derived signal | Value | Meaning |
|----------------|-------|---------|
| Baseline idle CPU | **0.400%** | Confirms the RingBuf/AsyncFd idle-spin fix ([Issue #103](https://github.com/Neuromesh-Security/neuromesh/issues/103)) remains stable (pre-fix idle was ~**93–97%** of one core) |
| Correlator-idle tax | **~0.22** percentage points (`0.617 − 0.400`) | Cost of K8s API connection + node-local watch + inotify poll with **no** pod churn |
| Correlator churn vs idle | **~6×** idle CPU (`3.850 / 0.617`) | Real event-processing cost under multi-container pod create/delete |

**Honesty caveat (same as every other single-run figure in this document):** these six numbers are from **one** successful droplet run (`EXIT=0`, all three phases). They are reproducible methodology and a credible order-of-magnitude baseline for procurement discussion — not a multi-run statistical distribution. Re-run the harness after material correlator or watch-path changes before treating the deltas as frozen SLOs.

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

eBPF verifier matrix re-runs suites on two honest runner/kernel cells:
`ubuntu-22.04 / ~6.8-azure` and `ubuntu-24.04 / ~6.17-azure` (not three LTS lines).

Stress and live kernel benchmarks are **`#[ignore]`** — not executed in GitHub Actions due to runner variance. Numeric gates are populated via manual pre-release validation on Linux hardware.

---

## 7. Procurement Quick Reference

| Question | Answer (v0.1.0-core) |
|----------|----------------------|
| How much user-space tax per exec event? | **~1 µs** (benign LSM path) |
| Can RuleEngine keep up with production? | **>8M evaluations/sec** per core (benign) |
| What happens above 500k execve/sec? | Kernel token bucket drops; counted in Prometheus |
| What is unmeasured today? | Syscall latency delta; full post-burst drain-to-idle; high-EPS / kernel rate-limiter drops (extreme). Measured: zero drops @ ~880–962 EPS (3 runs, §2.3); two-phase burst/drain CPU (§2.4); idle baseline **0.400%** + correlator idle/churn (§2.5, Issue #100, single run) |
| Where are graphs? | Placeholders in Section 2; populate post-CI into `docs/assets/` |

---

*User-space figures measured 2026-07-12 via Criterion. Live standard-tier load + pidstat measured 2026-08 (three independent droplet runs, ~880–962 EPS, zero drops, two-phase CPU). Slice 2b-ii correlator overhead measured 2026-08 (Issue #100, single EXIT=0 droplet run: baseline 0.400% / idle 0.617% / churn 3.850% CPU). High-throughput kernel end-to-end figures still pending stronger hardware — re-run this document after each material change to BPF programs or monitor pipeline.*
