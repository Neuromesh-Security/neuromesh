# Neuromesh Performance Baseline — eBPF Sensor Core

## Security Correctness — Verified Separately from Performance

This document measures **throughput, latency, CPU, and drop-rate under sustained load** (Sections 1–4 below). Those load/performance figures remain **partially TBD** as documented in the tables and procedures that follow.

It does **not** measure **security correctness** (whether enforcement and detection work at all). That has been **verified live, separately**, via internal engineering checks:

| Verified behavior | Reference |
|-------------------|-----------|
| LSM enforcement survives agent `kill -9` | [Issue #44](https://github.com/Neuromesh-Security/neuromesh/issues/44) / [PR #72](https://github.com/Neuromesh-Security/neuromesh/pull/72), [`scripts/manual_verify_lsm_pin.sh`](../scripts/manual_verify_lsm_pin.sh) |
| Runtime tamper detection of pinned enforcement artifacts | [PR #74](https://github.com/Neuromesh-Security/neuromesh/pull/74) / [PR #76](https://github.com/Neuromesh-Security/neuromesh/pull/76), [`scripts/manual_verify_runtime_integrity.sh`](../scripts/manual_verify_runtime_integrity.sh) |
| Identity-exception allow / deny / scope / TTL correctness (all 7 scenarios) | [PR #79](https://github.com/Neuromesh-Security/neuromesh/pull/79), [`scripts/manual_verify_identity_exception.sh`](../scripts/manual_verify_identity_exception.sh) |

These two categories are **independent**. Security correctness being verified does **not** by itself prove throughput. The **current tested execve claim** is the post-[#160](https://github.com/Neuromesh-Security/neuromesh/pull/160) standard-tier run on the same **1-vCPU** host: `average_eps=816` (`spawned=24860`, `failed=0`, `elapsed=30.48s`, `workers=128`, `worker_model=std::thread`). That run is still **generator-bound**, not agent-bound. A worker sweep on the same session reported `SWEEP_BEST workers=8 average_eps=738` over 15 s cells — **not** silently interchangeable with 816; see §2.3.2. Historical pre-#160 Tokio-serialized 30 s runs were **880–962** (best **962**, zero RingBuf/MPSC drops). The in-kernel **500k/CPU** token bucket is a fork-bomb **safety valve**, not a measured production rate — see §2.3.1 (production headroom) and §2.3.2 (generator physics).

For the narrative summary of the same live checks, see [Security Verification](../README.md#security-verification) in the repository README.

---

**Status:** Security correctness verified live (see section above) · **§2.3 tested (post-#160, 1 vCPU, generator-bound): standard-tier `average_eps=816`; sweep `SWEEP_BEST` `average_eps=738` at 8 workers** · historical pre-#160 band 880–962 (best 962, zero drops, 3 runs) · §2.3.1 production-headroom justification · §2.3.2 OS-thread generator measured · §2.4 measured (two-phase CPU; full drain-to-idle not captured) · §2.5 measured (Slice 2b-ii correlator overhead, single droplet run, Issue #100) · 500k/CPU token-bucket saturation is **not** a test target  
**Release:** `v0.1.0-core`  
**Date:** 2026-08-22  
**Component:** `apps/agent-ebpf-sensor`  
**Harness:** [Criterion.rs](https://github.com/bheisler/criterion.rs) v0.5 (user space) · `execve_stress_test` (kernel load)  
**Environment:** Linux x86_64, release profile

---

## Executive Summary

The eBPF Sensor Core adds **sub-microsecond user-space detection overhead** on the LSM telemetry hot path. **Live-tested execve throughput after the OS-thread generator fix ([PR #160](https://github.com/Neuromesh-Security/neuromesh/pull/160)) is `average_eps=816`** on the same **1-vCPU** Ubuntu 24.04 BPF-LSM host (`spawned=24860`, `failed=0`, `elapsed=30.48s`, `workers=128`, `worker_model=std::thread`). A 15 s worker sweep in the same session reported `SWEEP_BEST workers=8 average_eps=738` (`host_parallelism=1`). Both figures are **generator-bound**, not agent-bound — same honesty as the historical pre-#160 **962** (30 s Tokio-serialized best). That comfortably exceeds realistic Kubernetes **node process-creation** (tens to low hundreds of `execve`/s; §2.3.1) — about **16×** a conservative typical worker (~50 EPS) at 816, and about **3.7×** a pathological 110-pod exec-probe farm (816 / 220). The BPF token bucket at ~500k/CPU is a **fork-bomb safety valve**, not a tested SLO and not a production-justified target.

| Layer | Median latency | Throughput | Measurement status |
|-------|----------------|------------|-------------------|
| User-space `RuleEngine` (benign) | **115 ns** | **8.69 Melem/s** | Measured (Criterion) |
| User-space `DataNormalizer` (spawn) | **956 ns** | **1.05 Melem/s** | Measured (Criterion) |
| Combined benign detection path | **~1.07 µs** | — | Derived |
| Kernel execve capture (tracepoint) | — | **816 EPS** (post-#160 standard tier); sweep-best **738** | Measured (live, 1 vCPU, generator-bound) |
| RingBuf → user-space drain | — | Kept up at historical ~900 EPS (MPSC default 8192); post-#160 drop counters not in this paste-back | Measured at pre-#160 load; post-#160 generator `failed=0` |

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
| `sys_enter_execve` | `nm_proc_events` | `PROCESS_EVENTS` (**1 MiB** in `sys_exec.bpf.c`) | Per-CPU token bucket (BPF constant ~500k/sec, **fork-bomb valve**) → `RATE_LIMIT_DROPS` |
| `sys_enter_execveat` | `nm_execveat` | `PROCESS_EVENTS` (same 1 MiB buffer) | **Same** per-CPU token bucket → `RATE_LIMIT_DROPS` |
| `tcp_connect` | `nm_tcp_connect` | `NETWORK_EVENTS` (256 KiB) | RingBuf reserve failure → `DROPPED_EVENTS` |
| `bprm_check_security` | `nm_lsm_bprm` | `TELEMETRY_RINGBUF` (256 KiB) | Reserve failure → `TELEMETRY_STATS.lost_events_count` |

User-space exec consumer: `process_monitor.rs` — AsyncFd poller → bounded MPSC (default **8192**) → correlation worker.

**Capacity note for the `execveat` attach (Issue #126):** the second tracepoint did **not** require a RingBuf resize. Both exec programs call the same `rate_limit_allow()` against the same `RLIMIT_BUCKET` per-CPU token bucket, so the *aggregate* admitted rate is still one shared BPF constant (~500k/CPU **safety valve**) rather than one per hook. At 932 B per record (ExecEvent v3, Issue #140) a 1 MiB buffer holds ~1,126 in-flight records. That constant is **not** a tested or production-justified throughput; live-tested generator throughput is post-#160 **`average_eps=816`** (30 s standard) / **`average_eps=738`** (sweep-best), historical pre-#160 **962** (§2.3).

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
| Idle agent | — | **0.400%** of 1 core (§2.5) | _TBD_ (`perf stat` delta) | CPU measured; latency TBD |
| Tested live burst | **816 EPS** post-#160 (`average_eps=816`); historical **880–962** | **~38–41%** during pre-#160 burst (§2.4) | _TBD_ (`perf stat` delta) | EPS measured; post-#160 pidstat not re-run |

> **Graph placeholder:** `docs/assets/perf-execve-latency-overhead.svg` — plot p50/p99 execve latency delta (agent attached vs detached) across EPS tiers. Generate from `perf stat` JSON export after CI run.

### 2.3 RingBuf drop rates

#### Capacity impact of ExecEvent v2 (Issue #46 argv)

`PROCESS_EVENTS` is sized at **1 MiB** (`max_entries = 1024 * 1024` in `sys_exec.bpf.c` — not 256 KiB). Approximate in-flight slots if the consumer stalls:

| Schema | `sizeof(ExecEvent)` | ≈ events fitting in 1 MiB | Fill time at **816 EPS** (post-#160 standard) | Fill time if token bucket saturated (~500k/CPU, **not a test target**) |
|--------|---------------------|---------------------------|-----------------------------------------------|---------------------------------------------------------------------|
| v1 (pre-#46) | 408 B | ≈ **2570** | ≈ **3.2 s** | ≈ **5.1 ms** |
| v2 (with 256 B argv) | 668 B | ≈ **1569** | ≈ **1.9 s** | ≈ **3.1 ms** |
| v3 (argv + allowlisted env, Issue #140) | 932 B | ≈ **1126** | ≈ **1.4 s** | ≈ **2.3 ms** |

v3 is another ~28% reduction in ringbuf depth vs v2 (932/668 ≈ 1.40× bytes/event), in the **same class** as the #46 argv tradeoff. The full env block is **never** copied (scan ≤32 pointers, copy ≤8×32 B allowlisted hits). At post-#160 **`average_eps=816`**, v3 still holds ~1.4 s of in-flight records if the consumer stalls. The ~500k/CPU column is **safety-valve math only**. Operators should watch `ebpf_events_dropped_total` after deploying v3.

#### Kernel-side drops

| Map / counter | Trigger | User-space reader |
|---------------|---------|-------------------|
| `RATE_LIMIT_DROPS` | Token bucket exhausted (BPF constant ~500k evt/s per CPU; **fork-bomb valve**, not a production rate) | Health monitor → `ebpf_events_dropped_total` |
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
```

The older `min(500_000, …)` form described the **BPF safety valve**, not a load we have driven or a production-justified target.

| Load | EPS | Expected kernel drops | Expected user-space drops | Measured drop rate | Status |
|------|-----|----------------------|--------------------------|-------------------|--------|
| **Tested live (this document’s claim)** | **816** (post-#160 30 s standard); sweep-best **738** | — | generator `failed=0` | agent drops **not in this paste-back** | Measured (1 vCPU, generator-bound) |
| Historical pre-#160 | **880–962** | 0 | 0 | **0%** | Measured (3 independent 30 s runs, Tokio-serialized) |
| Typical production worker | ~10–50 | 0 | 0 | — | Derived (§2.3.1); well below tested load |
| Pathological 110-pod exec-probe farm | ~220 | 0 | 0 | — | Derived (§2.3.1); still below tested load |
| Harness “standard” knob | 100k *target* | — | — | — | Generator did not hit this; **not a product SLO** |
| Token-bucket valve | ~500k/CPU | > 0 by design | — | untested | BPF constant; **not a test target** (§2.3.2) |
| Chaos (MPSC=64) | generator-limited | 0 | > 0 (by design) | _TBD_ | Untested |

##### Live measurement note (standard tier, Ubuntu 24.04 BPF-LSM host)

**Pre-#160 (historical, Tokio-serialized, three independent 30 s runs, 128 workers, `/bin/true`, 1 vCPU):**

| Signal | Observed (all three runs) |
|--------|---------------------------|
| Generator `average_eps` | **880–962** (best **962**) |
| Example run detail | `spawned=28868`, `failed=0`, `elapsed=30.00s`, `average_eps=962` |
| `ebpf_events_dropped_total` | **0** throughout every run (zero kernel / MPSC drops before, during, and after) |
| `ebpf_events_processed_total` | Tracks generator volume (example: 12 → 28897, **Δ 28885**) |

**Reproducibility (pre-#160):** The same ~900 EPS band with **zero drops on every run** is a **reproducible** generator-side bottleneck on this hardware class — not a kernel-side drop or rate-limiter problem.

**What bound the generator (pre-[PR #160](https://github.com/Neuromesh-Security/neuromesh/pull/160)):** The harness issued blocking `Command::new("/bin/true").status()` (full `fork`/`posix_spawn`+`execve`+wait) from **async** worker tasks whose loops never `.await`. On a single shared vCPU, Tokio has ~one runtime thread, so one task monopolized that thread until the deadline; the 128-worker knob did not create 128 concurrent spawn pipelines. Process lifetime is ~1 ms per spawn (1/962 s ≈ **1.04 ms**). Aggregate spawn rate saturated at **880–962 EPS**. The agent’s token bucket was never approached — and **does not need to be** for a production-credible claim (§2.3.1).

**Post-#160 (OS-thread generator, same 1-vCPU droplet, `main` with PR #160 merged) — verbatim:**

```
[execve-stress] SWEEP_BEST workers=8 average_eps=738 (generator ceiling on THIS host; not a 500k claim)
[execve-stress] worker sweep host_parallelism=1 duration_secs=15 worker_model=std::thread counts=[1, 8, 32, 128]
[execve-stress] complete spawned=24860 failed=0 elapsed=30.48s average_eps=816 target_eps=100000 workers=128
```

`host_parallelism=1` confirms this is still a **single 1-vCPU** host. `worker_model=std::thread` confirms the OS-thread fix was the generator that ran. Generator `failed=0`. Agent `ebpf_events_dropped_total` was **not** in this paste-back — do not claim zero RingBuf/MPSC drops for the post-#160 session.

**738 vs 816 — do not pick one silently.** These are **two protocols**, not two machines:

| Protocol | Window | Workers | Reported EPS | What it is |
|----------|--------|---------|--------------|------------|
| Worker sweep `SWEEP_BEST` | **15 s** per cell, sequential 1→8→32→128 | **8** (the cell that won) | **738** | Max of four short cells. Later cells can be penalized by leftover fork/`pid`/dcache pressure. |
| Standard tier | **30.48 s** standalone burst | **128** | **816** | Same *class of test* as the historical 962 (30 s, 128 workers). |

On `host_parallelism=1`, 128 OS threads are **oversubscribed**. A 15 s cell at 8 workers can beat 32/128 in the sweep while a longer 128-worker run still averages higher than that 15 s “best.” Single-shot variance on a shared k3s node is also real. **Document both.** For apples-to-apples vs historical 962, use **816** (30 s standard). For “sweep-found ceiling,” use **738** and say it is a **15 s, 8-worker** figure.

**Documented claim:** post-#160, still **generator-bound on 1 vCPU** — **`average_eps=816`** (30 s standard) and **`average_eps=738`** (sweep-best). Comfortably above realistic node process-creation (§2.3.1). Do **not** read this as “the kernel cannot go faster.” Do **not** read it as “we validated 100k or 500k.” OS threads did **not** raise the 1-vCPU generator above historical 962; 816 < 962 is expected when 128 threads fight one core.

**Single-sample caveat (still true until §2.3.3 paste-back):** the post-#160 **816** figure and the pre-#160 **962** best-of-three band are **not** p50/p90 distributions. Historical pre-#160 used **three** independent runs (band only). Use [`scripts/measure_perf_distributions.sh`](../scripts/measure_perf_distributions.sh) for a real multi-run EPS distribution (§2.3.3).

##### 2.3.1 Tested ceiling vs realistic Kubernetes process-creation (2026-08-22)

**Current defensible figure (post-#160, 1 vCPU, generator-bound):** **`average_eps=816`** from the 30 s standard-tier line (apples-to-apples with historical 962). Sweep-best **`average_eps=738`** at 8 workers / 15 s is also measured — see §2.3.2; do not collapse them. Historical pre-#160: **962 EPS** (best of three 30 s runs; `ebpf_events_dropped_total = 0`).

**500k EPS is not a production-justified target.** It is a round BPF constant (`NS_PER_TOKEN = 2000` ns → 1e9/2000 = 500,000) that admits events into the RingBuf during a fork-bomb. Kubernetes does not publish an execve/s SLO. Comparable eBPF security tools (Falco, Tetragon) do not publish an execve-only EPS product ceiling either — so this claim is grounded in **our measurement** plus **Kubernetes’ own scale and probe docs**, not in a competitor bake-off.

**Production execve on a worker node** (order of magnitude, from Kubernetes’ published envelope — not a vendor syscall trace):

Kubernetes is designed for **≤ 110 pods per node** ([Considerations for large clusters](https://kubernetes.io/docs/setup/best-practices/cluster-large/)). An `exec` probe **forks a process on every check**; default `periodSeconds` is **10**, minimum **1**. Official docs warn that exec probes at high density / low period cost node CPU and recommend HTTP/TCP/gRPC instead ([Pod lifecycle](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/), [Configure probes](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/)).

Headroom below uses **816** (post-#160 30 s standard). vs historical 962 the typical-worker multiplier moves **~19× → ~16×** (material: 962/50 vs 816/50). The pathological 110-pod 1 s farm uses the **same formula** (tested EPS / 220). It is **not** a different baseline: 962/220 ≈ **4.4×**, 816/220 ≈ **3.7×**. One-significant-figure “~4×” would hide that drop; the table uses **~3.7×**. Sweep-best 738 would be **~15×** vs ~50 EPS and **~3.4×** vs 220.

| Node scenario | Execve/s (reasoned) | Headroom vs **816 EPS** (post-#160 standard) |
|---------------|---------------------|-----------------------------------------------|
| Quiet long-running worker (HTTP/TCP probes; kubelet + containerd + rare app forks) | ~10–50 | **~16–82×** |
| **Conservative typical (headline)** | **~50** | **~16×** (816 / 50) |
| Max-density, one exec liveness probe, default 10 s period (110 × 1 / 10) | 11 | **~74×** |
| Max-density, exec liveness **and** readiness, default 10 s (110 × 2 / 10) | 22 | **~37×** |
| Pathological anti-pattern: 110 pods × 2 exec probes × 1 s period (Kubernetes warns against this) | 220 | **~3.7×** (816 / 220; historical 962 / 220 ≈ 4.4×) |
| CI/builder bursts (shell, compilers) | hundreds–low thousands | ~1× to a few ×; **not** the typical-worker claim |

**Headline for evaluators:** live-tested at **`average_eps=816`** (post-#160, 1 vCPU, generator-bound; 30 s standard) — about **16×** a conservative typical production worker (~50 execve/s) and about **3.7×** even a pathological 110-pod exec-probe farm (816 / 220). Typical workers using HTTP/TCP probes sit in the tens of execve/s, so headroom is larger than 16×. CI builder nodes can approach this band in bursts; that is a different workload class and is **not** claimed as 16×.

**Still unmeasured (and not required for the production claim above):** `perf stat` execve latency delta; full post-burst drain-to-idle; post-#160 `ebpf_events_dropped_total` (not in the paste-back); whether the BPF token bucket drops when *synthetically* driven at its 500k/CPU constant. Those remain optional lab items, not procurement blockers.

##### 2.3.2 Generator OS-thread fix ([PR #160](https://github.com/Neuromesh-Security/neuromesh/pull/160)) — measured on 1 vCPU

**What changed in code:** `apps/agent-ebpf-sensor/tests/execve_stress_test.rs` now runs **one OS thread per worker** (`std::thread`), each looping blocking `Command::status()`. The test is no longer `#[tokio::test]`. A per-syscall `tokio::task::spawn_blocking` wrapper was **rejected**: it would unblock the runtime but enqueue one blocking-pool job per exec (overhead at the EPS rate) and still share Tokio’s blocking pool. Dedicated threads overlap `wait` with the next spawn without that tax.

**Post-#160 ceiling on the existing 1-vCPU droplet: measured.** Verbatim from the droplet (`worker_model=std::thread`, `host_parallelism=1`):

```
[execve-stress] SWEEP_BEST workers=8 average_eps=738 (generator ceiling on THIS host; not a 500k claim)
[execve-stress] worker sweep host_parallelism=1 duration_secs=15 worker_model=std::thread counts=[1, 8, 32, 128]
[execve-stress] complete spawned=24860 failed=0 elapsed=30.48s average_eps=816 target_eps=100000 workers=128
```

Still a **single 1-vCPU** node. Still **generator-bound** (`/bin/true` fork+exec+wait), not agent-bound. 128/512 worker knobs are **not** 100k/500k capability. Reproduction (already run):

```bash
EXECVE_STRESS_SWEEP=1 cargo test -p agent-ebpf-sensor --test execve_stress_test \
  worker_sweep_finds_generator_ceiling -- --ignored --nocapture

EXECVE_STRESS_TIER=standard cargo test -p agent-ebpf-sensor --test execve_stress_test \
  -- --ignored --nocapture
```

**Is ~500k processes/second realistic from a single generator process?** **No — not with real `/bin/true` fork+exec+wait, and not by “fixing one thread.”** Measured post-#160 on this host is **738–816 EPS**, same order as pre-#160 ~900, orders of magnitude below 500k.

| Setup | What it can actually generate | Why |
|-------|-------------------------------|-----|
| 1 OS thread, full `fork`/`execve`/`wait` of `/bin/true` | ~900 EPS on this 1-vCPU class (**pre-#160 measured**) | Serial process lifetime ≈ 1 ms |
| 1 process, many OS threads, **same** 1-vCPU host (#160) | **Measured:** sweep-best **738** (8 workers, 15 s); standard **816** (128 workers, 30.48 s). **Not** higher than historical 962. Oversubscription on one core. | Threads hide `wait`, they do not create extra CPUs |
| 1 process, many OS threads, many-core **target** host | Scales with cores **until** fork/`pid`/dcache/`ld.so` saturate. Published spawn benches are typically **10k–50k/core** class for tiny binaries, not 500k/core | 500k EPS = **2 µs per process lifetime**. Dynamically linked `/bin/true` is tens of µs **before** fork MM accounting |
| “Distributed generator” on **other machines** | **Does not inject `execve` into the target kernel.** `execve` is a local syscall. Extra droplets cannot bombard this node’s tracepoint | To load **this** agent you must spawn **on this host**, stealing CPU from the agent |

The kernel token bucket (~500k/CPU) is a **safety valve**, not a measured “we have driven 500k execves through the agent.” Hitting it would need a specialized generator on a **many-core target** — **not** required to defend the 816 EPS production claim in §2.3.1. Extra machines and a bigger droplet are **not** the next procurement step.

##### 2.3.3 Multi-run distributions — methodology (single-node)

**Harness:** [`scripts/measure_perf_distributions.sh`](../scripts/measure_perf_distributions.sh) — wraps existing mechanisms only (does **not** reimplement timing):

| Metric family | Underlying tool | Default N | Est. wall-clock (1-vCPU lab) |
|---------------|-----------------|-----------|------------------------------|
| Identity insert / delete invalidation / PE revoke latency | [`manual_verify_identity_2bii_correlation.sh`](../scripts/manual_verify_identity_2bii_correlation.sh) full EXIT=0 trials | **15** | ~45–90 min (revoke sync-bound) |
| Execve `average_eps` (standard tier, 30 s, 128 OS threads) | `EXECVE_STRESS_TIER=standard` `standard_tier` ([PR #160](https://github.com/Neuromesh-Security/neuromesh/pull/160) generator) | **30** | ~20–25 min (+ one-time compile) |

**Sample-size reasoning (not arbitrary):**

- **EPS N=30:** each sample costs ~30 s of burst. N=30 ≈ 10× the historical three-run band, enough for a stable **p50** and a usable exploratory **p90** (~3 observations in the upper decile). Wall-clock stays under ~half an hour of measurement.
- **Identity N=15:** each sample is a full 2b-ii-C gate (agent start + insert + delete + recreate + PE revoke). Threat-model already asked for “5–10×” repeats; **15** sits just above that for a credible **p50** without a multi-hour session. Revoke latency is dominated by `POLICY_SYNC_INTERVAL` (~30 s), so N≫15 has poor cost/benefit on this droplet.
- **p99:** with N=15 or N=30, an empirical “p99” is essentially **max / near-max** — it does **not** estimate the 99th percentile of the process. The harness reports p99 only when **n≥100**; otherwise the summary marks **`insufficient_sample_size`**. Report **min / p50 / p90 / max / mean** as the honest ceiling.

**Envelope:** **single-node k3s only.** Multi-node distribution would differ and is infrastructure-blocked / out of scope for this harness.

**Live results:** _PENDING paste-back_ — replace the placeholder table below after a successful droplet run (`SUMMARY_MD` / `SUMMARY_JSON` from the harness). Until then, keep citing single-sample **816** / 2b-ii-C latencies as **one-shot** figures, not percentiles.

| Metric | n | min | p50 | p90 | p99 | max | mean | wall-clock |
|--------|---|-----|-----|-----|-----|-----|------|------------|
| `execve_standard_average_eps` | 30 | _TBD_ | _TBD_ | _TBD_ | insufficient N | _TBD_ | _TBD_ | _TBD_ |
| `identity_insert_latency_ms` | 15 | _TBD_ | _TBD_ | _TBD_ | insufficient N | _TBD_ | _TBD_ | _TBD_ |
| `identity_delete_invalidation_latency_ms` | 15 | _TBD_ | _TBD_ | _TBD_ | insufficient N | _TBD_ | _TBD_ | _TBD_ |
| `identity_revoke_latency_ms` | 15 | _TBD_ | _TBD_ | _TBD_ | insufficient N | _TBD_ | _TBD_ | _TBD_ |

> **Graph placeholder:** `docs/assets/perf-ringbuf-drop-rate.svg` — time-series of `ebpf_events_dropped_total` / (`processed` + `dropped`) during the tested ~900 EPS burst.

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
| Extreme / token-bucket saturation | n/a | **Not a test target** — BPF fork-bomb valve, not a production rate (§2.3.1–§2.3.2) | Not pursued |
| Full drain-to-idle after burst | _TBD_ | **Unknown beyond the 60s window** — sampling ended while agent was still near-saturated; full drain duration not captured | Follow-up |

**Honest limitation:** Post-burst drain duration **beyond the 60s `pidstat` window is unknown**. If precise drain-to-idle figures are ever needed for procurement, re-run with a longer `pidstat` window (or until `%CPU` returns to idle baseline).

DaemonSet resource defaults (`deploy/kubernetes/neuromesh-agent.yaml`): request **100m** CPU, limit **500m** CPU, limit **512Mi** memory.

> **Graph placeholder:** `docs/assets/perf-cpu-utilization.svg` — agent CPU % vs generator EPS. Two-phase shape (moderate during burst → near-saturation during backlog drain) is the measured pattern at **~900 EPS**.

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

| Tier | Env | Workers | Duration | Meaning |
|------|-----|---------|----------|---------|
| Standard (what was actually run) | `EXECVE_STRESS_TIER=standard` | 128 **OS threads** | 30s | Post-#160: `average_eps=816` (`spawned=24860`, `failed=0`, `elapsed=30.48s`). Historical pre-#160: 880–962. |
| Extreme (harness knob only) | `EXECVE_STRESS_TIER=extreme` | 512 **OS threads** | 60s | Historical 500k *knob* aligned with the BPF token-bucket constant. **Not a production target. Not a validated SLO.** |
| Sweep (measured) | `EXECVE_STRESS_SWEEP=1` | 1, 8, 32, 128 | 15s/cell | Post-#160: `SWEEP_BEST workers=8 average_eps=738`; `host_parallelism=1`; `worker_model=std::thread`. |

### Execution

```bash
# Terminal 1 — orchestrator
cargo run -p agent-ebpf-sensor --features orchestrator --release

# Terminal 2 — worker sweep (measured post-#160: SWEEP_BEST workers=8 average_eps=738)
EXECVE_STRESS_SWEEP=1 cargo test -p agent-ebpf-sensor --test execve_stress_test \
  worker_sweep_finds_generator_ceiling -- --ignored --nocapture

# Terminal 2 — standard tier
EXECVE_STRESS_TIER=standard \
  cargo test -p agent-ebpf-sensor --test execve_stress_test -- --ignored --nocapture

# Terminal 2 — extreme tier (optional; exercises the BPF valve *if* the host can generate enough execve)
# Do not treat a run that fails to reach 500k as a product defect.
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
| `EXECVE_STRESS_WORKERS` | tier-dependent | Concurrent **OS-thread** spawn pipelines (not Tokio tasks) |
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
| **What execve rate is tested?** | Post-#160 (1 vCPU, generator-bound): **`average_eps=816`** (30 s standard, 128 workers); sweep **`SWEEP_BEST workers=8 average_eps=738`**. Historical pre-#160: **962** (band 880–962, zero RingBuf drops, 3 runs). |
| **How does that compare to production?** | **~16×** a conservative typical worker (~50 execve/s) at 816; **~3.7×** a pathological 110-pod exec-probe farm (816 / 220). Typical HTTP-probe workers are tens/s, so headroom is larger. See §2.3.1. |
| What is the 500k/CPU number? | In-kernel **fork-bomb safety valve** (`RATE_LIMIT_BUCKET`). Not a tested SLO and not a production-justified target. |
| What is still unmeasured? | Syscall latency delta (`perf stat`); full post-burst drain-to-idle; post-#160 Prometheus drop counters (not in the paste-back). **Not** “we still owe a 500k run.” |
| Where are graphs? | Placeholders in Section 2; populate into `docs/assets/` |

---

*User-space figures measured 2026-07-12 via Criterion. Historical standard-tier load + pidstat measured 2026-08 (three independent droplet runs, **best 962 EPS**, band 880–962, zero drops, two-phase CPU, **pre-#160 Tokio serialization**). OS-thread generator ([PR #160](https://github.com/Neuromesh-Security/neuromesh/pull/160)) measured 2026-08-22 on the same 1-vCPU host: `worker_model=std::thread`, `host_parallelism=1`, `SWEEP_BEST workers=8 average_eps=738`, standard `spawned=24860 failed=0 elapsed=30.48s average_eps=816`. Production-headroom (§2.3.1): **~16×** a conservative typical K8s worker (~50 execve/s) at 816. Slice 2b-ii correlator overhead measured 2026-08 (Issue #100, single EXIT=0 droplet run: baseline 0.400% / idle 0.617% / churn 3.850% CPU). The BPF 500k/CPU token bucket is a safety valve, not a tested or production-justified throughput.*
