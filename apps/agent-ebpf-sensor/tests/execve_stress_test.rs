//! High-velocity `execve` syscall generator for kernel rate-limiter and user-space
//! backpressure validation.
//!
//! # Why OS threads (not Tokio tasks / per-call `spawn_blocking`)
//!
//! `Command::status()` is a blocking `fork`/`posix_spawn` + `execve` + `wait`.
//! The previous harness spawned **async** worker tasks whose loops **never
//! `.await`**. On a 1-vCPU host Tokio has ~one runtime thread, so one task
//! monopolized that thread until the deadline; the other 127 "workers" never
//! ran. Measured result: ~880–962 EPS regardless of the 128-worker knob
//! (docs/performance-baseline.md §2.3, generator-bound).
//!
//! Wrapping **each** `Command::status()` in `tokio::task::spawn_blocking` would
//! unblock the runtime but would enqueue one blocking-pool job per exec (~the
//! EPS rate) and still share Tokio's blocking pool. Dedicated **OS threads**
//! (one fork+exec+wait pipeline each) overlap `wait` with the next spawn
//! without per-syscall task-queue tax. That is the generator we actually want
//! to measure.
//!
//! # Usage (Linux, agent running with process monitor armed)
//!
//! ```bash
//! # Standard tier (~100k eps *target*): 128 OS threads × 30s
//! EXECVE_STRESS_TIER=standard cargo test -p agent-ebpf-sensor --test execve_stress_test -- --ignored --nocapture
//!
//! # Extreme tier (~500k eps *target*): 512 OS threads × 60s
//! EXECVE_STRESS_TIER=extreme cargo test -p agent-ebpf-sensor --test execve_stress_test -- --ignored --nocapture
//!
//! # Worker sweep — find the generator ceiling on THIS machine before buying
//! # bigger hardware (15s per cell unless EXECVE_STRESS_DURATION_SECS is set):
//! EXECVE_STRESS_SWEEP=1 cargo test -p agent-ebpf-sensor --test execve_stress_test worker_sweep_finds_generator_ceiling -- --ignored --nocapture
//!
//! # Chaos pairing — shrink agent channel + watch /metrics during burst
//! EXECVE_STRESS_CHAOS=1 EXECVE_STRESS_TIER=extreme \
//!   cargo test -p agent-ebpf-sensor --test execve_stress_test -- --ignored --nocapture
//! ```
//!
//! Watch agent stdout/stderr for:
//! - Kernel-side: `RATE_LIMIT_DROPS` map growth (via bpftool if instrumented)
//! - User-space: `PROCESS_EVENTS backpressure: dropping execve events (user-space channel full)`

mod common;

use common::{ChaosHints, StressTier};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_TARGET_BINARY: &str = "/bin/true";

/// Worker counts for `EXECVE_STRESS_SWEEP=1` (cheap droplet ladder).
const SWEEP_WORKER_COUNTS: &[usize] = &[1, 8, 32, 128];

struct StressConfig {
    tier: StressTier,
    workers: usize,
    duration: Duration,
    binary: Arc<str>,
    chaos: ChaosHints,
}

impl StressConfig {
    fn from_env() -> Self {
        let tier = StressTier::from_env();
        let workers = std::env::var("EXECVE_STRESS_WORKERS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| tier.default_workers());
        let duration_secs = std::env::var("EXECVE_STRESS_DURATION_SECS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| tier.default_duration_secs());
        let binary = std::env::var("EXECVE_STRESS_BINARY")
            .unwrap_or_else(|_| DEFAULT_TARGET_BINARY.to_string());

        Self {
            tier,
            workers: workers.max(1),
            duration: Duration::from_secs(duration_secs.max(1)),
            binary: Arc::from(binary.as_str()),
            chaos: ChaosHints::from_env(),
        }
    }
}

struct StressMetrics {
    spawned: AtomicU64,
    failed: AtomicU64,
}

impl StressMetrics {
    fn new() -> Self {
        Self {
            spawned: AtomicU64::new(0),
            failed: AtomicU64::new(0),
        }
    }

    fn record_success(&self) {
        self.spawned.fetch_add(1, Ordering::Relaxed);
    }

    fn record_failure(&self) {
        self.failed.fetch_add(1, Ordering::Relaxed);
    }

    fn spawned(&self) -> u64 {
        self.spawned.load(Ordering::Relaxed)
    }

    fn failed(&self) -> u64 {
        self.failed.load(Ordering::Relaxed)
    }
}

/// Blocking `fork`/`posix_spawn` + `execve` + wait. Call only from an OS thread
/// (never from a Tokio worker thread).
#[inline]
fn fire_execve(binary: &str) -> bool {
    Command::new(binary)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(unix)]
fn worker_loop(deadline: Instant, binary: Arc<str>, metrics: Arc<StressMetrics>) {
    while Instant::now() < deadline {
        if fire_execve(&binary) {
            metrics.record_success();
        } else {
            metrics.record_failure();
        }
    }
}

#[cfg(unix)]
fn metrics_reporter(deadline: Instant, metrics: Arc<StressMetrics>, target_eps: u64) {
    let mut last_total = 0u64;

    while Instant::now() < deadline {
        thread::sleep(Duration::from_secs(1));
        if Instant::now() > deadline {
            break;
        }
        let current = metrics.spawned();
        let delta = current.saturating_sub(last_total);
        let pct = (delta as f64 / target_eps as f64) * 100.0;
        eprintln!(
            "[execve-stress] syscalls/sec: {delta} ({pct:.1}% of {target_eps} target) | cumulative: {current} | failed: {}",
            metrics.failed()
        );
        last_total = current;
    }
}

#[cfg(unix)]
fn host_parallelism() -> String {
    match thread::available_parallelism() {
        Ok(n) => n.get().to_string(),
        Err(_) => "unknown".to_string(),
    }
}

#[cfg(unix)]
struct BurstOutcome {
    spawned: u64,
    failed: u64,
    average_eps: f64,
    elapsed_secs: f64,
    workers: usize,
}

#[cfg(unix)]
fn run_stress_burst(config: &StressConfig) -> BurstOutcome {
    let deadline = Instant::now() + config.duration;
    let metrics = Arc::new(StressMetrics::new());
    let started = Instant::now();

    let mut workers = Vec::with_capacity(config.workers);
    for i in 0..config.workers {
        let binary = Arc::clone(&config.binary);
        let metrics = Arc::clone(&metrics);
        let handle = thread::Builder::new()
            .name(format!("execve-stress-{i}"))
            .spawn(move || worker_loop(deadline, binary, metrics))
            .unwrap_or_else(|err| panic!("failed to spawn OS-thread worker {i}: {err}"));
        workers.push(handle);
    }

    let reporter_metrics = Arc::clone(&metrics);
    let target_eps = config.tier.target_eps();
    let reporter = thread::Builder::new()
        .name("execve-stress-reporter".into())
        .spawn(move || {
            metrics_reporter(deadline, reporter_metrics, target_eps);
        })
        .expect("failed to spawn metrics reporter thread");

    let mut join_panics = 0u64;
    for handle in workers {
        if handle.join().is_err() {
            join_panics += 1;
        }
    }
    let _ = reporter.join();

    if join_panics > 0 {
        eprintln!("[execve-stress] WARNING: {join_panics} worker thread(s) panicked");
    }

    let spawned = metrics.spawned();
    let failed = metrics.failed();
    let elapsed_secs = started.elapsed().as_secs_f64().max(f64::EPSILON);
    BurstOutcome {
        spawned,
        failed,
        average_eps: spawned as f64 / elapsed_secs,
        elapsed_secs,
        workers: config.workers,
    }
}

#[cfg(unix)]
fn log_burst_banner(config: &StressConfig) {
    eprintln!(
        "[execve-stress] tier={:?} workers={} duration={}s binary={} target_eps={} worker_model=std::thread host_parallelism={}",
        config.tier,
        config.workers,
        config.duration.as_secs(),
        config.binary,
        config.tier.target_eps(),
        host_parallelism()
    );
}

#[cfg(unix)]
fn run_tiered_burst(tier: StressTier) {
    std::env::set_var(
        "EXECVE_STRESS_TIER",
        match tier {
            StressTier::Standard => "standard",
            StressTier::Extreme => "extreme",
        },
    );

    let config = StressConfig::from_env();
    config.chaos.log_guidance();
    log_burst_banner(&config);

    let outcome = run_stress_burst(&config);
    eprintln!(
        "[execve-stress] complete spawned={} failed={} elapsed={:.2}s average_eps={:.0} target_eps={} workers={}",
        outcome.spawned,
        outcome.failed,
        outcome.elapsed_secs,
        outcome.average_eps,
        config.tier.target_eps(),
        outcome.workers
    );

    assert!(
        outcome.spawned > 0,
        "expected at least one successful execve syscall"
    );
}

#[cfg(unix)]
fn run_worker_sweep() {
    let duration_secs = std::env::var("EXECVE_STRESS_DURATION_SECS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(15);
    std::env::set_var("EXECVE_STRESS_DURATION_SECS", duration_secs.to_string());
    std::env::set_var("EXECVE_STRESS_TIER", "standard");

    eprintln!(
        "[execve-stress] worker sweep host_parallelism={} duration_secs={duration_secs} worker_model=std::thread counts={SWEEP_WORKER_COUNTS:?}",
        host_parallelism()
    );
    eprintln!("[execve-stress] SWEEP_HEADER workers spawned failed elapsed_s average_eps");

    let mut max_eps = 0.0f64;
    let mut max_workers = 0usize;
    for &workers in SWEEP_WORKER_COUNTS {
        std::env::set_var("EXECVE_STRESS_WORKERS", workers.to_string());
        let config = StressConfig::from_env();
        log_burst_banner(&config);
        let outcome = run_stress_burst(&config);
        eprintln!(
            "[execve-stress] SWEEP_ROW {} {} {} {:.2} {:.0}",
            outcome.workers,
            outcome.spawned,
            outcome.failed,
            outcome.elapsed_secs,
            outcome.average_eps
        );
        if outcome.average_eps > max_eps {
            max_eps = outcome.average_eps;
            max_workers = outcome.workers;
        }
        assert!(
            outcome.spawned > 0,
            "expected at least one successful execve syscall at workers={workers}"
        );
    }

    eprintln!(
        "[execve-stress] SWEEP_BEST workers={max_workers} average_eps={max_eps:.0} (generator ceiling on THIS host; not a 500k claim)"
    );
}

#[cfg(unix)]
#[test]
#[ignore = "manual Linux load test — standard tier (~100k eps target): cargo test -p agent-ebpf-sensor --test execve_stress_test standard_tier -- --ignored --nocapture"]
fn standard_tier_execve_burst_targets_100k_eps() {
    run_tiered_burst(StressTier::Standard);
}

#[cfg(unix)]
#[test]
#[ignore = "manual Linux load test — extreme tier (~500k eps target): cargo test -p agent-ebpf-sensor --test execve_stress_test extreme_tier -- --ignored --nocapture"]
fn extreme_tier_execve_burst_targets_500k_eps() {
    run_tiered_burst(StressTier::Extreme);
}

#[cfg(unix)]
#[test]
#[ignore = "manual Linux load test — legacy entrypoint: cargo test -p agent-ebpf-sensor --test execve_stress_test bombard_execve -- --ignored --nocapture"]
fn bombard_execve_for_rate_limit_validation() {
    run_tiered_burst(StressTier::from_env());
}

#[cfg(unix)]
#[test]
#[ignore = "manual Linux generator ceiling: EXECVE_STRESS_SWEEP=1 cargo test -p agent-ebpf-sensor --test execve_stress_test worker_sweep_finds_generator_ceiling -- --ignored --nocapture"]
fn worker_sweep_finds_generator_ceiling() {
    run_worker_sweep();
}

#[cfg(not(unix))]
#[test]
#[ignore = "execve stress test requires a Unix host"]
fn execve_stress_requires_unix() {
    eprintln!("[execve-stress] skipped: requires Linux/macOS with /bin/true");
}
