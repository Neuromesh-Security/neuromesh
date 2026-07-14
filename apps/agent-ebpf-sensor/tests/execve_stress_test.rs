//! High-velocity `execve` syscall generator for kernel rate-limiter and user-space
//! backpressure validation.
//!
//! # Usage (Linux, agent running with process monitor armed)
//!
//! ```bash
//! # Default: 64 workers × 30s burst via /bin/true
//! cargo test -p agent-ebpf-sensor --test execve_stress_test -- --ignored --nocapture
//!
//! # Aggressive burst tuned to exceed 500k/sec kernel token bucket
//! EXECVE_STRESS_WORKERS=256 EXECVE_STRESS_DURATION_SECS=60 \
//!   cargo test -p agent-ebpf-sensor --test execve_stress_test -- --ignored --nocapture
//! ```
//!
//! Watch agent stdout/stderr for:
//! - Kernel-side: `RATE_LIMIT_DROPS` map growth (via bpftool if instrumented)
//! - User-space: `PROCESS_EVENTS backpressure: dropping execve events (user-space channel full)`

use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const DEFAULT_WORKERS: usize = 64;
const DEFAULT_DURATION_SECS: u64 = 30;
const DEFAULT_TARGET_BINARY: &str = "/bin/true";

struct StressConfig {
    workers: usize,
    duration: Duration,
    binary: Arc<str>,
}

impl StressConfig {
    fn from_env() -> Self {
        let workers = std::env::var("EXECVE_STRESS_WORKERS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_WORKERS);
        let duration_secs = std::env::var("EXECVE_STRESS_DURATION_SECS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_DURATION_SECS);
        let binary = std::env::var("EXECVE_STRESS_BINARY")
            .unwrap_or_else(|_| DEFAULT_TARGET_BINARY.to_string());

        Self {
            workers: workers.max(1),
            duration: Duration::from_secs(duration_secs.max(1)),
            binary: Arc::from(binary.as_str()),
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
async fn worker_loop(deadline: Instant, binary: Arc<str>, metrics: Arc<StressMetrics>) {
    while Instant::now() < deadline {
        if fire_execve(&binary) {
            metrics.record_success();
        } else {
            metrics.record_failure();
        }
    }
}

#[cfg(unix)]
async fn metrics_reporter(deadline: Instant, metrics: Arc<StressMetrics>) {
    let mut last_total = 0u64;
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    while Instant::now() < deadline {
        interval.tick().await;
        let current = metrics.spawned();
        let delta = current.saturating_sub(last_total);
        eprintln!(
            "[execve-stress] syscalls/sec: {delta} | cumulative: {current} | failed: {}",
            metrics.failed()
        );
        last_total = current;
    }
}

#[cfg(unix)]
async fn run_stress_burst(config: &StressConfig) -> (u64, u64) {
    let deadline = Instant::now() + config.duration;
    let metrics = Arc::new(StressMetrics::new());

    let mut workers = Vec::with_capacity(config.workers);
    for _ in 0..config.workers {
        let binary = Arc::clone(&config.binary);
        let metrics = Arc::clone(&metrics);
        workers.push(tokio::spawn(async move {
            worker_loop(deadline, binary, metrics).await;
        }));
    }

    let reporter_metrics = Arc::clone(&metrics);
    let reporter = tokio::spawn(async move {
        metrics_reporter(deadline, reporter_metrics).await;
    });

    for worker in workers {
        let _ = worker.await;
    }
    reporter.abort();

    (metrics.spawned(), metrics.failed())
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "manual Linux load test — run with: cargo test -p agent-ebpf-sensor --test execve_stress_test -- --ignored --nocapture"]
async fn bombard_execve_for_rate_limit_validation() {
    let config = StressConfig::from_env();
    eprintln!(
        "[execve-stress] starting burst workers={} duration={}s binary={}",
        config.workers,
        config.duration.as_secs(),
        config.binary
    );
    eprintln!(
        "[execve-stress] target: trigger RATE_LIMIT_DROPS (kernel) and channel-full warnings (user-space)"
    );

    let started = Instant::now();
    let (spawned, failed) = run_stress_burst(&config).await;
    let elapsed = started.elapsed().as_secs_f64().max(f64::EPSILON);
    let average_eps = spawned as f64 / elapsed;

    eprintln!(
        "[execve-stress] complete spawned={spawned} failed={failed} elapsed={elapsed:.2}s average_eps={average_eps:.0}"
    );

    assert!(
        spawned > 0,
        "expected at least one successful execve syscall"
    );
}

#[cfg(not(unix))]
#[test]
#[ignore = "execve stress test requires a Unix host"]
fn bombard_execve_requires_unix() {
    eprintln!("[execve-stress] skipped: requires Linux/macOS with /bin/true");
}
