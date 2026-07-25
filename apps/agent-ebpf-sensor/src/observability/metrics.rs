//! Shared agent counters surfaced to Prometheus and periodic health logs.

use anyhow::{Context, Result};
use prometheus::{Counter, CounterVec, Gauge, Opts, Registry};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Instant;

/// Kernel `RATE_LIMIT_DROPS` per-CPU map name (see `sys_exec.bpf.c`).
pub const RATE_LIMIT_DROPS_MAP: &str = "RATE_LIMIT_DROPS";

/// Enterprise observability counters for execve visibility and agent lifecycle.
pub struct AgentMetrics {
    pub registry: Registry,
    pub events_processed: Counter,
    pub events_dropped: Counter,
    pub uptime_seconds: Gauge,
    /// Issue #44 Phase 2 / #75 — labeled by `reason`
    /// (`exe_digest`|`on_disk_binary`|`lsm_link`|`pinned_map`).
    pub integrity_failures: CounterVec,
    userspace_drops: AtomicU64,
    started_at: Instant,
}

impl AgentMetrics {
    pub fn new() -> Result<Arc<Self>> {
        let registry = Registry::new();

        let events_processed = Counter::with_opts(Opts::new(
            "ebpf_events_processed_total",
            "execve visibility events accepted by the user-space process monitor",
        ))
        .context("failed to create ebpf_events_processed_total counter")?;

        let events_dropped = Counter::with_opts(Opts::new(
            "ebpf_events_dropped_total",
            "execve events dropped by kernel token-bucket rate limiting and user-space MPSC backpressure",
        ))
        .context("failed to create ebpf_events_dropped_total counter")?;

        let uptime_seconds = Gauge::with_opts(Opts::new(
            "agent_uptime_seconds",
            "Wall-clock seconds since the agent orchestrator started",
        ))
        .context("failed to create agent_uptime_seconds gauge")?;

        let integrity_failures = CounterVec::new(
            Opts::new(
                "agent_integrity_failure_total",
                "Runtime integrity check failures (Issue #44 Phase 2 / #75); label reason=exe_digest|on_disk_binary|lsm_link|pinned_map",
            ),
            &["reason"],
        )
        .context("failed to create agent_integrity_failure_total counter")?;

        registry
            .register(Box::new(events_processed.clone()))
            .context("failed to register ebpf_events_processed_total")?;
        registry
            .register(Box::new(events_dropped.clone()))
            .context("failed to register ebpf_events_dropped_total")?;
        registry
            .register(Box::new(uptime_seconds.clone()))
            .context("failed to register agent_uptime_seconds")?;
        registry
            .register(Box::new(integrity_failures.clone()))
            .context("failed to register agent_integrity_failure_total")?;

        Ok(Arc::new(Self {
            registry,
            events_processed,
            events_dropped,
            uptime_seconds,
            integrity_failures,
            userspace_drops: AtomicU64::new(0),
            started_at: Instant::now(),
        }))
    }

    pub fn record_event_processed(&self) {
        self.events_processed.inc();
    }

    pub fn record_userspace_drop(&self) {
        self.userspace_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn userspace_drops(&self) -> u64 {
        self.userspace_drops.load(Ordering::Relaxed)
    }

    pub fn inc_dropped_by(&self, delta: u64) {
        if delta > 0 {
            self.events_dropped.inc_by(delta as f64);
        }
    }

    pub fn reconcile_userspace_drops(&self, last_seen: &mut u64) {
        let current = self.userspace_drops();
        let delta = current.saturating_sub(*last_seen);
        *last_seen = current;
        self.inc_dropped_by(delta);
    }

    pub fn refresh_uptime(&self) {
        self.uptime_seconds
            .set(self.started_at.elapsed().as_secs_f64());
    }

    pub fn processed_total(&self) -> f64 {
        self.events_processed.get()
    }

    pub fn dropped_total(&self) -> f64 {
        self.events_dropped.get()
    }

    pub fn record_integrity_failure(&self, reason: &str) {
        self.integrity_failures.with_label_values(&[reason]).inc();
    }

    pub fn integrity_failure_total(&self, reason: &str) -> f64 {
        self.integrity_failures.with_label_values(&[reason]).get()
    }
}
