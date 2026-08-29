//! Shared agent counters surfaced to Prometheus and periodic health logs.

use anyhow::{Context, Result};
use prometheus::{Counter, CounterVec, Gauge, Opts, Registry};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Instant;

/// Kernel `RLIMIT_DROPS` per-CPU map name (see `sys_exec.bpf.c`).
/// Was `RATE_LIMIT_DROPS` (16 chars; exceeds BPF_OBJ_NAME_LEN-1).
pub use neuromesh_common::RATE_LIMIT_DROPS_MAP;

/// Enterprise observability counters for execve visibility and agent lifecycle.
pub struct AgentMetrics {
    pub registry: Registry,
    pub events_processed: Counter,
    pub events_dropped: Counter,
    pub uptime_seconds: Gauge,
    /// Issue #44 Phase 2 / #75 — labeled by `reason`
    /// (`exe_digest`|`on_disk_binary`|`lsm_link`|`pinned_map`).
    pub integrity_failures: CounterVec,
    /// Slice 2b-i — labeled by `reason`
    /// (`pod_delete`|`cgroup_teardown`|`resync_sweep`).
    pub identity_invalidations: CounterVec,
    /// Slice 2b-i — labeled by `reason`
    /// (`inotify_overflow`|`startup`|`watch_error`).
    pub identity_resyncs: CounterVec,
    /// Issue #176 — PE returned HTTP 429 on GET /v1/policy-bundle (throttled;
    /// distinct from crypto/temporal sync failures).
    pub policy_sync_throttled: Counter,
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

        let identity_invalidations = CounterVec::new(
            Opts::new(
                "identity_correlator_invalidation_total",
                "Slice 2b IDENTITY_ALLOW_CGROUPS invalidations; label reason=pod_delete|cgroup_teardown|resync_sweep|pe_allowlist_revoke",
            ),
            &["reason"],
        )
        .context("failed to create identity_correlator_invalidation_total counter")?;

        let identity_resyncs = CounterVec::new(
            Opts::new(
                "identity_correlator_resync_total",
                "Slice 2b-i forced correlator resyncs; label reason=inotify_overflow|startup|watch_error",
            ),
            &["reason"],
        )
        .context("failed to create identity_correlator_resync_total counter")?;

        let policy_sync_throttled = Counter::with_opts(Opts::new(
            "policy_sync_throttled_total",
            "GET /v1/policy-bundle HTTP 429 from PE (Issue #176); throttled with backoff — not signature/temporal rejection",
        ))
        .context("failed to create policy_sync_throttled_total counter")?;

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
        registry
            .register(Box::new(identity_invalidations.clone()))
            .context("failed to register identity_correlator_invalidation_total")?;
        registry
            .register(Box::new(identity_resyncs.clone()))
            .context("failed to register identity_correlator_resync_total")?;
        registry
            .register(Box::new(policy_sync_throttled.clone()))
            .context("failed to register policy_sync_throttled_total")?;

        Ok(Arc::new(Self {
            registry,
            events_processed,
            events_dropped,
            uptime_seconds,
            integrity_failures,
            identity_invalidations,
            identity_resyncs,
            policy_sync_throttled,
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

    pub fn record_identity_invalidation(&self, reason: &str) {
        self.identity_invalidations
            .with_label_values(&[reason])
            .inc();
    }

    pub fn identity_invalidation_total(&self, reason: &str) -> f64 {
        self.identity_invalidations
            .with_label_values(&[reason])
            .get()
    }

    pub fn record_identity_resync(&self, reason: &str) {
        self.identity_resyncs.with_label_values(&[reason]).inc();
    }

    pub fn identity_resync_total(&self, reason: &str) -> f64 {
        self.identity_resyncs.with_label_values(&[reason]).get()
    }

    pub fn record_policy_sync_throttled(&self) {
        self.policy_sync_throttled.inc();
    }

    pub fn policy_sync_throttled_total(&self) -> f64 {
        self.policy_sync_throttled.get()
    }
}
