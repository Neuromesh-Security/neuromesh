//! Prometheus counters for Datadog Logs forwarding outcomes.

use anyhow::{Context, Result};
use prometheus::{Counter, CounterVec, Gauge, Opts, Registry};
use std::sync::Arc;

pub struct DdMetrics {
    pub registry: Registry,
    pub forwarded_total: Counter,
    pub failed_total: CounterVec,
    pub dropped_total: CounterVec,
    pub queue_depth: Gauge,
}

impl DdMetrics {
    pub fn new() -> Result<Arc<Self>> {
        let registry = Registry::new();

        let forwarded_total = Counter::with_opts(Opts::new(
            "dd_forwarded_total",
            "Alerts successfully delivered to Datadog Logs API v2",
        ))
        .context("dd_forwarded_total")?;

        let failed_total = CounterVec::new(
            Opts::new(
                "dd_forward_failed_total",
                "Datadog Logs delivery failures; label reason=retryable|non_retryable|network",
            ),
            &["reason"],
        )
        .context("dd_forward_failed_total")?;

        let dropped_total = CounterVec::new(
            Opts::new(
                "dd_forward_dropped_total",
                "Alerts dropped before Datadog send; label reason=queue_full|malformed",
            ),
            &["reason"],
        )
        .context("dd_forward_dropped_total")?;

        let queue_depth = Gauge::with_opts(Opts::new(
            "dd_forward_queue_depth",
            "Current depth of the bounded Datadog send queue",
        ))
        .context("dd_forward_queue_depth")?;

        registry.register(Box::new(forwarded_total.clone()))?;
        registry.register(Box::new(failed_total.clone()))?;
        registry.register(Box::new(dropped_total.clone()))?;
        registry.register(Box::new(queue_depth.clone()))?;

        Ok(Arc::new(Self {
            registry,
            forwarded_total,
            failed_total,
            dropped_total,
            queue_depth,
        }))
    }

    pub fn record_success(&self) {
        self.forwarded_total.inc();
    }

    pub fn record_failure(&self, reason: &str) {
        self.failed_total.with_label_values(&[reason]).inc();
    }

    pub fn record_drop(&self, reason: &str) {
        self.dropped_total.with_label_values(&[reason]).inc();
    }

    pub fn set_queue_depth(&self, depth: usize) {
        self.queue_depth.set(depth as f64);
    }
}
