//! Bounded MPSC channel with pressure-aware drop policy for the correlation hot path.

use crate::monitoring::EnrichedNetworkEvent;
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc,
};
use tokio::sync::mpsc;

pub const DEFAULT_CHANNEL_CAPACITY: usize = 8192;
pub const PRESSURE_DROP_THRESHOLD_PCT: usize = 90;
pub const DEFAULT_CORRELATION_TOPIC: &str = "neuromesh.correlation.v1";

/// Runtime configuration for the correlation ingestion pipeline.
#[derive(Debug, Clone)]
pub struct CorrelationIngestionConfig {
    pub brokers: String,
    pub topic: String,
    pub node_name: String,
    pub channel_capacity: usize,
}

impl CorrelationIngestionConfig {
    pub fn from_env() -> Option<Self> {
        let brokers = std::env::var("NEUROMESH_KAFKA_BROKERS").ok()?;
        if brokers.trim().is_empty() {
            return None;
        }

        let topic = std::env::var("NEUROMESH_KAFKA_CORRELATION_TOPIC")
            .unwrap_or_else(|_| DEFAULT_CORRELATION_TOPIC.to_string());

        let node_name = std::env::var("NEUROMESH_NODE_NAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "unknown-node".to_string());

        let channel_capacity = std::env::var("NEUROMESH_KAFKA_CHANNEL_CAPACITY")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_CHANNEL_CAPACITY);

        Some(Self {
            brokers,
            topic,
            node_name,
            channel_capacity,
        })
    }

    pub fn pressure_drop_threshold(&self) -> usize {
        self.channel_capacity
            .saturating_mul(PRESSURE_DROP_THRESHOLD_PCT)
            .saturating_div(100)
    }
}

#[derive(Debug, Default)]
pub struct CorrelationIngestionStats {
    enqueued: AtomicU64,
    dropped_events: AtomicU64,
    published: AtomicU64,
    publish_failures: AtomicU64,
    queued: AtomicUsize,
}

impl CorrelationIngestionStats {
    pub fn enqueued(&self) -> u64 {
        self.enqueued.load(Ordering::Relaxed)
    }

    pub fn dropped_events(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }

    pub fn published(&self) -> u64 {
        self.published.load(Ordering::Relaxed)
    }

    pub fn publish_failures(&self) -> u64 {
        self.publish_failures.load(Ordering::Relaxed)
    }

    pub fn queued(&self) -> usize {
        self.queued.load(Ordering::Relaxed)
    }

    /// Test-only helper to simulate channel occupancy without enqueueing.
    #[doc(hidden)]
    pub fn testing_set_queued(&self, value: usize) {
        self.queued.store(value, Ordering::Relaxed);
    }

    pub(crate) fn record_enqueued(&self) {
        self.enqueued.fetch_add(1, Ordering::Relaxed);
        self.queued.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_dropped(&self) {
        self.dropped_events.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn decrement_queued(&self) {
        self.queued.fetch_sub(1, Ordering::Relaxed);
    }

    pub(crate) fn record_published(&self) {
        self.published.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(feature = "kafka-ingestion")]
    pub(crate) fn record_publish_failure(&self) {
        self.publish_failures.fetch_add(1, Ordering::Relaxed);
    }
}

/// Non-blocking enqueue surface for the eBPF correlation hot loop.
#[derive(Clone)]
pub struct CorrelationIngestionHandle {
    tx: mpsc::Sender<EnrichedNetworkEvent>,
    stats: Arc<CorrelationIngestionStats>,
    drop_threshold: usize,
}

impl CorrelationIngestionHandle {
    pub(crate) fn new(
        config: CorrelationIngestionConfig,
    ) -> (Self, mpsc::Receiver<EnrichedNetworkEvent>) {
        let (tx, rx) = mpsc::channel(config.channel_capacity);
        let handle = Self {
            tx,
            stats: Arc::new(CorrelationIngestionStats::default()),
            drop_threshold: config.pressure_drop_threshold(),
        };
        (handle, rx)
    }

    /// Test/diagnostic constructor exposing the receiver for verification.
    #[doc(hidden)]
    pub fn new_for_test(
        config: CorrelationIngestionConfig,
    ) -> (Self, mpsc::Receiver<EnrichedNetworkEvent>) {
        Self::new(config)
    }

    /// Enqueue a correlated network event without blocking the RingBuf consumer.
    #[inline]
    pub fn try_enqueue(&self, event: EnrichedNetworkEvent) {
        if self.should_apply_drop_policy() {
            self.stats.record_dropped();
            let (pid, uid, dest_ip, dest_port) =
                (event.pid, event.uid, event.dest_ip, event.dest_port);
            tracing::warn!(
                target: "neuromesh::ingestion",
                pid,
                uid,
                dest_ip,
                dest_port,
                queued = self.stats.queued(),
                drop_threshold = self.drop_threshold,
                dropped_events = self.stats.dropped_events(),
                "dropping low-priority correlated network event at channel pressure"
            );
            return;
        }

        match self.tx.try_send(event) {
            Ok(()) => {
                self.stats.record_enqueued();
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.stats.record_dropped();
                tracing::warn!(
                    target: "neuromesh::ingestion",
                    queued = self.stats.queued(),
                    dropped_events = self.stats.dropped_events(),
                    "dropping correlated network event: ingestion channel full"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.stats.record_dropped();
                tracing::warn!(
                    target: "neuromesh::ingestion",
                    "dropping correlated network event: ingestion channel closed"
                );
            }
        }
    }

    pub fn stats(&self) -> &Arc<CorrelationIngestionStats> {
        &self.stats
    }

    #[inline]
    fn should_apply_drop_policy(&self) -> bool {
        self.stats.queued() >= self.drop_threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pressure_threshold_defaults_to_ninety_percent() {
        let config = CorrelationIngestionConfig {
            brokers: "localhost:9092".to_string(),
            topic: DEFAULT_CORRELATION_TOPIC.to_string(),
            node_name: "node-a".to_string(),
            channel_capacity: 100,
        };
        assert_eq!(config.pressure_drop_threshold(), 90);
    }

    #[tokio::test]
    async fn drops_when_channel_at_pressure_threshold() {
        let config = CorrelationIngestionConfig {
            brokers: String::new(),
            topic: String::new(),
            node_name: "node-a".to_string(),
            channel_capacity: 10,
        };
        let (handle, _rx) = CorrelationIngestionHandle::new_for_test(config);
        handle.stats().testing_set_queued(9);

        let event = EnrichedNetworkEvent {
            pid: 1,
            uid: 1000,
            dest_ip: u32::from_be_bytes([1, 1, 1, 1]),
            dest_port: 443,
            process_name: "curl".to_string(),
        };

        handle.try_enqueue(event);
        assert_eq!(handle.stats.dropped_events(), 1);
        assert_eq!(handle.stats.enqueued(), 0);
    }
}
