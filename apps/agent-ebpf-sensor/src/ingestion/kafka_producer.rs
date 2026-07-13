//! Idempotent rdkafka producer with delivery guarantees for correlated events.

use anyhow::Context;
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord, Producer};
use rdkafka::util::Timeout;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::CorrelationIngestionConfig;

/// Owns the rdkafka producer and exposes health-check + publish APIs.
pub struct KafkaProducerManager {
    producer: FutureProducer,
    healthy: AtomicBool,
    delivery_timeout: Duration,
}

impl KafkaProducerManager {
    pub fn new(config: &CorrelationIngestionConfig) -> anyhow::Result<Self> {
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", &config.brokers)
            .set("enable.idempotence", "true")
            .set("acks", "all")
            .set("delivery.timeout.ms", "30000")
            .set("message.timeout.ms", "30000")
            .create()
            .context("failed to create idempotent rdkafka producer")?;

        let manager = Self {
            producer,
            healthy: AtomicBool::new(true),
            delivery_timeout: Duration::from_millis(30_000),
        };

        if !manager.health_check() {
            tracing::warn!(
                target: "neuromesh::ingestion",
                "kafka producer created but initial metadata health-check failed"
            );
        }

        Ok(manager)
    }

    /// Uses rdkafka's metadata fetch as a lightweight connection heartbeat.
    pub fn health_check(&self) -> bool {
        let healthy = self
            .producer
            .client()
            .fetch_metadata(None, Timeout::After(Duration::from_secs(5)))
            .is_ok();
        self.healthy.store(healthy, Ordering::Relaxed);
        healthy
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    pub async fn send(&self, topic: &str, key: &[u8], payload: &[u8]) -> anyhow::Result<()> {
        let record = FutureRecord::to(topic).key(key).payload(payload);
        self.producer
            .send(record, self.delivery_timeout)
            .await
            .map_err(|(error, _)| error)
            .context("rdkafka delivery failed")?;
        self.healthy.store(true, Ordering::Relaxed);
        Ok(())
    }
}
