//! High-throughput, decoupled Kafka ingestion for correlated network visibility events.

mod channel;
mod encoder;

#[cfg(feature = "kafka-ingestion")]
mod kafka_producer;

pub use channel::{
    CorrelationIngestionConfig, CorrelationIngestionHandle, CorrelationIngestionStats,
    PRESSURE_DROP_THRESHOLD_PCT,
};
pub use encoder::ProtobufEncoder;

#[cfg(feature = "kafka-ingestion")]
pub use kafka_producer::KafkaProducerManager;

#[cfg(feature = "kafka-ingestion")]
use crate::monitoring::EnrichedNetworkEvent;
use std::sync::Arc;

/// Spawn a Kafka-backed correlation ingestion pipeline when brokers are configured.
#[cfg(feature = "kafka-ingestion")]
pub async fn spawn_from_env() -> CorrelationIngestionHandle {
    match CorrelationIngestionConfig::from_env() {
        Some(config) => spawn(config).await,
        None => spawn_noop().await,
    }
}

#[cfg(not(feature = "kafka-ingestion"))]
pub async fn spawn_from_env() -> CorrelationIngestionHandle {
    spawn_noop().await
}

/// Spawn the bounded-channel + rdkafka publisher loop.
#[cfg(feature = "kafka-ingestion")]
pub async fn spawn(config: CorrelationIngestionConfig) -> CorrelationIngestionHandle {
    let (handle, rx) = CorrelationIngestionHandle::new(config.clone());
    let stats = Arc::clone(handle.stats());

    tokio::spawn(async move {
        if let Err(error) = kafka_publisher_loop(rx, config, stats).await {
            tracing::error!(target: "neuromesh::ingestion", "ingestion publisher exited: {error:#}");
        }
    });

    handle
}

#[cfg(feature = "kafka-ingestion")]
async fn kafka_publisher_loop(
    mut rx: tokio::sync::mpsc::Receiver<EnrichedNetworkEvent>,
    config: CorrelationIngestionConfig,
    stats: Arc<CorrelationIngestionStats>,
) -> anyhow::Result<()> {
    use std::time::Duration;

    let manager = KafkaProducerManager::new(&config)?;
    let mut encoder = ProtobufEncoder::with_capacity(256);

    while let Some(event) = rx.recv().await {
        stats.decrement_queued();

        let timestamp_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let event_id = format!("{}-{}-{}", config.node_name, event.pid, timestamp_ns);

        let payload = match encoder.encode_enriched_network_event(
            &config.node_name,
            &event_id,
            timestamp_ns,
            &event,
        ) {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::warn!(
                    target: "neuromesh::ingestion",
                    "protobuf serialization failed: {error:#}"
                );
                stats.record_publish_failure();
                continue;
            }
        };

        if let Err(error) = manager
            .send(&config.topic, event_id.as_bytes(), payload)
            .await
        {
            tracing::warn!(
                target: "neuromesh::ingestion",
                "kafka publish failed: {error:#}"
            );
            stats.record_publish_failure();
            if !manager.health_check() {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            continue;
        }

        stats.record_published();
    }

    Ok(())
}

/// Drain correlated events without Kafka (local dev / tests).
pub async fn spawn_noop() -> CorrelationIngestionHandle {
    let config = CorrelationIngestionConfig {
        brokers: String::new(),
        topic: String::new(),
        node_name: "noop-node".to_string(),
        channel_capacity: channel::DEFAULT_CHANNEL_CAPACITY,
    };
    let (handle, mut rx) = CorrelationIngestionHandle::new(config);
    let stats = Arc::clone(handle.stats());

    tokio::spawn(async move {
        while rx.recv().await.is_some() {
            stats.decrement_queued();
            stats.record_published();
        }
    });

    handle
}

#[cfg(not(feature = "kafka-ingestion"))]
pub async fn spawn(_config: CorrelationIngestionConfig) -> CorrelationIngestionHandle {
    spawn_noop().await
}
