//! Asynchronous Slow Path exporter — decouples Kafka I/O from the eBPF Fast Path.
//!
//! Alerts are enqueued via a bounded MPSC channel using `try_send` (never blocking
//! the RingBuf consumer). A dedicated Tokio task publishes to Kafka in the background.

use crate::normalizer::BehaviorAlert;
use crate::rules::SiemAlert;
use serde::Serialize;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tokio::sync::mpsc;

pub const DEFAULT_TOPIC: &str = "neuromesh.telemetry.v1";
pub const SCHEMA_VERSION: &str = "neuromesh.telemetry.v1";
const DEFAULT_CHANNEL_CAPACITY: usize = 8192;

/// Alert variants eligible for Slow Path export.
#[derive(Debug, Clone)]
pub enum StreamAlert {
    Behavior(BehaviorAlert),
    Critical(SiemAlert),
}

/// Kafka-bound envelope consumed by `apps/ai-threat-detector`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TelemetryKafkaMessage {
    pub event_id: String,
    pub timestamp_ns: i64,
    pub node_name: String,
    pub schema_version: String,
    pub alert_type: String,
    pub payload: serde_json::Value,
}

/// Runtime configuration for the telemetry exporter.
#[derive(Debug, Clone)]
pub struct TelemetryStreamConfig {
    pub brokers: Vec<String>,
    pub topic: String,
    pub node_name: String,
    pub channel_capacity: usize,
}

impl TelemetryStreamConfig {
    pub fn from_env() -> Option<Self> {
        let brokers = std::env::var("NEUROMESH_KAFKA_BROKERS")
            .ok()?
            .split(',')
            .map(str::trim)
            .filter(|broker| !broker.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();

        if brokers.is_empty() {
            return None;
        }

        let topic = std::env::var("NEUROMESH_KAFKA_TOPIC")
            .unwrap_or_else(|_| DEFAULT_TOPIC.to_string());

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
}

/// Non-blocking enqueue surface for the Fast Path hot loop.
#[derive(Clone)]
pub struct TelemetryStreamHandle {
    tx: mpsc::Sender<StreamAlert>,
    stats: Arc<TelemetryStreamStats>,
}

#[derive(Debug, Default)]
pub struct TelemetryStreamStats {
    pub enqueued: AtomicU64,
    pub dropped: AtomicU64,
    pub published: AtomicU64,
    pub failed: AtomicU64,
}

impl TelemetryStreamHandle {
    pub fn try_enqueue_behavior(&self, alert: BehaviorAlert) {
        self.try_enqueue(StreamAlert::Behavior(alert));
    }

    pub fn try_enqueue_critical(&self, alert: SiemAlert) {
        self.try_enqueue(StreamAlert::Critical(alert));
    }

    fn try_enqueue(&self, alert: StreamAlert) {
        match self.tx.try_send(alert) {
            Ok(()) => {
                self.stats.enqueued.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Full(_)) | Err(mpsc::error::TrySendError::Closed(_)) => {
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn stats(&self) -> &TelemetryStreamStats {
        &self.stats
    }
}

/// Spawn exporter when Kafka brokers are configured; otherwise returns a no-op drain.
pub async fn spawn_from_env() -> TelemetryStreamHandle {
    match TelemetryStreamConfig::from_env() {
        Some(config) => spawn(config).await,
        None => spawn_noop().await,
    }
}

/// Spawn a Kafka-backed Slow Path publisher (requires `kafka-stream` feature).
#[cfg(feature = "kafka-stream")]
pub async fn spawn(config: TelemetryStreamConfig) -> TelemetryStreamHandle {
    let (tx, rx) = mpsc::channel(config.channel_capacity);
    let stats = Arc::new(TelemetryStreamStats::default());

    let worker_stats = Arc::clone(&stats);
    tokio::spawn(async move {
        kafka_publisher_loop(rx, config, worker_stats).await;
    });

    TelemetryStreamHandle { tx, stats }
}

#[cfg(feature = "kafka-stream")]
async fn kafka_publisher_loop(
    mut rx: mpsc::Receiver<StreamAlert>,
    config: TelemetryStreamConfig,
    stats: Arc<TelemetryStreamStats>,
) {
    use rskafka::client::partition::Compression;
    use rskafka::record::Record;
    use std::collections::BTreeMap;
    use std::time::Duration;

    let mut partition_client = None;

    while let Some(alert) = rx.recv().await {
        if partition_client.is_none() {
            match connect_partition_client(&config).await {
                Ok(client) => {
                    log::info!(
                        "Kafka Slow Path connected | brokers={:?} topic={}",
                        config.brokers,
                        config.topic
                    );
                    partition_client = Some(client);
                }
                Err(error) => {
                    log::warn!("Kafka connection failed (will retry): {error}");
                    stats.failed.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            }
        }

        let message = match encode_alert(&config.node_name, alert) {
            Ok(message) => message,
            Err(error) => {
                log::warn!("telemetry serialization failed: {error}");
                stats.failed.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };

        let payload = match serde_json::to_vec(&message) {
            Ok(bytes) => bytes,
            Err(error) => {
                log::warn!("telemetry JSON encoding failed: {error}");
                stats.failed.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };

        let record = Record {
            key: Some(message.event_id.into_bytes()),
            value: Some(payload),
            headers: BTreeMap::from([
                ("schema_version".to_owned(), SCHEMA_VERSION.as_bytes().to_vec()),
                (
                    "alert_type".to_owned(),
                    message.alert_type.as_bytes().to_vec(),
                ),
            ]),
            timestamp: chrono::Utc::now(),
        };

        let client = partition_client.as_ref().unwrap();
        if let Err(error) = client.produce(vec![record], Compression::default()).await {
            log::warn!("Kafka publish failed (resetting client): {error}");
            stats.failed.fetch_add(1, Ordering::Relaxed);
            partition_client = None;
            continue;
        }

        stats.published.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(feature = "kafka-stream")]
async fn connect_partition_client(
    config: &TelemetryStreamConfig,
) -> Result<rskafka::client::partition::PartitionClient, anyhow::Error> {
    use rskafka::client::partition::UnknownTopicHandling;
    use rskafka::client::ClientBuilder;

    let client = ClientBuilder::new(config.brokers.clone())
        .build()
        .await?;

    let partition_client = client
        .partition_client(
            config.topic.clone(),
            0,
            UnknownTopicHandling::Retry,
        )
        .await?;

    Ok(partition_client)
}

/// No-op drain when Kafka is not configured (local dev / benchmark mode).
pub async fn spawn_noop() -> TelemetryStreamHandle {
    let (tx, mut rx) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
    let stats = Arc::new(TelemetryStreamStats::default());

    tokio::spawn(async move {
        while rx.recv().await.is_some() {
            stats.published.fetch_add(1, Ordering::Relaxed);
        }
    });

    TelemetryStreamHandle { tx, stats }
}

#[cfg(not(feature = "kafka-stream"))]
pub async fn spawn(_config: TelemetryStreamConfig) -> TelemetryStreamHandle {
    spawn_noop().await
}

pub fn encode_alert(
    node_name: &str,
    alert: StreamAlert,
) -> Result<TelemetryKafkaMessage, serde_json::Error> {
    match alert {
        StreamAlert::Behavior(alert) => encode_behavior_alert(node_name, alert),
        StreamAlert::Critical(alert) => encode_critical_alert(node_name, alert),
    }
}

fn encode_behavior_alert(
    node_name: &str,
    alert: BehaviorAlert,
) -> Result<TelemetryKafkaMessage, serde_json::Error> {
    let timestamp_ns = parse_rfc3339_ns(&alert.timestamp);
    Ok(TelemetryKafkaMessage {
        event_id: format!("{}-{}-{}", alert.rule_id, alert.ppid, alert.last_pid),
        timestamp_ns,
        node_name: node_name.to_string(),
        schema_version: SCHEMA_VERSION.to_string(),
        alert_type: alert.severity.clone(),
        payload: serde_json::to_value(alert)?,
    })
}

fn encode_critical_alert(
    node_name: &str,
    alert: SiemAlert,
) -> Result<TelemetryKafkaMessage, serde_json::Error> {
    let timestamp_ns = parse_rfc3339_ns(&alert.timestamp);
    Ok(TelemetryKafkaMessage {
        event_id: format!("{}-{}-{}", alert.rule_id, alert.pid, alert.ppid),
        timestamp_ns,
        node_name: node_name.to_string(),
        schema_version: SCHEMA_VERSION.to_string(),
        alert_type: alert.severity.clone(),
        payload: serde_json::to_value(alert)?,
    })
}

fn parse_rfc3339_ns(timestamp: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(timestamp)
        .map(|value| value.timestamp_nanos_opt().unwrap_or(0))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalizer::SEVERITY_BEHAVIOR_ALERT;
    use crate::rules::SEVERITY_CRITICAL_ALERT;

    #[test]
    fn encodes_critical_alert_for_kafka_consumer() {
        let message = encode_critical_alert(
            "node-a",
            SiemAlert {
                timestamp: "2026-07-12T10:00:00Z".to_string(),
                severity: SEVERITY_CRITICAL_ALERT.to_string(),
                rule_id: "NEUROMESH-EXEC-BLACKLIST-PATH".to_string(),
                rule_name: "Execution from ephemeral malware staging directory".to_string(),
                pid: 42,
                ppid: 1,
                uid: 1000,
                euid: 1000,
                comm: "bash".to_string(),
                binary_path: "/tmp/evil.bin".to_string(),
                matched_pattern: "/tmp/".to_string(),
            },
        )
        .expect("serialization");

        assert_eq!(message.schema_version, SCHEMA_VERSION);
        assert_eq!(message.alert_type, SEVERITY_CRITICAL_ALERT);
        assert_eq!(message.node_name, "node-a");
    }

    #[test]
    fn encodes_behavior_alert_for_kafka_consumer() {
        let message = encode_behavior_alert(
            "node-b",
            BehaviorAlert {
                timestamp: "2026-07-12T10:00:01Z".to_string(),
                severity: SEVERITY_BEHAVIOR_ALERT.to_string(),
                rule_id: "NEUROMESH-EXEC-SPAWN-BURST".to_string(),
                rule_name: "Abnormal process execution burst from single parent".to_string(),
                ppid: 4242,
                spawn_count: 8,
                window_secs: 2,
                last_pid: 110,
                last_comm: "bash".to_string(),
                last_binary_path: "/usr/bin/bash".to_string(),
            },
        )
        .expect("serialization");

        assert_eq!(message.alert_type, SEVERITY_BEHAVIOR_ALERT);
        assert!(message.payload.get("spawn_count").is_some());
    }

    #[tokio::test]
    async fn enqueue_is_non_blocking() {
        let handle = spawn_noop().await;
        let alert = BehaviorAlert {
            timestamp: "2026-07-12T10:00:01Z".to_string(),
            severity: SEVERITY_BEHAVIOR_ALERT.to_string(),
            rule_id: "NEUROMESH-EXEC-SPAWN-BURST".to_string(),
            rule_name: "burst".to_string(),
            ppid: 1,
            spawn_count: 8,
            window_secs: 2,
            last_pid: 1,
            last_comm: "bash".to_string(),
            last_binary_path: "/usr/bin/bash".to_string(),
        };

        handle.try_enqueue_behavior(alert);
        assert_eq!(handle.stats().enqueued.load(Ordering::Relaxed), 1);
    }
}
