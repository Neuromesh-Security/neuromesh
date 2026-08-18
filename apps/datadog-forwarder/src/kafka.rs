//! Kafka consumer wiring and Prometheus /metrics server.
//!
//! Independent partition fetch (same as Splunk HEC). `kafka_group_id` is logged
//! as operator identity and must stay distinct from `splunk-hec-forwarder` and
//! `ai-threat-detector`. rskafka does not join a Kafka consumer group, so this
//! process cannot steal partitions from another subscriber.

use anyhow::{Context, Result};
use datadog_forwarder::config::ForwarderConfig;
use datadog_forwarder::envelope::TelemetryEnvelope;
use datadog_forwarder::forwarder::DatadogForwarder;
use datadog_forwarder::metrics::DdMetrics;
use rskafka::client::partition::UnknownTopicHandling;
use rskafka::client::ClientBuilder;
use std::sync::Arc;
use tokio::net::TcpListener;

pub async fn run_kafka_consumer(
    config: &ForwarderConfig,
    forwarder: &DatadogForwarder,
    metrics: Arc<DdMetrics>,
) -> Result<()> {
    let client = ClientBuilder::new(config.kafka_brokers.clone())
        .build()
        .await
        .context("kafka client")?;

    let partition_client = client
        .partition_client(config.kafka_topic.clone(), 0, UnknownTopicHandling::Retry)
        .await
        .context("kafka partition client")?;

    tracing::info!(
        brokers = ?config.kafka_brokers,
        topic = %config.kafka_topic,
        group_id = %config.kafka_group_id,
        "Datadog Logs forwarder consuming Kafka slow path (independent fetch)"
    );

    let mut next_offset = 0_i64;

    loop {
        let (records, _high_watermark) = partition_client
            .fetch_records(next_offset, 1..10_000, 1_000)
            .await
            .context("kafka fetch")?;

        if records.is_empty() {
            continue;
        }

        for record in &records {
            let payload = record.record.value.as_deref().unwrap_or(&[]);
            match TelemetryEnvelope::parse_json(payload) {
                Ok(envelope) => forwarder.handle().try_enqueue(envelope),
                Err(error) => {
                    tracing::warn!(%error, "dropping malformed telemetry message");
                    metrics.record_drop("malformed");
                }
            }
        }

        next_offset += records.len() as i64;
    }
}

pub async fn spawn_metrics_server(metrics: Arc<DdMetrics>, port: u16) -> Result<()> {
    use axum::{routing::get, Router};

    async fn metrics_handler(
        axum::extract::State(metrics): axum::extract::State<Arc<DdMetrics>>,
    ) -> Result<String, axum::http::StatusCode> {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let metric_families = metrics.registry.gather();
        let mut buffer = Vec::new();
        encoder
            .encode(&metric_families, &mut buffer)
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok(String::from_utf8(buffer).unwrap_or_default())
    }

    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(metrics);

    let listener = TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .context("bind metrics")?;
    tracing::info!(port, "Prometheus /metrics listening");
    axum::serve(listener, app).await.context("metrics server")?;
    Ok(())
}
