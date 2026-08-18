use anyhow::Result;
use datadog_forwarder::config::ForwarderConfig;
use datadog_forwarder::metrics::DdMetrics;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

mod kafka;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let Some(config) = ForwarderConfig::from_env() else {
        tracing::info!(
            "Datadog Logs forwarding inactive (set {} or {} + {} + {})",
            datadog_forwarder::config::DATADOG_SITE_ENV,
            datadog_forwarder::config::DATADOG_LOGS_URL_ENV,
            datadog_forwarder::config::DATADOG_API_KEY_FILE_ENV,
            datadog_forwarder::config::KAFKA_BROKERS_ENV,
        );
        return Ok(());
    };

    let metrics = DdMetrics::new()?;
    let metrics_for_server = Arc::clone(&metrics);
    let forwarder =
        datadog_forwarder::forwarder::DatadogForwarder::spawn(&config, Arc::clone(&metrics));

    let metrics_port = config.metrics_port;
    tokio::spawn(async move {
        if let Err(error) = kafka::spawn_metrics_server(metrics_for_server, metrics_port).await {
            tracing::error!(%error, "metrics server exited");
        }
    });

    kafka::run_kafka_consumer(&config, &forwarder, metrics).await
}
