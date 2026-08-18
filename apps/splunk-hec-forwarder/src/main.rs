use anyhow::Result;
use splunk_hec_forwarder::config::ForwarderConfig;
use splunk_hec_forwarder::metrics::HecMetrics;
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
            "Splunk HEC forwarding inactive (set {} + {} + {})",
            splunk_hec_forwarder::config::SPLUNK_HEC_URL_ENV,
            splunk_hec_forwarder::config::SPLUNK_HEC_TOKEN_FILE_ENV,
            splunk_hec_forwarder::config::KAFKA_BROKERS_ENV,
        );
        return Ok(());
    };

    let metrics = HecMetrics::new()?;
    let metrics_for_server = Arc::clone(&metrics);
    let forwarder =
        splunk_hec_forwarder::forwarder::SplunkForwarder::spawn(&config, Arc::clone(&metrics));

    let metrics_port = config.metrics_port;
    tokio::spawn(async move {
        if let Err(error) = kafka::spawn_metrics_server(metrics_for_server, metrics_port).await {
            tracing::error!(%error, "metrics server exited");
        }
    });

    kafka::run_kafka_consumer(&config, &forwarder, metrics).await
}
