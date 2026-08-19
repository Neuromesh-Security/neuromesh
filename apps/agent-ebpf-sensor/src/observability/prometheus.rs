//! Lightweight Prometheus `/metrics` and Kubernetes `/healthz` on one listener.

use crate::observability::healthz::AgentHealthProbe;
use crate::observability::metrics::AgentMetrics;
use anyhow::{Context, Result};
use axum::http::StatusCode;
use axum::{routing::get, Router};
use prometheus::TextEncoder;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::info;

const DEFAULT_METRICS_PORT: u16 = 9090;

async fn metrics_handler(metrics: Arc<AgentMetrics>) -> Result<String, axum::http::StatusCode> {
    metrics.refresh_uptime();
    let encoder = TextEncoder::new();
    let metric_families = metrics.registry.gather();
    encoder
        .encode_to_string(&metric_families)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)
}

async fn healthz_handler(probe: Arc<AgentHealthProbe>) -> (StatusCode, [(axum::http::HeaderName, &'static str); 1], String) {
    let report = probe.evaluate();
    let body = AgentHealthProbe::to_json(&report);
    let status = if report.live {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
}

/// Bind a dedicated HTTP listener for Prometheus `/metrics` and `/healthz`.
pub async fn spawn_metrics_server(
    metrics: Arc<AgentMetrics>,
    health: Arc<AgentHealthProbe>,
    cancel: CancellationToken,
) -> Result<()> {
    let port = std::env::var("NEUROMESH_METRICS_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_METRICS_PORT);

    let app = Router::new()
        .route(
            "/metrics",
            get({
                let metrics = Arc::clone(&metrics);
                move || {
                    let metrics = Arc::clone(&metrics);
                    async move { metrics_handler(metrics).await }
                }
            }),
        )
        .route(
            "/healthz",
            get({
                let health = Arc::clone(&health);
                move || {
                    let health = Arc::clone(&health);
                    async move { healthz_handler(health).await }
                }
            }),
        );

    let listener = TcpListener::bind(("0.0.0.0", port))
        .await
        .with_context(|| format!("failed to bind Prometheus metrics listener on port {port}"))?;

    info!(
        target: "neuromesh::metrics",
        port,
        "Prometheus /metrics and /healthz exporter armed"
    );

    let shutdown = cancel.clone();
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                shutdown.cancelled().await;
            })
            .await
        {
            tracing::warn!(
                target: "neuromesh::metrics",
                error = %error,
                "Prometheus metrics server exited with error"
            );
        }
    });

    Ok(())
}
