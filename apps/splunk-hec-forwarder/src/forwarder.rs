//! Bounded-queue forwarder worker — same discipline as agent `telemetry_stream`.

use crate::config::ForwarderConfig;
use crate::envelope::TelemetryEnvelope;
use crate::hec::{build_hec_event, HecEventBody, HecSendOutcome, SplunkHecClient};
use crate::metrics::HecMetrics;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

#[derive(Debug, Default)]
pub struct ForwarderStats {
    pub enqueued: AtomicU64,
    pub dropped: AtomicU64,
    pub forwarded: AtomicU64,
    pub failed: AtomicU64,
}

#[derive(Clone)]
pub struct ForwarderHandle {
    tx: mpsc::Sender<TelemetryEnvelope>,
    stats: Arc<ForwarderStats>,
    metrics: Arc<HecMetrics>,
}

impl ForwarderHandle {
    pub fn try_enqueue(&self, envelope: TelemetryEnvelope) {
        match self.tx.try_send(envelope) {
            Ok(()) => {
                self.stats.enqueued.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Full(_)) | Err(mpsc::error::TrySendError::Closed(_)) => {
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                self.metrics.record_drop("queue_full");
            }
        }
    }

    pub fn stats(&self) -> &ForwarderStats {
        &self.stats
    }
}

pub struct SplunkForwarder {
    handle: ForwarderHandle,
    _worker: tokio::task::JoinHandle<()>,
}

impl SplunkForwarder {
    pub fn spawn(config: &ForwarderConfig, metrics: Arc<HecMetrics>) -> Self {
        let (tx, rx) = mpsc::channel(config.queue_capacity);
        let stats = Arc::new(ForwarderStats::default());
        let worker_stats = Arc::clone(&stats);
        let worker_metrics = Arc::clone(&metrics);
        let handle_metrics = Arc::clone(&metrics);

        let hec = SplunkHecClient::new(config.hec_url.clone(), config.hec_token.clone());
        let source = config.source.clone();
        let sourcetype = config.sourcetype.clone();
        let index = config.hec_index.clone();

        let worker = tokio::spawn(async move {
            worker_loop(
                rx,
                hec,
                source,
                sourcetype,
                index,
                worker_stats,
                worker_metrics,
            )
            .await;
        });

        Self {
            handle: ForwarderHandle {
                tx,
                stats,
                metrics: handle_metrics,
            },
            _worker: worker,
        }
    }

    pub fn handle(&self) -> &ForwarderHandle {
        &self.handle
    }
}

async fn worker_loop(
    mut rx: mpsc::Receiver<TelemetryEnvelope>,
    hec: SplunkHecClient,
    source: String,
    sourcetype: String,
    index: Option<String>,
    stats: Arc<ForwarderStats>,
    metrics: Arc<HecMetrics>,
) {
    let mut backoff = Duration::from_millis(250);

    while let Some(envelope) = rx.recv().await {
        metrics.set_queue_depth(rx.len());

        let body = build_hec_event(&envelope, &source, &sourcetype, index.as_deref());

        match send_with_retry(&hec, &body, &mut backoff).await {
            SendResult::Success => {
                stats.forwarded.fetch_add(1, Ordering::Relaxed);
                metrics.record_success();
                backoff = Duration::from_millis(250);
            }
            SendResult::RetryableExhausted => {
                stats.failed.fetch_add(1, Ordering::Relaxed);
                metrics.record_failure("retryable");
            }
            SendResult::NonRetryable => {
                stats.failed.fetch_add(1, Ordering::Relaxed);
                metrics.record_failure("non_retryable");
            }
            SendResult::Network => {
                stats.failed.fetch_add(1, Ordering::Relaxed);
                metrics.record_failure("network");
            }
        }
    }
}

enum SendResult {
    Success,
    RetryableExhausted,
    NonRetryable,
    Network,
}

async fn send_with_retry(
    hec: &SplunkHecClient,
    body: &HecEventBody,
    backoff: &mut Duration,
) -> SendResult {
    const MAX_ATTEMPTS: u32 = 4;

    for attempt in 0..MAX_ATTEMPTS {
        match hec.send(body).await {
            Ok(HecSendOutcome::Success) => return SendResult::Success,
            Ok(HecSendOutcome::RetryableFailure) => {
                if attempt + 1 >= MAX_ATTEMPTS {
                    return SendResult::RetryableExhausted;
                }
                sleep(*backoff).await;
                *backoff = (*backoff * 2).min(Duration::from_secs(30));
            }
            Ok(HecSendOutcome::NonRetryableFailure) => return SendResult::NonRetryable,
            Err(_) => {
                if attempt + 1 >= MAX_ATTEMPTS {
                    return SendResult::Network;
                }
                sleep(*backoff).await;
                *backoff = (*backoff * 2).min(Duration::from_secs(30));
            }
        }
    }
    SendResult::RetryableExhausted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ForwarderConfig;
    use crate::envelope::{BEHAVIOR_ALERT, SCHEMA_VERSION};
    use crate::metrics::HecMetrics;
    use axum::{routing::post, Router};
    use serde_json::json;
    use std::net::SocketAddr;
    use std::sync::atomic::Ordering as AtomicOrdering;
    use std::sync::Mutex;
    use tokio::net::TcpListener;

    fn test_config(url: String, token: String, capacity: usize) -> ForwarderConfig {
        ForwarderConfig {
            hec_url: url,
            hec_token: token,
            hec_index: None,
            sourcetype: "neuromesh:alert:v1".into(),
            source: "neuromesh/agent-ebpf-sensor".into(),
            kafka_brokers: vec!["localhost:9092".into()],
            kafka_topic: "neuromesh.telemetry.v1".into(),
            kafka_group_id: "test".into(),
            queue_capacity: capacity,
            metrics_port: 9091,
        }
    }

    fn sample_envelope(id: &str) -> TelemetryEnvelope {
        TelemetryEnvelope {
            event_id: id.into(),
            timestamp_ns: 1,
            node_name: "n1".into(),
            schema_version: SCHEMA_VERSION.into(),
            alert_type: BEHAVIOR_ALERT.into(),
            payload: json!({"rule_id": "NEUROMESH-EXEC-SPAWN-BURST"}),
        }
    }

    async fn spawn_mock_hec(status: axum::http::StatusCode) -> (SocketAddr, Arc<Mutex<usize>>) {
        let hits = Arc::new(Mutex::new(0usize));
        let hits_clone = Arc::clone(&hits);
        let app = Router::new().route(
            "/services/collector/event",
            post(move || {
                let hits = Arc::clone(&hits_clone);
                async move {
                    *hits.lock().expect("lock") += 1;
                    status
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        (addr, hits)
    }

    #[tokio::test]
    async fn enqueue_is_non_blocking_and_forwards_on_success() {
        let (addr, hits) = spawn_mock_hec(axum::http::StatusCode::OK).await;
        let url = format!("http://{addr}/services/collector/event");
        let metrics = HecMetrics::new().expect("metrics");
        let forwarder =
            SplunkForwarder::spawn(&test_config(url, "secret-token".into(), 8), metrics);

        forwarder.handle().try_enqueue(sample_envelope("e1"));
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert_eq!(
            forwarder
                .handle()
                .stats()
                .enqueued
                .load(AtomicOrdering::Relaxed),
            1
        );
        assert_eq!(
            forwarder
                .handle()
                .stats()
                .forwarded
                .load(AtomicOrdering::Relaxed),
            1
        );
        assert!(*hits.lock().expect("lock") >= 1);
    }

    #[tokio::test]
    async fn drops_when_queue_full_under_slow_hec() {
        let (addr, _hits) = spawn_mock_hec(axum::http::StatusCode::SERVICE_UNAVAILABLE).await;
        let url = format!("http://{addr}/services/collector/event");
        let metrics = HecMetrics::new().expect("metrics");
        let forwarder =
            SplunkForwarder::spawn(&test_config(url, "secret-token".into(), 1), metrics);

        forwarder.handle().try_enqueue(sample_envelope("e1"));
        forwarder.handle().try_enqueue(sample_envelope("e2"));
        forwarder.handle().try_enqueue(sample_envelope("e3"));

        assert_eq!(
            forwarder
                .handle()
                .stats()
                .enqueued
                .load(AtomicOrdering::Relaxed),
            1
        );
        assert!(
            forwarder
                .handle()
                .stats()
                .dropped
                .load(AtomicOrdering::Relaxed)
                >= 2,
            "expected queue_full drops under backpressure"
        );
    }
}
