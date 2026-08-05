//! Kubernetes Pod watch scoped to this node (Slice 2b-i + 2b-ii-A).
//!
//! Uses `fieldSelector=spec.nodeName=<NEUROMESH_NODE_NAME>`.
//! Implemented with **reqwest** against the Kubernetes HTTP API — intentionally
//! **not** the `kube` crate (cargo-deny / unmaintained deps).

use anyhow::{bail, Context, Result};
use reqwest::Certificate;
use serde::Deserialize;
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const SA_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const SA_CA_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
const SA_NS_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";

/// Minimal authenticated Kubernetes API client (list + watch pods).
#[derive(Clone)]
pub struct K8sClient {
    http: reqwest::Client,
    base_url: String,
    token: String,
}

/// One container status entry (main / init / ephemeral).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContainerStatusView {
    pub name: String,
    pub container_id: Option<String>,
    /// True when `state.running` is present.
    pub running: bool,
}

/// Pod fields needed for 2b-ii-A reconcile + 2b-i DELETE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodView {
    pub uid: String,
    pub namespace: String,
    pub service_account: String,
    pub containers: Vec<ContainerStatusView>,
}

/// Watch / reconcile trigger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PodWatchEvent {
    /// ADDED or MODIFIED — run idempotent `reconcile_pod`.
    Upsert(PodView),
    Deleted {
        uid: String,
    },
}

#[derive(Debug, Deserialize)]
struct PodList {
    #[serde(default)]
    items: Vec<serde_json::Value>,
    metadata: Option<ListMeta>,
}

#[derive(Debug, Deserialize)]
struct ListMeta {
    #[serde(rename = "resourceVersion", default)]
    resource_version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WatchEvent {
    #[serde(rename = "type")]
    event_type: String,
    object: serde_json::Value,
}

impl K8sClient {
    /// Prefer in-cluster ServiceAccount; fall back to `KUBERNETES_SERVICE_HOST`/`PORT`
    /// with token from SA paths. Explicit `NEUROMESH_K8S_API_URL` +
    /// `NEUROMESH_K8S_BEARER_TOKEN` override for host-agent / lab (does **not**
    /// read `KUBECONFIG`). Optional `NEUROMESH_K8S_CA_FILE` PEM for private CA
    /// (k3s `server-ca.crt`) — required for TLS verify against local apiserver.
    pub async fn connect() -> Result<Self> {
        if let (Ok(url), Ok(token)) = (
            std::env::var("NEUROMESH_K8S_API_URL"),
            std::env::var("NEUROMESH_K8S_BEARER_TOKEN"),
        ) {
            let url = url.trim().trim_end_matches('/').to_string();
            let token = token.trim().to_string();
            if url.is_empty() || token.is_empty() {
                bail!("NEUROMESH_K8S_API_URL / NEUROMESH_K8S_BEARER_TOKEN empty");
            }
            let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(30));
            if let Ok(ca_path) = std::env::var("NEUROMESH_K8S_CA_FILE") {
                let ca_path = ca_path.trim();
                if !ca_path.is_empty() {
                    let ca = std::fs::read(ca_path)
                        .with_context(|| format!("read NEUROMESH_K8S_CA_FILE at {ca_path}"))?;
                    let cert =
                        Certificate::from_pem(&ca).context("parse NEUROMESH_K8S_CA_FILE PEM")?;
                    builder = builder.add_root_certificate(cert);
                }
            }
            let http = builder.build().context("build reqwest client")?;
            return Ok(Self {
                http,
                base_url: url,
                token,
            });
        }

        let host = std::env::var("KUBERNETES_SERVICE_HOST")
            .context("KUBERNETES_SERVICE_HOST unset (not in-cluster?)")?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".into());
        let base_url = format!("https://{host}:{port}");
        let token = std::fs::read_to_string(SA_TOKEN_PATH)
            .with_context(|| format!("read SA token at {SA_TOKEN_PATH}"))?
            .trim()
            .to_string();
        if token.is_empty() {
            bail!("serviceaccount token is empty");
        }

        let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(30));
        if PathBuf::from(SA_CA_PATH).is_file() {
            let ca =
                std::fs::read(SA_CA_PATH).with_context(|| format!("read SA CA at {SA_CA_PATH}"))?;
            let cert = Certificate::from_pem(&ca).context("parse SA CA PEM")?;
            builder = builder.add_root_certificate(cert);
        } else {
            tracing::warn!(
                target: "neuromesh::identity_correlator",
                "SA CA missing at {SA_CA_PATH} — TLS verify may fail"
            );
        }
        let _ = std::fs::read_to_string(SA_NS_PATH);

        let http = builder.build().context("build in-cluster reqwest client")?;
        Ok(Self {
            http,
            base_url,
            token,
        })
    }

    async fn get_json(&self, path_and_query: &str) -> Result<serde_json::Value> {
        let url = format!("{}{path_and_query}", self.base_url);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        let status = resp.status();
        let body = resp.text().await.context("read response body")?;
        if !status.is_success() {
            bail!("GET {url} HTTP {status}: {}", truncate(&body, 500));
        }
        serde_json::from_str(&body).context("parse JSON response")
    }
}

/// Parse a Pod JSON object into [`PodView`].
pub fn parse_pod_view(obj: &serde_json::Value) -> Option<PodView> {
    let uid = obj.pointer("/metadata/uid")?.as_str()?.to_string();
    let namespace = obj
        .pointer("/metadata/namespace")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let service_account = obj
        .pointer("/spec/serviceAccountName")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let mut containers = Vec::new();
    for key in [
        "/status/containerStatuses",
        "/status/initContainerStatuses",
        "/status/ephemeralContainerStatuses",
    ] {
        if let Some(arr) = obj.pointer(key).and_then(|v| v.as_array()) {
            for c in arr {
                containers.push(parse_container_status(c));
            }
        }
    }

    Some(PodView {
        uid,
        namespace,
        service_account,
        containers,
    })
}

fn parse_container_status(c: &serde_json::Value) -> ContainerStatusView {
    let name = c
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let container_id = c
        .get("containerID")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.trim().is_empty());
    let running = c.pointer("/state/running").is_some();
    ContainerStatusView {
        name,
        container_id,
        running,
    }
}

/// List pod UIDs currently scheduled on `node_name` (all namespaces).
pub async fn list_pod_uids_on_node(client: &K8sClient, node_name: &str) -> Result<HashSet<String>> {
    let selector = urlencoding_field_selector(node_name);
    let path = format!("/api/v1/pods?fieldSelector={selector}&limit=500");
    let value = client.get_json(&path).await?;
    let list: PodList = serde_json::from_value(value).context("decode PodList")?;
    let mut out = HashSet::new();
    for item in list.items {
        if let Some(uid) = item.pointer("/metadata/uid").and_then(|v| v.as_str()) {
            out.insert(uid.to_string());
        }
    }
    Ok(out)
}

/// Spawn a background watch; ADDED/MODIFIED → [`PodWatchEvent::Upsert`], DELETED → uid.
pub fn spawn_pod_watch(
    client: K8sClient,
    node_name: String,
    shutdown: CancellationToken,
) -> mpsc::UnboundedReceiver<PodWatchEvent> {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        if let Err(e) = watch_loop(client, node_name, tx, shutdown).await {
            tracing::error!(
                target: "neuromesh::identity_correlator",
                error = %e,
                "pod watch loop exited"
            );
        }
    });
    rx
}

/// Accumulates HTTP body chunks and yields complete NDJSON lines (no trailing `\n`).
#[derive(Default)]
struct NdjsonLineBuf {
    buf: Vec<u8>,
}

impl NdjsonLineBuf {
    /// Push a chunk; return every full line completed by this chunk (may be empty).
    fn push_chunk(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        let mut lines = Vec::new();
        while let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
            let mut line: Vec<u8> = self.buf.drain(..=pos).collect();
            line.pop(); // drop '\n'
            if !line.is_empty() {
                lines.push(line);
            }
        }
        lines
    }
}

/// Decode one Kubernetes watch NDJSON line into optional RV update + channel event.
///
/// Returns `None` when the line is malformed or a non-actionable type (e.g. BOOKMARK
/// without a parseable pod object — RV still updated when present).
fn decode_watch_line(line: &[u8]) -> Option<(Option<String>, Option<PodWatchEvent>)> {
    let ev: WatchEvent = match serde_json::from_slice(line) {
        Ok(e) => e,
        Err(e) => {
            tracing::debug!(
                target: "neuromesh::identity_correlator",
                error = %e,
                "skip malformed watch line"
            );
            return None;
        }
    };
    let rv = ev
        .object
        .pointer("/metadata/resourceVersion")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let event = match ev.event_type.as_str() {
        "ADDED" | "MODIFIED" => parse_pod_view(&ev.object).map(PodWatchEvent::Upsert),
        "DELETED" => ev
            .object
            .pointer("/metadata/uid")
            .and_then(|v| v.as_str())
            .map(|uid| PodWatchEvent::Deleted {
                uid: uid.to_string(),
            }),
        _ => None,
    };
    Some((rv, event))
}

/// Stream-consume a watch body: parse each complete NDJSON line as chunks arrive
/// and `send` immediately — **must not** wait for the HTTP response to finish.
async fn consume_watch_byte_stream<S, E>(
    stream: S,
    tx: &mpsc::UnboundedSender<PodWatchEvent>,
    resource_version: &mut String,
) -> Result<()>
where
    S: futures_util::Stream<Item = Result<bytes::Bytes, E>>,
    E: std::error::Error + Send + Sync + 'static,
{
    use futures_util::StreamExt;

    futures_util::pin_mut!(stream);
    let mut line_buf = NdjsonLineBuf::default();
    while let Some(item) = stream.next().await {
        let chunk = item.context("watch stream chunk")?;
        for line in line_buf.push_chunk(&chunk) {
            let Some((rv, event)) = decode_watch_line(&line) else {
                continue;
            };
            if let Some(rv) = rv {
                *resource_version = rv;
            }
            if let Some(event) = event {
                if tx.send(event).is_err() {
                    return Ok(());
                }
            }
        }
    }
    Ok(())
}

async fn watch_loop(
    client: K8sClient,
    node_name: String,
    tx: mpsc::UnboundedSender<PodWatchEvent>,
    shutdown: CancellationToken,
) -> Result<()> {
    let selector = urlencoding_field_selector(&node_name);
    let mut resource_version = {
        let path = format!("/api/v1/pods?fieldSelector={selector}&limit=1");
        let value = client.get_json(&path).await?;
        let list: PodList = serde_json::from_value(value).context("initial list for RV")?;
        list.metadata
            .and_then(|m| m.resource_version)
            .unwrap_or_else(|| "0".into())
    };

    loop {
        if shutdown.is_cancelled() {
            break;
        }
        let path = format!(
            "/api/v1/pods?watch=1&allowWatchBookmarks=true&fieldSelector={selector}&resourceVersion={resource_version}&timeoutSeconds=30"
        );
        let url = format!("{}{path}", client.base_url);
        // Per-request timeout must exceed timeoutSeconds so the stream can run
        // to server close; never buffer the full body before parsing.
        let resp = tokio::select! {
            _ = shutdown.cancelled() => break,
            r = client
                .http
                .get(&url)
                .bearer_auth(&client.token)
                .header(reqwest::header::ACCEPT, "application/json")
                .timeout(Duration::from_secs(90))
                .send() => r.with_context(|| format!("watch GET {url}"))?,
        };
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if status.as_u16() == 410 {
                tracing::warn!(
                    target: "neuromesh::identity_correlator",
                    "pod watch 410 Gone — resetting resourceVersion"
                );
                resource_version = "0".into();
                continue;
            }
            bail!("watch HTTP {status}: {}", truncate(&body, 500));
        }

        let stream = resp.bytes_stream();
        tokio::select! {
            _ = shutdown.cancelled() => break,
            result = consume_watch_byte_stream(stream, &tx, &mut resource_version) => {
                result?;
            }
        }
    }
    Ok(())
}

fn urlencoding_field_selector(node_name: &str) -> String {
    let raw = format!("spec.nodeName={node_name}");
    raw.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '=' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

/// Validate node name for fieldSelector (reject empty / control chars).
pub fn validate_node_name(name: &str) -> Result<()> {
    let name = name.trim();
    if name.is_empty() {
        bail!("NEUROMESH_NODE_NAME is empty — required when identity correlator is enabled");
    }
    if name.chars().any(|c| c.is_control() || c == ',') {
        bail!("NEUROMESH_NODE_NAME contains illegal characters for fieldSelector");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::io;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[test]
    fn rejects_empty_node_name() {
        assert!(validate_node_name("").is_err());
        assert!(validate_node_name("   ").is_err());
    }

    #[test]
    fn accepts_normal_node_name() {
        assert!(validate_node_name("node-1").is_ok());
    }

    #[test]
    fn field_selector_encoding_keeps_eq() {
        let s = urlencoding_field_selector("worker-1");
        assert_eq!(s, "spec.nodeName=worker-1");
    }

    #[test]
    fn parse_pod_view_extracts_fields() {
        let obj = serde_json::json!({
            "metadata": {
                "uid": "uid-1",
                "namespace": "default"
            },
            "spec": { "serviceAccountName": "agent-ebpf-sensor" },
            "status": {
                "containerStatuses": [{
                    "name": "app",
                    "containerID": "containerd://abc123",
                    "state": { "running": { "startedAt": "2026-01-01T00:00:00Z" } }
                }],
                "initContainerStatuses": [{
                    "name": "init",
                    "containerID": "containerd://init99",
                    "state": { "terminated": { "exitCode": 0 } }
                }]
            }
        });
        let v = parse_pod_view(&obj).unwrap();
        assert_eq!(v.uid, "uid-1");
        assert_eq!(v.namespace, "default");
        assert_eq!(v.service_account, "agent-ebpf-sensor");
        assert_eq!(v.containers.len(), 2);
        assert!(v.containers[0].running);
        assert_eq!(
            v.containers[0].container_id.as_deref(),
            Some("containerd://abc123")
        );
        assert!(!v.containers[1].running);
    }

    #[test]
    fn ndjson_buf_splits_across_chunks() {
        let mut buf = NdjsonLineBuf::default();
        assert!(buf.push_chunk(b"{\"type\":\"").is_empty());
        let lines = buf.push_chunk(b"ADDED\"}\n{\"type\":\"DELETED\"}\n");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], br#"{"type":"ADDED"}"#);
        assert_eq!(lines[1], br#"{"type":"DELETED"}"#);
    }

    #[test]
    fn decode_watch_line_added_and_deleted() {
        let added = serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": { "uid": "u1", "namespace": "ns", "resourceVersion": "9" },
                "spec": { "serviceAccountName": "sa" },
                "status": { "containerStatuses": [] }
            }
        });
        let line = serde_json::to_vec(&added).unwrap();
        let (rv, ev) = decode_watch_line(&line).unwrap();
        assert_eq!(rv.as_deref(), Some("9"));
        match ev.unwrap() {
            PodWatchEvent::Upsert(p) => assert_eq!(p.uid, "u1"),
            other => panic!("unexpected {other:?}"),
        }

        let deleted = serde_json::json!({
            "type": "DELETED",
            "object": { "metadata": { "uid": "u2", "resourceVersion": "10" } }
        });
        let line = serde_json::to_vec(&deleted).unwrap();
        let (rv, ev) = decode_watch_line(&line).unwrap();
        assert_eq!(rv.as_deref(), Some("10"));
        match ev.unwrap() {
            PodWatchEvent::Deleted { uid } => assert_eq!(uid, "u2"),
            other => panic!("unexpected {other:?}"),
        }
    }

    /// A complete NDJSON line arriving mid-stream must be forwarded on the
    /// channel **before** the HTTP stream closes (the old `resp.bytes()` bug).
    #[tokio::test]
    async fn mid_stream_line_forwarded_before_connection_closes() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (chunk_tx, chunk_rx) = mpsc::channel::<Bytes>(4);
        let stream_closed = Arc::new(AtomicBool::new(false));
        let closed_flag = stream_closed.clone();

        let mut line = serde_json::to_vec(&serde_json::json!({
            "type": "MODIFIED",
            "object": {
                "metadata": {
                    "uid": "mid-stream-uid",
                    "namespace": "default",
                    "resourceVersion": "42"
                },
                "spec": { "serviceAccountName": "default" },
                "status": {
                    "containerStatuses": [{
                        "name": "main",
                        "containerID": "containerd://abc",
                        "state": { "running": {} }
                    }]
                }
            }
        }))
        .unwrap();
        line.push(b'\n');
        let first = Bytes::from(line);

        let join = tokio::spawn(async move {
            let stream = futures_util::stream::unfold(chunk_rx, |mut rx| async {
                rx.recv().await.map(|b| (Ok::<_, io::Error>(b), rx))
            });
            let mut rv = "0".to_string();
            let result = consume_watch_byte_stream(stream, &tx, &mut rv).await;
            closed_flag.store(true, Ordering::SeqCst);
            result.map(|_| rv)
        });

        chunk_tx.send(first).await.expect("send first chunk");
        let ev = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timed out waiting for mid-stream event")
            .expect("channel closed");
        match ev {
            PodWatchEvent::Upsert(p) => {
                assert_eq!(p.uid, "mid-stream-uid");
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(
            !stream_closed.load(Ordering::SeqCst),
            "event must be forwarded BEFORE the watch stream ends"
        );
        drop(chunk_tx); // close stream (simulates HTTP body EOF)
        let rv = join.await.expect("join").expect("consume");
        assert_eq!(rv, "42");
        assert!(stream_closed.load(Ordering::SeqCst));
    }
}
