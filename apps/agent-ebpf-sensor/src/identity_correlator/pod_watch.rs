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
    Deleted { uid: String },
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
    /// `NEUROMESH_K8S_BEARER_TOKEN` override for lab/kind.
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
            let http = reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .context("build reqwest client")?;
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
        let resp = tokio::select! {
            _ = shutdown.cancelled() => break,
            r = client
                .http
                .get(&url)
                .bearer_auth(&client.token)
                .header(reqwest::header::ACCEPT, "application/json")
                .timeout(Duration::from_secs(60))
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

        let bytes = resp.bytes().await.context("read watch body")?;
        for line in bytes.split(|b| *b == b'\n') {
            if line.is_empty() {
                continue;
            }
            let ev: WatchEvent = match serde_json::from_slice(line) {
                Ok(e) => e,
                Err(e) => {
                    tracing::debug!(
                        target: "neuromesh::identity_correlator",
                        error = %e,
                        "skip malformed watch line"
                    );
                    continue;
                }
            };
            if let Some(rv) = ev
                .object
                .pointer("/metadata/resourceVersion")
                .and_then(|v| v.as_str())
            {
                resource_version = rv.to_string();
            }
            let event = match ev.event_type.as_str() {
                "ADDED" | "MODIFIED" => {
                    let Some(view) = parse_pod_view(&ev.object) else {
                        continue;
                    };
                    PodWatchEvent::Upsert(view)
                }
                "DELETED" => {
                    let Some(uid) = ev
                        .object
                        .pointer("/metadata/uid")
                        .and_then(|v| v.as_str())
                    else {
                        continue;
                    };
                    PodWatchEvent::Deleted {
                        uid: uid.to_string(),
                    }
                }
                _ => continue,
            };
            if tx.send(event).is_err() {
                return Ok(());
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
}
