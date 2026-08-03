//! Kubernetes Pod watch scoped to this node (Slice 2b-i).
//!
//! Uses `fieldSelector=spec.nodeName=<NEUROMESH_NODE_NAME>`.
//! Implemented with **reqwest** against the Kubernetes HTTP API — intentionally
//! **not** the `kube` crate, which pulled unmaintained advisories
//! (`backoff` / `instant` / `rustls-pemfile`) into cargo-deny (PR #93).

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

#[derive(Debug, Deserialize)]
struct PodList {
    #[serde(default)]
    items: Vec<PodItem>,
    metadata: Option<ListMeta>,
}

#[derive(Debug, Deserialize)]
struct ListMeta {
    #[serde(rename = "resourceVersion", default)]
    resource_version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PodItem {
    metadata: ObjectMeta,
}

#[derive(Debug, Deserialize)]
struct ObjectMeta {
    uid: Option<String>,
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
        // Touch namespace file so misconfigured pods fail early (optional).
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

/// List pod UIDs currently scheduled on `node_name` (all namespaces).
pub async fn list_pod_uids_on_node(client: &K8sClient, node_name: &str) -> Result<HashSet<String>> {
    let selector = urlencoding_field_selector(node_name);
    let path = format!("/api/v1/pods?fieldSelector={selector}&limit=500");
    let value = client.get_json(&path).await?;
    let list: PodList = serde_json::from_value(value).context("decode PodList")?;
    let mut out = HashSet::new();
    for pod in list.items {
        if let Some(uid) = pod.metadata.uid {
            out.insert(uid);
        }
    }
    Ok(out)
}

/// Spawn a background watch; sends deleted pod UIDs on the returned channel.
pub fn spawn_pod_delete_watch(
    client: K8sClient,
    node_name: String,
    shutdown: CancellationToken,
) -> mpsc::UnboundedReceiver<String> {
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
    tx: mpsc::UnboundedSender<String>,
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
            // 410 Gone → reset resourceVersion
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
            if ev.event_type == "DELETED" {
                if let Some(uid) = ev.object.pointer("/metadata/uid").and_then(|v| v.as_str()) {
                    if tx.send(uid.to_string()).is_err() {
                        return Ok(());
                    }
                }
            }
        }
    }
    Ok(())
}

fn urlencoding_field_selector(node_name: &str) -> String {
    // fieldSelector value; encode `=` and keep node name safe.
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
}
