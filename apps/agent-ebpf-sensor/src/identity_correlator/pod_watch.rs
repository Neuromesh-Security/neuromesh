//! Kubernetes Pod watch scoped to this node (Slice 2b-i).
//!
//! Uses `field_selector = spec.nodeName=<NEUROMESH_NODE_NAME>`.
//! On Delete, returns the pod UID for side-table invalidation.

use anyhow::{bail, Context, Result};
use futures::Stream;
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, ListParams};
use kube::runtime::watcher::{self, Event};
use kube::{Client, Config};
use std::collections::HashSet;
use std::pin::Pin;

/// Boxed pod watcher stream.
pub type PodWatchStream =
    Pin<Box<dyn Stream<Item = Result<Event<Pod>, watcher::Error>> + Send>>;

/// Build an in-cluster (or kubeconfig) client.
pub async fn connect_client() -> Result<Client> {
    let config = Config::infer()
        .await
        .context("kube Config::infer failed (in-cluster or kubeconfig)")?;
    Client::try_from(config).context("kube Client::try_from failed")
}

/// List pod UIDs currently scheduled on `node_name` (all namespaces).
pub async fn list_pod_uids_on_node(client: &Client, node_name: &str) -> Result<HashSet<String>> {
    let pods: Api<Pod> = Api::all(client.clone());
    let lp = ListParams::default().fields(&format!("spec.nodeName={node_name}"));
    let list = pods
        .list(&lp)
        .await
        .with_context(|| format!("list pods fieldSelector=spec.nodeName={node_name}"))?;
    let mut out = HashSet::new();
    for pod in list.items {
        if let Some(uid) = pod.metadata.uid {
            out.insert(uid);
        }
    }
    Ok(out)
}

/// Stream of watcher events for pods on this node.
pub fn pod_delete_stream(client: Client, node_name: String) -> PodWatchStream {
    let pods: Api<Pod> = Api::all(client);
    let wc = watcher::Config::default().fields(&format!("spec.nodeName={node_name}"));
    Box::pin(watcher::watcher(pods, wc))
}

/// Extract pod UID from a watcher event if it is a deletion.
pub fn deleted_pod_uid(event: &Event<Pod>) -> Option<String> {
    match event {
        Event::Delete(pod) => pod.metadata.uid.clone(),
        _ => None,
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
}
