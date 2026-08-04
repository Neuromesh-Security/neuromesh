//! Slice 2b-ii-A: idempotent pod reconcile + PE allowlist revoke.

use super::allowlist::PeAllowlistCache;
use super::container_match::{find_container_leaf, find_existing_pod_dir, strip_runtime_prefix};
use super::invalidate::InvalidationReason;
use super::pod_watch::{ContainerStatusView, PodView};
use super::side_table::{InsertOutcome, SideEntry, SideTable};
use super::spiffe::construct_spiffe_id;
use super::{apply_invalidations, CorrelatorState};
use crate::identity_allow::IdentityAllowMaps;
use anyhow::Result;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

#[cfg(target_os = "linux")]
use super::TeardownCmd;
#[cfg(target_os = "linux")]
use crate::identity_allow::seed_allow_cgroup;

/// Whether a container status row should be considered for insert this pass.
pub fn container_eligible(c: &ContainerStatusView) -> bool {
    match &c.container_id {
        Some(id) if !id.trim().is_empty() => true,
        _ => c.running,
    }
}

/// Resolve cgroup leaf path for one container status (no-op friendly).
pub fn resolve_container_cgroup_path(
    cgroup_root: &Path,
    pod_uid: &str,
    container: &ContainerStatusView,
) -> Option<PathBuf> {
    if !container_eligible(container) {
        return None;
    }
    let raw = container
        .container_id
        .as_ref()
        .and_then(|s| strip_runtime_prefix(s))?;
    let pod_dir = find_existing_pod_dir(cgroup_root, pod_uid)?;
    find_container_leaf(&pod_dir, &raw)
}

/// Plan which auto-inserted cgroup_ids to revoke given the current PE allowlist.
pub fn plan_revoke_ids(table: &SideTable, allowed: &HashSet<String>) -> Vec<u64> {
    table.plan_pe_allowlist_revoke(allowed)
}

/// Apply PE allowlist revoke: remove side entries + return paths to unwatch.
pub fn apply_revoke_plan(table: &mut SideTable, ids: &[u64]) -> Vec<(u64, PathBuf)> {
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        if let Some(e) = table.remove_by_cgroup(*id) {
            out.push((*id, e.cgroup_path));
        }
    }
    out
}

/// Idempotent reconcile for one pod (Linux: resolves inodes + writes BPF).
#[cfg(target_os = "linux")]
pub async fn reconcile_pod(
    pod: &PodView,
    trust_domain: &str,
    cgroup_root: &Path,
    allowlist: &PeAllowlistCache,
    state: &CorrelatorState,
    maps: &Arc<Mutex<IdentityAllowMaps>>,
    teardown_tx: &tokio::sync::mpsc::UnboundedSender<TeardownCmd>,
    #[cfg(feature = "orchestrator")] metrics: Option<&crate::observability::AgentMetrics>,
) -> Result<()> {
    use super::cgroup_resolve::inode_of_path;

    let spiffe = construct_spiffe_id(trust_domain, &pod.namespace, &pod.service_account);

    if !allowlist.contains(&spiffe) {
        let (ids, paths) = {
            let mut table = state.side_table.lock().await;
            let removed = table.remove_by_pod(&pod.uid);
            let paths: Vec<_> = removed.iter().map(|(_, e)| e.cgroup_path.clone()).collect();
            let ids: Vec<_> = removed.into_iter().map(|(id, _)| id).collect();
            (ids, paths)
        };
        for p in paths {
            let _ = teardown_tx.send(TeardownCmd::Unwatch(p));
        }
        apply_invalidations(
            maps,
            &ids,
            InvalidationReason::PeAllowlistRevoke,
            #[cfg(feature = "orchestrator")]
            metrics,
        )
        .await?;
        return Ok(());
    }

    for c in &pod.containers {
        let Some(leaf) = resolve_container_cgroup_path(cgroup_root, &pod.uid, c) else {
            continue;
        };
        let inode = match inode_of_path(&leaf) {
            Ok(i) => i,
            Err(e) => {
                tracing::debug!(
                    target: "neuromesh::identity_correlator",
                    path = %leaf.display(),
                    error = %e,
                    "skip container cgroup — inode resolve failed"
                );
                continue;
            }
        };

        let entry = SideEntry {
            pod_uid: pod.uid.clone(),
            namespace: pod.namespace.clone(),
            service_account: if pod.service_account.trim().is_empty() {
                "default".into()
            } else {
                pod.service_account.clone()
            },
            spiffe_id: spiffe.clone(),
            cgroup_path: leaf.clone(),
            inode,
        };

        let outcome = {
            let mut table = state.side_table.lock().await;
            table.insert(inode, entry)
        };
        match outcome {
            InsertOutcome::RejectedFull => {
                tracing::error!(
                    target: "neuromesh::identity_correlator",
                    cgroup_id = inode,
                    pod_uid = %pod.uid,
                    "IDENTITY_ALLOW_CGROUPS / side table full — refusing insert"
                );
                continue;
            }
            InsertOutcome::Inserted | InsertOutcome::Replaced => {}
        }

        {
            let mut guard = maps.lock().await;
            if let Err(e) = seed_allow_cgroup(&mut guard, inode) {
                tracing::error!(
                    target: "neuromesh::identity_correlator",
                    cgroup_id = inode,
                    error = %e,
                    "BPF insert failed during reconcile_pod"
                );
                let mut table = state.side_table.lock().await;
                let _ = table.remove_by_cgroup(inode);
                continue;
            }
        }

        let _ = teardown_tx.send(TeardownCmd::Watch(leaf));
        tracing::info!(
            target: "neuromesh::identity_correlator",
            cgroup_id = inode,
            pod_uid = %pod.uid,
            spiffe = %spiffe,
            container = %c.name,
            "auto-inserted IDENTITY_ALLOW_CGROUPS entry (2b-ii-A)"
        );
    }
    Ok(())
}

/// Revoke auto-inserts whose SPIFFE left the PE allowlist (Fresh sync).
pub async fn revoke_not_in_allowlist(
    allowlist: &PeAllowlistCache,
    state: &CorrelatorState,
    maps: &Arc<Mutex<IdentityAllowMaps>>,
    #[cfg(target_os = "linux")] teardown_tx: Option<
        &tokio::sync::mpsc::UnboundedSender<TeardownCmd>,
    >,
    #[cfg(feature = "orchestrator")] metrics: Option<&crate::observability::AgentMetrics>,
) -> Result<()> {
    let allowed = allowlist.snapshot();
    let removed = {
        let mut table = state.side_table.lock().await;
        let ids = plan_revoke_ids(&table, &allowed);
        apply_revoke_plan(&mut table, &ids)
    };
    let ids: Vec<u64> = removed.iter().map(|(id, _)| *id).collect();
    #[cfg(target_os = "linux")]
    if let Some(tx) = teardown_tx {
        for (_, path) in &removed {
            let _ = tx.send(TeardownCmd::Unwatch(path.clone()));
        }
    }
    apply_invalidations(
        maps,
        &ids,
        InvalidationReason::PeAllowlistRevoke,
        #[cfg(feature = "orchestrator")]
        metrics,
    )
    .await
}

/// On Invalid / VALID=0: clear side table (+ BPF keys we tracked) for hygiene.
pub async fn clear_side_table_hygiene(
    state: &CorrelatorState,
    maps: &Arc<Mutex<IdentityAllowMaps>>,
    #[cfg(target_os = "linux")] teardown_tx: Option<
        &tokio::sync::mpsc::UnboundedSender<TeardownCmd>,
    >,
    #[cfg(feature = "orchestrator")] metrics: Option<&crate::observability::AgentMetrics>,
) -> Result<()> {
    let cleared = {
        let mut table = state.side_table.lock().await;
        table.clear()
    };
    let ids: Vec<u64> = cleared.iter().map(|(id, _)| *id).collect();
    #[cfg(target_os = "linux")]
    if let Some(tx) = teardown_tx {
        for (_, e) in &cleared {
            let _ = tx.send(TeardownCmd::Unwatch(e.cgroup_path.clone()));
        }
    }
    apply_invalidations(
        maps,
        &ids,
        InvalidationReason::PeAllowlistRevoke,
        #[cfg(feature = "orchestrator")]
        metrics,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_correlator::side_table::SideEntry;
    use std::path::PathBuf;

    #[test]
    fn eligible_requires_id_or_running() {
        assert!(!container_eligible(&ContainerStatusView {
            name: "a".into(),
            container_id: None,
            running: false,
        }));
        assert!(container_eligible(&ContainerStatusView {
            name: "a".into(),
            container_id: Some("containerd://abc".into()),
            running: false,
        }));
        assert!(container_eligible(&ContainerStatusView {
            name: "a".into(),
            container_id: None,
            running: true,
        }));
    }

    #[test]
    fn revoke_plan_clears_dropped_spiffe_only() {
        let mut t = SideTable::new();
        t.insert(
            1,
            SideEntry {
                pod_uid: "u1".into(),
                namespace: "default".into(),
                service_account: "keep".into(),
                spiffe_id: "spiffe://t/ns/default/sa/keep".into(),
                cgroup_path: PathBuf::from("/a"),
                inode: 1,
            },
        );
        t.insert(
            2,
            SideEntry {
                pod_uid: "u2".into(),
                namespace: "default".into(),
                service_account: "drop".into(),
                spiffe_id: "spiffe://t/ns/default/sa/drop".into(),
                cgroup_path: PathBuf::from("/b"),
                inode: 2,
            },
        );
        t.insert(
            3,
            SideEntry {
                pod_uid: "u3".into(),
                namespace: String::new(),
                service_account: String::new(),
                spiffe_id: String::new(), // manual seed
                cgroup_path: PathBuf::from("/c"),
                inode: 3,
            },
        );
        let mut allowed = HashSet::new();
        allowed.insert("spiffe://t/ns/default/sa/keep".into());
        let ids = plan_revoke_ids(&t, &allowed);
        assert_eq!(ids, vec![2]);
        let removed = apply_revoke_plan(&mut t, &ids);
        assert_eq!(removed.len(), 1);
        assert!(t.get(1).is_some());
        assert!(t.get(3).is_some());
        assert!(t.get(2).is_none());
    }

    #[test]
    fn allowlist_gate_concept() {
        let cache = PeAllowlistCache::new();
        cache.replace(["spiffe://neuromesh.security/ns/default/sa/ok".into()]);
        let yes = construct_spiffe_id("neuromesh.security", "default", "ok");
        let no = construct_spiffe_id("neuromesh.security", "default", "nope");
        assert!(cache.contains(&yes));
        assert!(!cache.contains(&no));
    }
}
