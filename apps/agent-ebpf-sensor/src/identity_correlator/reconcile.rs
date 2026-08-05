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

/// If the pod's SPIFFE is not in the PE cache, purge its side-table rows.
///
/// Returns `Some((cgroup_ids, paths))` when a purge is required; `None` when
/// the SPIFFE is allowed (caller proceeds to container upsert).
pub fn take_pod_if_not_allowed(
    table: &mut SideTable,
    pod_uid: &str,
    spiffe: &str,
    allowlist: &PeAllowlistCache,
) -> Option<(Vec<u64>, Vec<PathBuf>)> {
    if allowlist.contains(spiffe) {
        return None;
    }
    let removed = table.remove_by_pod(pod_uid);
    if removed.is_empty() {
        return Some((Vec::new(), Vec::new()));
    }
    let paths: Vec<_> = removed.iter().map(|(_, e)| e.cgroup_path.clone()).collect();
    let ids: Vec<_> = removed.into_iter().map(|(id, _)| id).collect();
    Some((ids, paths))
}

/// Build the side-table entry for a resolvable container leaf (no BPF I/O).
pub fn side_entry_for_container(
    pod: &PodView,
    spiffe: &str,
    leaf: PathBuf,
    inode: u64,
) -> SideEntry {
    SideEntry {
        pod_uid: pod.uid.clone(),
        namespace: pod.namespace.clone(),
        service_account: if pod.service_account.trim().is_empty() {
            "default".into()
        } else {
            pod.service_account.clone()
        },
        spiffe_id: spiffe.to_string(),
        cgroup_path: leaf,
        inode,
    }
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

    let purge = {
        let mut table = state.side_table.lock().await;
        take_pod_if_not_allowed(&mut table, &pod.uid, &spiffe, allowlist)
    };
    if let Some((ids, paths)) = purge {
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

        let entry = side_entry_for_container(pod, &spiffe, leaf.clone(), inode);

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
            // Re-delivery / MODIFIED after insert: side table already has this
            // cgroup_id — idempotent no-op for map cardinality; still ensure BPF
            // key exists and inotify stays armed.
            InsertOutcome::Replaced => {
                {
                    let mut guard = maps.lock().await;
                    if let Err(e) = seed_allow_cgroup(&mut guard, inode) {
                        tracing::error!(
                            target: "neuromesh::identity_correlator",
                            cgroup_id = inode,
                            error = %e,
                            "BPF re-seed failed during idempotent reconcile_pod"
                        );
                        let mut table = state.side_table.lock().await;
                        let _ = table.remove_by_cgroup(inode);
                        continue;
                    }
                }
                let _ = teardown_tx.send(TeardownCmd::Watch(leaf));
                tracing::debug!(
                    target: "neuromesh::identity_correlator",
                    cgroup_id = inode,
                    pod_uid = %pod.uid,
                    spiffe = %spiffe,
                    container = %c.name,
                    "reconcile_pod idempotent replace (already tracked)"
                );
                continue;
            }
            InsertOutcome::Inserted => {}
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
    use std::fs;
    use std::path::PathBuf;

    fn temp_base(tag: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "nm-recon-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&base);
        base
    }

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

    #[test]
    fn resolve_cgroupfs_leaf_and_skip_empty_id() {
        let base = temp_base("cgroupfs");
        let uid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let raw = "81591f675f72aabbccddeeff00112233445566778899aabbccddeeff00112233";
        let pod = base.join("kubepods").join(format!("pod{uid}"));
        fs::create_dir_all(pod.join(raw)).unwrap();

        let found = resolve_container_cgroup_path(
            &base,
            uid,
            &ContainerStatusView {
                name: "app".into(),
                container_id: Some(format!("containerd://{raw}")),
                running: true,
            },
        );
        assert_eq!(found.unwrap().file_name().unwrap().to_string_lossy(), raw);

        // Null/empty containerID while not Running → skip (not an error).
        assert!(resolve_container_cgroup_path(
            &base,
            uid,
            &ContainerStatusView {
                name: "init".into(),
                container_id: None,
                running: false,
            },
        )
        .is_none());

        // Running without containerID still eligible, but no raw id → skip match.
        assert!(resolve_container_cgroup_path(
            &base,
            uid,
            &ContainerStatusView {
                name: "app2".into(),
                container_id: Some("".into()),
                running: true,
            },
        )
        .is_none());

        // Missing pod dir → no-op.
        assert!(resolve_container_cgroup_path(
            &base,
            "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee",
            &ContainerStatusView {
                name: "app".into(),
                container_id: Some(format!("containerd://{raw}")),
                running: true,
            },
        )
        .is_none());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn resolve_systemd_scope_leaf() {
        let base = temp_base("systemd");
        let uid = "11111111-2222-3333-4444-555555555555";
        let uid_under = uid.replace('-', "_");
        let raw = "abc123def4567890abc123def4567890abc123def4567890abc123def4567890";
        let pod = base
            .join("kubepods.slice")
            .join("kubepods-burstable.slice")
            .join(format!("kubepods-burstable-pod{uid_under}.slice"));
        let scope = format!("cri-containerd-{raw}.scope");
        fs::create_dir_all(pod.join(&scope)).unwrap();

        let found = resolve_container_cgroup_path(
            &base,
            uid,
            &ContainerStatusView {
                name: "main".into(),
                container_id: Some(format!("containerd://{raw}")),
                running: true,
            },
        );
        assert_eq!(found.unwrap().file_name().unwrap().to_string_lossy(), scope);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn take_pod_purges_when_spiffe_absent() {
        let cache = PeAllowlistCache::new();
        cache.replace(["spiffe://t/ns/default/sa/other".into()]);
        let mut t = SideTable::new();
        t.insert(
            9,
            SideEntry {
                pod_uid: "pod-x".into(),
                namespace: "default".into(),
                service_account: "victim".into(),
                spiffe_id: "spiffe://t/ns/default/sa/victim".into(),
                cgroup_path: PathBuf::from("/cg/x"),
                inode: 9,
            },
        );
        let purge =
            take_pod_if_not_allowed(&mut t, "pod-x", "spiffe://t/ns/default/sa/victim", &cache);
        let (ids, paths) = purge.expect("must purge");
        assert_eq!(ids, vec![9]);
        assert_eq!(paths, vec![PathBuf::from("/cg/x")]);
        assert!(t.is_empty());
    }

    #[test]
    fn take_pod_none_when_allowed() {
        let cache = PeAllowlistCache::new();
        let spiffe = "spiffe://t/ns/default/sa/ok".to_string();
        cache.replace([spiffe.clone()]);
        let mut t = SideTable::new();
        t.insert(
            1,
            SideEntry {
                pod_uid: "pod-y".into(),
                namespace: "default".into(),
                service_account: "ok".into(),
                spiffe_id: spiffe.clone(),
                cgroup_path: PathBuf::from("/cg/y"),
                inode: 1,
            },
        );
        assert!(take_pod_if_not_allowed(&mut t, "pod-y", &spiffe, &cache).is_none());
        assert!(t.get(1).is_some());
    }

    #[test]
    fn side_entry_defaults_empty_sa() {
        let pod = PodView {
            uid: "u".into(),
            namespace: "ns".into(),
            service_account: "  ".into(),
            containers: vec![],
        };
        let e =
            side_entry_for_container(&pod, "spiffe://t/ns/ns/sa/default", PathBuf::from("/p"), 7);
        assert_eq!(e.service_account, "default");
        assert_eq!(e.inode, 7);
        assert_eq!(e.spiffe_id, "spiffe://t/ns/ns/sa/default");
    }
}
