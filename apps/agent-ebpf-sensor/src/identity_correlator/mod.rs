//! Slice 2b-i: identity-allow **invalidation** correlator.
//!
//! - Populates a side table at manual seed / insert time.
//! - Invalidates `IDENTITY_ALLOW_CGROUPS` on Pod DELETE (node-local informer)
//!   and on cgroup directory teardown (inotify).
//! - Does **not** auto-correlate / auto-insert (that is Slice 2b-ii).
//!
//! Enable with `NEUROMESH_IDENTITY_CORRELATOR=1` and `NEUROMESH_NODE_NAME`.

mod invalidate;
mod path_parse;
mod side_table;

#[cfg(target_os = "linux")]
mod cgroup_resolve;
#[cfg(target_os = "linux")]
mod pod_watch;
#[cfg(target_os = "linux")]
mod teardown_watch;

pub use invalidate::{
    plan_missing_path_sweep, plan_pod_delete, plan_teardown, InvalidationReason, ResyncReason,
};
pub use path_parse::{normalize_pod_uid, parse_cgroup_path, CgroupPathStyle, ParsedCgroupPath};
pub use side_table::{InsertOutcome, SideEntry, SideTable};

use crate::identity_allow::{remove_allow_cgroup, IdentityAllowMaps};
use anyhow::{bail, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

/// `1` / `true` / `yes` enables the correlator task.
pub const IDENTITY_CORRELATOR_ENV: &str = "NEUROMESH_IDENTITY_CORRELATOR";

/// Absolute cgroup v2 root (DaemonSet: `/host/sys/fs/cgroup`).
pub const CGROUP_ROOT_ENV: &str = "NEUROMESH_CGROUP_ROOT";

/// Node name for fieldSelector (already injected on the DaemonSet).
pub const NODE_NAME_ENV: &str = "NEUROMESH_NODE_NAME";

#[derive(Debug, Clone)]
pub struct IdentityCorrelatorConfig {
    pub enabled: bool,
    pub node_name: String,
    pub cgroup_root: PathBuf,
}

impl IdentityCorrelatorConfig {
    pub fn from_env() -> Result<Self> {
        let enabled = match std::env::var(IDENTITY_CORRELATOR_ENV) {
            Ok(v) => {
                let v = v.trim().to_ascii_lowercase();
                matches!(v.as_str(), "1" | "true" | "yes" | "on")
            }
            Err(_) => false,
        };
        let node_name = std::env::var(NODE_NAME_ENV).unwrap_or_default();
        let cgroup_root = std::env::var(CGROUP_ROOT_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/sys/fs/cgroup"));
        if enabled {
            if node_name.trim().is_empty() {
                bail!(
                    "{IDENTITY_CORRELATOR_ENV} enabled but {NODE_NAME_ENV} is unset/empty \
                     (required for node-local pod watch)"
                );
            }
            #[cfg(target_os = "linux")]
            pod_watch::validate_node_name(&node_name)?;
        }
        Ok(Self {
            enabled,
            node_name,
            cgroup_root,
        })
    }
}

/// Shared side table for seed registration + invalidation tasks.
pub struct CorrelatorState {
    pub side_table: Mutex<SideTable>,
}

impl CorrelatorState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            side_table: Mutex::new(SideTable::new()),
        })
    }
}

/// Commands for the inotify worker (arm/disarm watches).
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub enum TeardownCmd {
    Watch(PathBuf),
    Unwatch(PathBuf),
    Rearm(Vec<PathBuf>),
}

/// Register a manually seeded cgroup_id into the side table.
///
/// Resolves path via cgroup walk; parses pod UID when the path is a K8s layout
/// (empty `pod_uid` for lab synthetic cgroups is OK — teardown watch still arms).
/// BPF map must already contain the allow entry (Slice 2a seed path).
#[cfg(target_os = "linux")]
pub async fn register_seeded_cgroup(
    state: &CorrelatorState,
    cgroup_root: &Path,
    cgroup_id: u64,
    teardown_tx: Option<&tokio::sync::mpsc::UnboundedSender<TeardownCmd>>,
) -> Result<SideEntry> {
    let path = cgroup_resolve::path_for_cgroup_id(cgroup_root, cgroup_id)?;
    let inode = cgroup_resolve::inode_of_path(&path)?;
    if inode != cgroup_id {
        bail!(
            "cgroup path {} inode={inode} != seeded cgroup_id={cgroup_id}",
            path.display()
        );
    }
    let pod_uid = parse_cgroup_path(&path.to_string_lossy())
        .map(|p| p.pod_uid)
        .unwrap_or_default();
    let entry = SideEntry {
        pod_uid,
        cgroup_path: path.clone(),
        inode,
    };
    {
        let mut table = state.side_table.lock().await;
        match table.insert(cgroup_id, entry.clone()) {
            InsertOutcome::Inserted | InsertOutcome::Replaced => {}
            InsertOutcome::RejectedFull => {
                bail!("side table full — cannot register cgroup_id={cgroup_id}")
            }
        }
    }
    if let Some(tx) = teardown_tx {
        tx.send(TeardownCmd::Watch(path.clone()))
            .map_err(|_| anyhow::anyhow!("inotify worker channel closed — cannot arm watch"))?;
    }
    Ok(entry)
}

/// Arm side table + inotify for every lab-seeded cgroup_id (Slice 2a → 2b-i bridge).
///
/// `identity_allow::apply_manual_cgroup_seeds_from_env` only writes the BPF map.
/// Without this call, teardown/Pod-DELETE invalidation never sees those ids.
#[cfg(target_os = "linux")]
pub async fn register_manual_seed_ids(
    state: &CorrelatorState,
    cgroup_root: &Path,
    cgroup_ids: &[u64],
    teardown_tx: &tokio::sync::mpsc::UnboundedSender<TeardownCmd>,
) -> Result<Vec<SideEntry>> {
    let mut out = Vec::with_capacity(cgroup_ids.len());
    for id in cgroup_ids {
        let entry = register_seeded_cgroup(state, cgroup_root, *id, Some(teardown_tx)).await?;
        tracing::info!(
            target: "neuromesh::identity_correlator",
            cgroup_id = *id,
            path = %entry.cgroup_path.display(),
            pod_uid = %entry.pod_uid,
            "Side-table registered seeded cgroup; inotify watch queued"
        );
        // Also via `log` so default RUST_LOG=info agent consoles always show it
        // (matches other startup `info!` lines in main).
        log::info!(
            "Side-table registered seeded cgroup_id={} path={} pod_uid={:?} (inotify watch queued)",
            id,
            entry.cgroup_path.display(),
            entry.pod_uid
        );
        out.push(entry);
    }
    Ok(out)
}

#[cfg(not(target_os = "linux"))]
pub async fn register_seeded_cgroup(
    _state: &CorrelatorState,
    _cgroup_root: &Path,
    _cgroup_id: u64,
    _teardown_tx: Option<&()>,
) -> Result<SideEntry> {
    bail!("identity correlator cgroup resolve is Linux-only")
}

/// Apply BPF map deletes for planned cgroup_ids.
pub async fn apply_invalidations(
    maps: &Arc<Mutex<IdentityAllowMaps>>,
    cgroup_ids: &[u64],
    reason: InvalidationReason,
    #[cfg(feature = "orchestrator")] metrics: Option<&crate::observability::AgentMetrics>,
) -> Result<()> {
    if cgroup_ids.is_empty() {
        return Ok(());
    }
    let mut guard = maps.lock().await;
    for id in cgroup_ids {
        remove_allow_cgroup(&mut guard, *id)?;
        tracing::warn!(
            target: "neuromesh::identity_correlator",
            cgroup_id = *id,
            reason = reason.as_metric_label(),
            "invalidated IDENTITY_ALLOW_CGROUPS entry"
        );
        #[cfg(feature = "orchestrator")]
        if let Some(m) = metrics {
            m.record_identity_invalidation(reason.as_metric_label());
        }
    }
    Ok(())
}

/// Spawn pod-watch + teardown-watch tasks. No-op when config.enabled is false.
///
/// Returns `(join_handle, teardown_cmd_tx)` so callers can arm watches after
/// manual seed registration.
#[cfg(target_os = "linux")]
pub fn spawn_identity_correlator(
    config: IdentityCorrelatorConfig,
    maps: Arc<Mutex<IdentityAllowMaps>>,
    state: Arc<CorrelatorState>,
    #[cfg(feature = "orchestrator")] metrics: Arc<crate::observability::AgentMetrics>,
    shutdown: CancellationToken,
) -> Option<(
    tokio::task::JoinHandle<()>,
    tokio::sync::mpsc::UnboundedSender<TeardownCmd>,
)> {
    if !config.enabled {
        tracing::info!(
            target: "neuromesh::identity_correlator",
            "NEUROMESH_IDENTITY_CORRELATOR disabled — Slice 2b-i invalidation not running"
        );
        return None;
    }

    tracing::info!(
        target: "neuromesh::identity_correlator",
        node = %config.node_name,
        cgroup_root = %config.cgroup_root.display(),
        "starting Slice 2b-i identity invalidation correlator"
    );

    let (tx_cmd, rx_cmd) = tokio::sync::mpsc::unbounded_channel::<TeardownCmd>();
    let (tx_batch, rx_batch) =
        tokio::sync::mpsc::unbounded_channel::<teardown_watch::TeardownBatch>();

    let shutdown_watch = shutdown.clone();
    let _inotify_worker = std::thread::Builder::new()
        .name("nm-cgroup-inotify".into())
        .spawn(move || inotify_worker_loop(rx_cmd, tx_batch, shutdown_watch))
        .expect("spawn inotify worker thread");

    let tx_cmd_for_task = tx_cmd.clone();
    let handle = tokio::spawn(async move {
        if let Err(e) = run_correlator(
            config,
            maps,
            state,
            tx_cmd_for_task,
            rx_batch,
            #[cfg(feature = "orchestrator")]
            metrics,
            shutdown,
        )
        .await
        {
            tracing::error!(
                target: "neuromesh::identity_correlator",
                error = %e,
                "identity correlator exited with error"
            );
        }
    });

    Some((handle, tx_cmd))
}

#[cfg(not(target_os = "linux"))]
pub fn spawn_identity_correlator(
    config: IdentityCorrelatorConfig,
    _maps: Arc<Mutex<IdentityAllowMaps>>,
    _state: Arc<CorrelatorState>,
    #[cfg(feature = "orchestrator")] _metrics: Arc<crate::observability::AgentMetrics>,
    _shutdown: CancellationToken,
) -> Option<()> {
    if config.enabled {
        tracing::error!(
            target: "neuromesh::identity_correlator",
            "identity correlator enabled but this platform is not Linux — refusing to run"
        );
    }
    None
}

#[cfg(target_os = "linux")]
fn inotify_worker_loop(
    mut rx_cmd: tokio::sync::mpsc::UnboundedReceiver<TeardownCmd>,
    tx_batch: tokio::sync::mpsc::UnboundedSender<teardown_watch::TeardownBatch>,
    shutdown: CancellationToken,
) {
    let mut watcher = match teardown_watch::TeardownWatcher::new() {
        Ok(w) => w,
        Err(e) => {
            tracing::error!(
                target: "neuromesh::identity_correlator",
                error = %e,
                "inotify init failed — teardown watch unavailable"
            );
            return;
        }
    };

    while !shutdown.is_cancelled() {
        while let Ok(cmd) = rx_cmd.try_recv() {
            match cmd {
                TeardownCmd::Watch(path) => {
                    match watcher.watch_path(&path) {
                        Ok(true) => {
                            log::info!(
                                "armed inotify teardown watch path={}",
                                path.display()
                            );
                            tracing::info!(
                                target: "neuromesh::identity_correlator",
                                path = %path.display(),
                                "armed inotify teardown watch"
                            );
                        }
                        Ok(false) => {
                            tracing::debug!(
                                target: "neuromesh::identity_correlator",
                                path = %path.display(),
                                "inotify watch already armed for path"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                target: "neuromesh::identity_correlator",
                                path = %path.display(),
                                error = %e,
                                "failed to watch cgroup path"
                            );
                            log::warn!(
                                "failed to watch cgroup path={}: {e}",
                                path.display()
                            );
                        }
                    }
                }
                TeardownCmd::Unwatch(path) => {
                    let _ = watcher.unwatch_path(&path);
                }
                TeardownCmd::Rearm(paths) => {
                    if let Err(e) = watcher.rearm_paths(paths) {
                        tracing::warn!(
                            target: "neuromesh::identity_correlator",
                            error = %e,
                            "failed to rearm cgroup watches"
                        );
                    }
                }
            }
        }

        let mut fds = [libc::pollfd {
            fd: std::os::fd::AsRawFd::as_raw_fd(&watcher),
            events: libc::POLLIN,
            revents: 0,
        }];
        let pr = unsafe { libc::poll(fds.as_mut_ptr(), 1, 200) };
        if pr > 0 {
            match watcher.drain_events() {
                Ok(batch) if batch.overflow || !batch.torn_down_paths.is_empty() => {
                    let _ = tx_batch.send(batch);
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::error!(
                        target: "neuromesh::identity_correlator",
                        error = %e,
                        "inotify drain failed"
                    );
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
async fn run_correlator(
    config: IdentityCorrelatorConfig,
    maps: Arc<Mutex<IdentityAllowMaps>>,
    state: Arc<CorrelatorState>,
    tx_cmd: tokio::sync::mpsc::UnboundedSender<TeardownCmd>,
    mut rx_batch: tokio::sync::mpsc::UnboundedReceiver<teardown_watch::TeardownBatch>,
    #[cfg(feature = "orchestrator")] metrics: Arc<crate::observability::AgentMetrics>,
    shutdown: CancellationToken,
) -> Result<()> {
    // Prefer full pod-watch + teardown. If the API is unavailable (lab droplet
    // without a cluster), keep teardown watch alone — that is the primary
    // recycle-race closer per the design decision.
    let client = match pod_watch::K8sClient::connect().await {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::error!(
                target: "neuromesh::identity_correlator",
                error = %e,
                "Kubernetes API client unavailable — running cgroup teardown invalidation ONLY \
                 (Pod DELETE watch disabled). Not production-complete."
            );
            None
        }
    };

    if let Some(ref client) = client {
        forced_resync(
            &config,
            client,
            &maps,
            &state,
            &tx_cmd,
            ResyncReason::Startup,
            #[cfg(feature = "orchestrator")]
            Some(metrics.as_ref()),
        )
        .await?;
    } else {
        let mut to_delete = Vec::new();
        {
            let mut table = state.side_table.lock().await;
            to_delete.extend(plan_missing_path_sweep(&mut table));
            let paths: Vec<_> = table
                .entries()
                .map(|(_, e)| e.cgroup_path.clone())
                .collect();
            let _ = tx_cmd.send(TeardownCmd::Rearm(paths));
        }
        apply_invalidations(
            &maps,
            &to_delete,
            InvalidationReason::ResyncSweep,
            #[cfg(feature = "orchestrator")]
            Some(metrics.as_ref()),
        )
        .await?;
        #[cfg(feature = "orchestrator")]
        metrics.record_identity_resync(ResyncReason::Startup.as_metric_label());
    }

    let mut rx_pod_delete = match client.clone() {
        Some(c) => Some(pod_watch::spawn_pod_delete_watch(
            c,
            config.node_name.clone(),
            shutdown.clone(),
        )),
        None => None,
    };

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,

            batch = rx_batch.recv() => {
                let Some(batch) = batch else { break; };
                if batch.overflow {
                    if let Some(ref client) = client {
                        if let Err(e) = forced_resync(
                            &config,
                            client,
                            &maps,
                            &state,
                            &tx_cmd,
                            ResyncReason::InotifyOverflow,
                            #[cfg(feature = "orchestrator")]
                            Some(metrics.as_ref()),
                        ).await {
                            tracing::error!(
                                target: "neuromesh::identity_correlator",
                                error = %e,
                                "inotify overflow resync failed"
                            );
                        }
                    } else {
                        #[cfg(feature = "orchestrator")]
                        metrics.record_identity_resync(
                            ResyncReason::InotifyOverflow.as_metric_label(),
                        );
                        let mut to_delete = Vec::new();
                        {
                            let mut table = state.side_table.lock().await;
                            to_delete.extend(plan_missing_path_sweep(&mut table));
                            let paths: Vec<_> = table
                                .entries()
                                .map(|(_, e)| e.cgroup_path.clone())
                                .collect();
                            let _ = tx_cmd.send(TeardownCmd::Rearm(paths));
                        }
                        let _ = apply_invalidations(
                            &maps,
                            &to_delete,
                            InvalidationReason::ResyncSweep,
                            #[cfg(feature = "orchestrator")]
                            Some(metrics.as_ref()),
                        ).await;
                    }
                    continue;
                }
                for path in batch.torn_down_paths {
                    let id = {
                        let mut table = state.side_table.lock().await;
                        match table.cgroup_id_for_path(&path) {
                            Some(cid) => plan_teardown(&mut table, cid),
                            None => None,
                        }
                    };
                    let _ = tx_cmd.send(TeardownCmd::Unwatch(path));
                    if let Some(id) = id {
                        let _ = apply_invalidations(
                            &maps,
                            &[id],
                            InvalidationReason::CgroupTeardown,
                            #[cfg(feature = "orchestrator")]
                            Some(metrics.as_ref()),
                        ).await;
                    }
                }
            }

            uid = async {
                match rx_pod_delete.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending::<Option<String>>().await,
                }
            } => {
                let Some(uid) = uid else {
                    rx_pod_delete = None;
                    continue;
                };
                let (ids, paths) = {
                    let mut table = state.side_table.lock().await;
                    let removed = table.remove_by_pod(&uid);
                    let paths: Vec<_> =
                        removed.iter().map(|(_, e)| e.cgroup_path.clone()).collect();
                    let ids: Vec<_> = removed.into_iter().map(|(id, _)| id).collect();
                    (ids, paths)
                };
                for p in paths {
                    let _ = tx_cmd.send(TeardownCmd::Unwatch(p));
                }
                let _ = apply_invalidations(
                    &maps,
                    &ids,
                    InvalidationReason::PodDelete,
                    #[cfg(feature = "orchestrator")]
                    Some(metrics.as_ref()),
                ).await;
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn forced_resync(
    config: &IdentityCorrelatorConfig,
    client: &pod_watch::K8sClient,
    maps: &Arc<Mutex<IdentityAllowMaps>>,
    state: &CorrelatorState,
    tx_cmd: &tokio::sync::mpsc::UnboundedSender<TeardownCmd>,
    reason: ResyncReason,
    #[cfg(feature = "orchestrator")] metrics: Option<&crate::observability::AgentMetrics>,
) -> Result<()> {
    tracing::error!(
        target: "neuromesh::identity_correlator",
        reason = reason.as_metric_label(),
        "forced identity correlator resync (fail-closed)"
    );
    #[cfg(feature = "orchestrator")]
    if let Some(m) = metrics {
        m.record_identity_resync(reason.as_metric_label());
    }

    let live_pods = pod_watch::list_pod_uids_on_node(client, &config.node_name).await?;

    let mut to_delete = Vec::new();
    {
        let mut table = state.side_table.lock().await;
        to_delete.extend(plan_missing_path_sweep(&mut table));

        let stale_uids: Vec<String> = table
            .entries()
            .filter_map(|(_, e)| {
                if !e.pod_uid.is_empty() && !live_pods.contains(&e.pod_uid) {
                    Some(e.pod_uid.clone())
                } else {
                    None
                }
            })
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        for uid in stale_uids {
            to_delete.extend(plan_pod_delete(&mut table, &uid));
        }
        let paths: Vec<_> = table
            .entries()
            .map(|(_, e)| e.cgroup_path.clone())
            .collect();
        let _ = tx_cmd.send(TeardownCmd::Rearm(paths));
    }

    to_delete.sort_unstable();
    to_delete.dedup();
    apply_invalidations(
        maps,
        &to_delete,
        InvalidationReason::ResyncSweep,
        #[cfg(feature = "orchestrator")]
        metrics,
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod overflow_resync_tests {
    use super::*;
    use crate::identity_correlator::side_table::SideEntry;

    #[test]
    fn overflow_reason_label() {
        assert_eq!(
            ResyncReason::InotifyOverflow.as_metric_label(),
            "inotify_overflow"
        );
    }

    #[test]
    fn simulated_overflow_sweep_removes_missing_paths() {
        // Unit stand-in for overflow→resync: missing paths are swept.
        let mut table = SideTable::new();
        table.insert(
            1,
            SideEntry {
                pod_uid: "p".into(),
                cgroup_path: PathBuf::from("/nonexistent/neuromesh-overflow-test-path"),
                inode: 1,
            },
        );
        let ids = plan_missing_path_sweep(&mut table);
        assert_eq!(ids, vec![1]);
        assert!(table.is_empty());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod manual_seed_bridge_tests {
    use super::*;
    use std::fs;

    /// Lab manual-seed path must populate the side table AND queue an inotify Watch
    /// — BPF map seeding alone is not enough (Slice 2a vs 2b-i bridge).
    #[tokio::test]
    async fn register_manual_seed_ids_fills_side_table_and_queues_watch() {
        let root = std::env::temp_dir().join(format!(
            "neuromesh-manual-seed-bridge-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let leaf = root.join("tracked");
        fs::create_dir_all(&leaf).unwrap();
        let cgroup_id = cgroup_resolve::inode_of_path(&leaf).unwrap();

        let state = CorrelatorState::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<TeardownCmd>();

        let entries = register_manual_seed_ids(&state, &root, &[cgroup_id], &tx)
            .await
            .expect("register_manual_seed_ids");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].cgroup_path, leaf);
        assert_eq!(entries[0].inode, cgroup_id);
        // Synthetic lab path is not kubepods — empty pod_uid is expected.
        assert!(entries[0].pod_uid.is_empty());

        {
            let table = state.side_table.lock().await;
            let got = table.get(cgroup_id).expect("side-table entry missing");
            assert_eq!(got.cgroup_path, leaf);
        }

        match rx.try_recv() {
            Ok(TeardownCmd::Watch(p)) => assert_eq!(p, leaf),
            other => panic!("expected TeardownCmd::Watch({leaf:?}), got {other:?}"),
        }

        let _ = fs::remove_dir_all(&root);
    }
}
