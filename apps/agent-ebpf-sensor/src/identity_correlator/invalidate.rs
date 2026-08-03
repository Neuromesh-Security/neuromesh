//! Pure invalidation planning (side table → cgroup_ids to delete from BPF).

use super::side_table::SideTable;

/// Why an allow entry was removed from the side table / BPF map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidationReason {
    PodDelete,
    CgroupTeardown,
    /// Forced resync discovered a missing path / gone pod.
    ResyncSweep,
}

impl InvalidationReason {
    pub fn as_metric_label(self) -> &'static str {
        match self {
            Self::PodDelete => "pod_delete",
            Self::CgroupTeardown => "cgroup_teardown",
            Self::ResyncSweep => "resync_sweep",
        }
    }
}

/// Why a full correlator resync was triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResyncReason {
    InotifyOverflow,
    Startup,
    WatchError,
}

impl ResyncReason {
    pub fn as_metric_label(self) -> &'static str {
        match self {
            Self::InotifyOverflow => "inotify_overflow",
            Self::Startup => "startup",
            Self::WatchError => "watch_error",
        }
    }
}

/// Plan BPF deletes for a Pod DELETE (all cgroups registered under that UID).
pub fn plan_pod_delete(table: &mut SideTable, pod_uid: &str) -> Vec<u64> {
    table
        .remove_by_pod(pod_uid)
        .into_iter()
        .map(|(id, _)| id)
        .collect()
}

/// Plan BPF delete for a single cgroup teardown event.
pub fn plan_teardown(table: &mut SideTable, cgroup_id: u64) -> Option<u64> {
    table.remove_by_cgroup(cgroup_id).map(|_| cgroup_id)
}

/// Sweep side-table entries whose paths no longer exist (forced resync step).
pub fn plan_missing_path_sweep(table: &mut SideTable) -> Vec<u64> {
    table
        .sweep_missing_paths()
        .into_iter()
        .map(|(id, _)| id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_correlator::side_table::SideEntry;
    use std::path::PathBuf;

    fn entry(uid: &str, path: &str, inode: u64) -> SideEntry {
        SideEntry {
            pod_uid: uid.to_string(),
            cgroup_path: PathBuf::from(path),
            inode,
        }
    }

    #[test]
    fn pod_delete_returns_all_ids() {
        let mut t = SideTable::new();
        t.insert(10, entry("u1", "/a", 10));
        t.insert(11, entry("u1", "/b", 11));
        let mut ids = plan_pod_delete(&mut t, "u1");
        ids.sort_unstable();
        assert_eq!(ids, vec![10, 11]);
        assert!(t.is_empty());
    }

    #[test]
    fn teardown_removes_one() {
        let mut t = SideTable::new();
        t.insert(7, entry("u", "/x", 7));
        assert_eq!(plan_teardown(&mut t, 7), Some(7));
        assert_eq!(plan_teardown(&mut t, 7), None);
    }

    #[test]
    fn metric_labels_stable() {
        assert_eq!(InvalidationReason::PodDelete.as_metric_label(), "pod_delete");
        assert_eq!(
            ResyncReason::InotifyOverflow.as_metric_label(),
            "inotify_overflow"
        );
    }
}
