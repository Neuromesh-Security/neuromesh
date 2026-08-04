//! Side table: `cgroup_id` ↔ `(pod_uid, path/inode, optional SPIFFE)`.
//!
//! Populated at manual seed / auto-insert time. Both invalidation paths (Pod DELETE
//! informer and cgroup teardown watch) consult this table — never invent
//! cgroup_ids from the K8s API alone without a prior insert/seed.

use neuromesh_common::IDENTITY_ALLOW_CGROUPS_MAX_ENTRIES;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

/// One tracked allowlisted cgroup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SideEntry {
    /// Canonical dashed pod UID when known (empty if non-K8s / unresolved).
    pub pod_uid: String,
    /// Namespace (auto-insert); empty for lab manual seeds.
    pub namespace: String,
    /// ServiceAccount name (auto-insert); empty for lab manual seeds.
    pub service_account: String,
    /// Constructed SPIFFE ID for PE revoke reconcile. **Empty for manual seeds**
    /// so PE allowlist revoke does not touch lab-only entries.
    pub spiffe_id: String,
    pub cgroup_path: PathBuf,
    /// cgroup v2 directory inode; equals `bpf_get_current_cgroup_id()` / map key.
    pub inode: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    Inserted,
    Replaced,
    /// Would exceed [`IDENTITY_ALLOW_CGROUPS_MAX_ENTRIES`] — caller must not insert.
    RejectedFull,
}

/// In-memory index for invalidation. Not the BPF map.
#[derive(Debug, Default)]
pub struct SideTable {
    by_cgroup: HashMap<u64, SideEntry>,
    by_pod: HashMap<String, HashSet<u64>>,
    by_path: HashMap<PathBuf, u64>,
}

impl SideTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.by_cgroup.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_cgroup.is_empty()
    }

    pub fn get(&self, cgroup_id: u64) -> Option<&SideEntry> {
        self.by_cgroup.get(&cgroup_id)
    }

    pub fn cgroup_ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.by_cgroup.keys().copied()
    }

    pub fn entries(&self) -> impl Iterator<Item = (u64, &SideEntry)> + '_ {
        self.by_cgroup.iter().map(|(k, v)| (*k, v))
    }

    pub fn insert(&mut self, cgroup_id: u64, entry: SideEntry) -> InsertOutcome {
        if !self.by_cgroup.contains_key(&cgroup_id)
            && self.by_cgroup.len() as u32 >= IDENTITY_ALLOW_CGROUPS_MAX_ENTRIES
        {
            return InsertOutcome::RejectedFull;
        }

        let outcome = if self.by_cgroup.contains_key(&cgroup_id) {
            InsertOutcome::Replaced
        } else {
            InsertOutcome::Inserted
        };

        if let Some(old) = self.by_cgroup.remove(&cgroup_id) {
            self.unlink_indexes(cgroup_id, &old);
        }

        if !entry.pod_uid.is_empty() {
            self.by_pod
                .entry(entry.pod_uid.clone())
                .or_default()
                .insert(cgroup_id);
        }
        self.by_path.insert(entry.cgroup_path.clone(), cgroup_id);
        self.by_cgroup.insert(cgroup_id, entry);
        outcome
    }

    pub fn remove_by_cgroup(&mut self, cgroup_id: u64) -> Option<SideEntry> {
        let entry = self.by_cgroup.remove(&cgroup_id)?;
        self.unlink_indexes(cgroup_id, &entry);
        Some(entry)
    }

    pub fn remove_by_pod(&mut self, pod_uid: &str) -> Vec<(u64, SideEntry)> {
        let Some(ids) = self.by_pod.remove(pod_uid) else {
            return Vec::new();
        };
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(entry) = self.by_cgroup.remove(&id) {
                self.by_path.remove(&entry.cgroup_path);
                out.push((id, entry));
            }
        }
        out
    }

    /// Auto-inserted entries whose `spiffe_id` is non-empty and not in `allowed`.
    /// Manual seeds (`spiffe_id` empty) are never selected.
    pub fn plan_pe_allowlist_revoke(&self, allowed: &HashSet<String>) -> Vec<u64> {
        self.by_cgroup
            .iter()
            .filter(|(_, e)| !e.spiffe_id.is_empty() && !allowed.contains(&e.spiffe_id))
            .map(|(id, _)| *id)
            .collect()
    }

    pub fn cgroup_id_for_path(&self, path: &std::path::Path) -> Option<u64> {
        self.by_path.get(path).copied()
    }

    pub fn clear(&mut self) -> Vec<(u64, SideEntry)> {
        let out: Vec<_> = self.by_cgroup.drain().collect();
        self.by_pod.clear();
        self.by_path.clear();
        out
    }

    /// Drop entries whose cgroup_path no longer exists on disk.
    /// Returns removed `(cgroup_id, entry)` pairs for BPF map deletes.
    pub fn sweep_missing_paths(&mut self) -> Vec<(u64, SideEntry)> {
        let stale: Vec<u64> = self
            .by_cgroup
            .iter()
            .filter(|(_, e)| !e.cgroup_path.exists())
            .map(|(id, _)| *id)
            .collect();
        let mut out = Vec::with_capacity(stale.len());
        for id in stale {
            if let Some(e) = self.remove_by_cgroup(id) {
                out.push((id, e));
            }
        }
        out
    }

    fn unlink_indexes(&mut self, cgroup_id: u64, entry: &SideEntry) {
        self.by_path.remove(&entry.cgroup_path);
        if !entry.pod_uid.is_empty() {
            if let Some(set) = self.by_pod.get_mut(&entry.pod_uid) {
                set.remove(&cgroup_id);
                if set.is_empty() {
                    self.by_pod.remove(&entry.pod_uid);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neuromesh_common::IDENTITY_ALLOW_CGROUPS_MAX_ENTRIES;
    use std::path::PathBuf;

    fn entry(uid: &str, path: &str, inode: u64) -> SideEntry {
        SideEntry {
            pod_uid: uid.to_string(),
            namespace: String::new(),
            service_account: String::new(),
            spiffe_id: String::new(),
            cgroup_path: PathBuf::from(path),
            inode,
        }
    }

    fn auto_entry(uid: &str, path: &str, inode: u64, spiffe: &str) -> SideEntry {
        SideEntry {
            pod_uid: uid.to_string(),
            namespace: "default".into(),
            service_account: "sa".into(),
            spiffe_id: spiffe.to_string(),
            cgroup_path: PathBuf::from(path),
            inode,
        }
    }

    #[test]
    fn max_entries_is_16384() {
        assert_eq!(IDENTITY_ALLOW_CGROUPS_MAX_ENTRIES, 16384);
    }

    #[test]
    fn insert_and_remove_by_cgroup() {
        let mut t = SideTable::new();
        assert_eq!(
            t.insert(10, entry("pod-a", "/cg/a", 10)),
            InsertOutcome::Inserted
        );
        assert_eq!(t.get(10).unwrap().pod_uid, "pod-a");
        let removed = t.remove_by_cgroup(10).unwrap();
        assert_eq!(removed.pod_uid, "pod-a");
        assert!(t.get(10).is_none());
        assert!(t.is_empty());
    }

    #[test]
    fn remove_by_pod_clears_all_cgroups() {
        let mut t = SideTable::new();
        t.insert(1, entry("uid-1", "/cg/1", 1));
        t.insert(2, entry("uid-1", "/cg/2", 2));
        t.insert(3, entry("uid-2", "/cg/3", 3));
        let gone = t.remove_by_pod("uid-1");
        assert_eq!(gone.len(), 2);
        assert!(t.get(1).is_none());
        assert!(t.get(2).is_none());
        assert!(t.get(3).is_some());
    }

    #[test]
    fn pe_revoke_skips_manual_seed_empty_spiffe() {
        let mut t = SideTable::new();
        t.insert(1, entry("uid-1", "/cg/1", 1));
        t.insert(
            2,
            auto_entry("uid-2", "/cg/2", 2, "spiffe://t/ns/n/sa/gone"),
        );
        let allowed = HashSet::new();
        let mut ids = t.plan_pe_allowlist_revoke(&allowed);
        ids.sort_unstable();
        assert_eq!(ids, vec![2]);
    }

    #[test]
    fn replace_updates_indexes() {
        let mut t = SideTable::new();
        t.insert(5, entry("old", "/cg/old", 5));
        assert_eq!(
            t.insert(5, entry("new", "/cg/new", 5)),
            InsertOutcome::Replaced
        );
        assert!(t
            .cgroup_id_for_path(std::path::Path::new("/cg/old"))
            .is_none());
        assert_eq!(
            t.cgroup_id_for_path(std::path::Path::new("/cg/new")),
            Some(5)
        );
        assert!(t.remove_by_pod("old").is_empty());
        assert_eq!(t.remove_by_pod("new").len(), 1);
    }
}
