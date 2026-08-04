//! inotify-based cgroup directory teardown watch (Slice 2b-i).
//!
//! ## Why parent watches (not `DELETE_SELF` on the leaf)
//!
//! Regular filesystems (tmpfs/ext4) deliver `IN_DELETE_SELF` / `IN_IGNORED` when
//! the watched directory itself is `rmdir`'d — see `inotify(7)` and
//! `WatchMask::DELETE_SELF` in the `inotify` crate.
//!
//! **cgroupfs is kernfs.** Kernfs historically does **not** emit
//! `IN_DELETE_SELF` / `IN_IGNORED` on cgroup directory removal even when
//! `inotify_add_watch(..., IN_DELETE_SELF)` succeeds (LKML 2023 thread
//! "KernFS: Missing IN_DELETE_SELF or IN_IGNORED"; kernfs patches to add those
//! events are far newer than typical droplet/Azure kernels ~6.8). Symptom:
//! watch appears armed, `rmdir` of the cgroup happens, **zero events**.
//!
//! VFS still notifies the **parent** directory with `IN_DELETE` /
//! `IN_MOVED_FROM` when a child is removed. So we watch the parent for those
//! masks and match the child basename.
//!
//! On `Q_OVERFLOW`, signals the correlator to run a forced fail-closed resync.

use anyhow::{bail, Context, Result};
use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

/// Outcome of draining one inotify read batch.
#[derive(Debug, Default)]
pub struct TeardownBatch {
    /// Absolute paths whose watches fired as teardown.
    pub torn_down_paths: Vec<PathBuf>,
    /// Kernel inotify queue overflowed — caller MUST forced-resync.
    pub overflow: bool,
}

struct ParentWatch {
    wd: WatchDescriptor,
    /// Child directory names under this parent we care about.
    children: HashSet<OsString>,
}

/// Tracks inotify watches for registered cgroup directories (via their parents).
pub struct TeardownWatcher {
    inotify: Inotify,
    /// Watch descriptor → parent path.
    by_wd: HashMap<WatchDescriptor, PathBuf>,
    /// Parent path → active watch + child set.
    by_parent: HashMap<PathBuf, ParentWatch>,
    /// Full cgroup path → (parent, child name) for unwatch.
    by_path: HashMap<PathBuf, (PathBuf, OsString)>,
}

impl AsRawFd for TeardownWatcher {
    fn as_raw_fd(&self) -> RawFd {
        self.inotify.as_raw_fd()
    }
}

impl TeardownWatcher {
    pub fn new() -> Result<Self> {
        // `Inotify::init` sets IN_CLOEXEC | IN_NONBLOCK (inotify 0.11 docs).
        let inotify = Inotify::init().context("inotify_init1 failed")?;
        Ok(Self {
            inotify,
            by_wd: HashMap::new(),
            by_parent: HashMap::new(),
            by_path: HashMap::new(),
        })
    }

    /// Watch an absolute cgroup directory for teardown.
    ///
    /// Returns `true` when this full path was newly registered, `false` if it
    /// was already tracked. Missing paths / missing parents are errors.
    pub fn watch_path(&mut self, path: &Path) -> Result<bool> {
        if self.by_path.contains_key(path) {
            return Ok(false);
        }
        if !path.exists() {
            bail!(
                "cannot inotify-watch {}: path does not exist",
                path.display()
            );
        }
        let parent = path.parent().ok_or_else(|| {
            anyhow::anyhow!(
                "cannot inotify-watch {}: no parent directory",
                path.display()
            )
        })?;
        let child = path.file_name().ok_or_else(|| {
            anyhow::anyhow!(
                "cannot inotify-watch {}: no file name component",
                path.display()
            )
        })?;
        let child = child.to_os_string();
        let parent_buf = parent.to_path_buf();

        if let Some(pw) = self.by_parent.get_mut(&parent_buf) {
            pw.children.insert(child.clone());
            self.by_path.insert(path.to_path_buf(), (parent_buf, child));
            return Ok(true);
        }

        // Parent watch: child unlink/rename — works on cgroupfs/kernfs where
        // DELETE_SELF on the leaf does not.
        let mask = WatchMask::DELETE | WatchMask::MOVED_FROM | WatchMask::ONLYDIR;
        let wd = self
            .inotify
            .watches()
            .add(&parent_buf, mask)
            .with_context(|| {
                format!(
                    "inotify add_watch parent {} (for child {})",
                    parent_buf.display(),
                    Path::new(&child).display()
                )
            })?;

        let mut children = HashSet::new();
        children.insert(child.clone());
        self.by_wd.insert(wd.clone(), parent_buf.clone());
        self.by_parent
            .insert(parent_buf.clone(), ParentWatch { wd, children });
        self.by_path.insert(path.to_path_buf(), (parent_buf, child));
        Ok(true)
    }

    pub fn unwatch_path(&mut self, path: &Path) -> Result<()> {
        let Some((parent, child)) = self.by_path.remove(path) else {
            return Ok(());
        };
        let Some(mut pw) = self.by_parent.remove(&parent) else {
            return Ok(());
        };
        pw.children.remove(&child);
        if pw.children.is_empty() {
            self.by_wd.remove(&pw.wd);
            let _ = self.inotify.watches().remove(pw.wd);
        } else {
            self.by_parent.insert(parent, pw);
        }
        Ok(())
    }

    pub fn clear_all_watches(&mut self) -> Result<()> {
        let paths: Vec<PathBuf> = self.by_path.keys().cloned().collect();
        for p in paths {
            self.unwatch_path(&p)?;
        }
        Ok(())
    }

    /// Re-arm watches for every path currently in the side table (post-resync).
    ///
    /// An **empty** path list is a no-op: it must not `clear_all_watches`.
    pub fn rearm_paths<I, P>(&mut self, paths: I) -> Result<()>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let paths: Vec<PathBuf> = paths
            .into_iter()
            .map(|p| p.as_ref().to_path_buf())
            .collect();
        if paths.is_empty() {
            return Ok(());
        }
        self.clear_all_watches()?;
        for p in &paths {
            self.watch_path(p)?;
        }
        Ok(())
    }

    /// Non-blocking drain of pending events into a [`TeardownBatch`].
    pub fn drain_events(&mut self) -> Result<TeardownBatch> {
        let mut batch = TeardownBatch::default();
        let mut buf = [0u8; 8192];
        loop {
            let events = match self.inotify.read_events(&mut buf) {
                Ok(e) => e,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e).context("inotify read_events"),
            };
            let mut saw_any = false;
            for ev in events {
                saw_any = true;
                let mask_bits = ev.mask.bits();
                let parent = self.by_wd.get(&ev.wd).cloned();
                let name = ev
                    .name
                    .as_ref()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();

                // Diagnostic: every raw event (even ignored ones) so droplet
                // runs can distinguish "never fires" vs "fires but filtered".
                log::info!(
                    "inotify raw event wd={} mask=0x{:x} parent={} name={:?} \
                     DELETE={} MOVED_FROM={} DELETE_SELF={} IGNORED={} Q_OVERFLOW={}",
                    ev.wd.get_watch_descriptor_id(),
                    mask_bits,
                    parent
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "<unknown-wd>".into()),
                    name,
                    ev.mask.contains(EventMask::DELETE),
                    ev.mask.contains(EventMask::MOVED_FROM),
                    ev.mask.contains(EventMask::DELETE_SELF),
                    ev.mask.contains(EventMask::IGNORED),
                    ev.mask.contains(EventMask::Q_OVERFLOW),
                );
                tracing::info!(
                    target: "neuromesh::identity_correlator",
                    wd = ev.wd.get_watch_descriptor_id(),
                    mask = format_args!("0x{mask_bits:x}"),
                    parent = %parent
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "<unknown-wd>".into()),
                    name = %name,
                    "inotify raw event"
                );

                if ev.mask.contains(EventMask::Q_OVERFLOW) {
                    batch.overflow = true;
                    tracing::error!(
                        target: "neuromesh::identity_correlator",
                        "SECURITY: inotify queue overflow — forcing fail-closed correlator resync"
                    );
                    continue;
                }

                // Parent lost a child (cgroupfs-compatible path).
                let is_child_gone =
                    ev.mask.contains(EventMask::DELETE) || ev.mask.contains(EventMask::MOVED_FROM);
                if !is_child_gone {
                    log::info!(
                        "inotify event mask=0x{:x} for parent={} name={:?} — \
                         not DELETE/MOVED_FROM child teardown, ignoring",
                        mask_bits,
                        parent
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "<unknown>".into()),
                        name
                    );
                    continue;
                }

                let Some(parent_path) = parent else {
                    log::warn!(
                        "inotify DELETE/MOVED_FROM for unknown wd={} name={:?} — ignoring",
                        ev.wd.get_watch_descriptor_id(),
                        name
                    );
                    continue;
                };
                if name.is_empty() {
                    log::info!(
                        "inotify DELETE/MOVED_FROM on parent={} with empty name — ignoring",
                        parent_path.display()
                    );
                    continue;
                }
                let child = OsString::from(&name);
                let should_drop_parent = {
                    let Some(pw) = self.by_parent.get_mut(&parent_path) else {
                        continue;
                    };
                    if !pw.children.remove(&child) {
                        log::info!(
                            "inotify child teardown parent={} name={:?} — not in tracked set, ignoring",
                            parent_path.display(),
                            name
                        );
                        continue;
                    }
                    pw.children.is_empty()
                };
                let full = parent_path.join(&child);
                self.by_path.remove(&full);
                if should_drop_parent {
                    if let Some(pw) = self.by_parent.remove(&parent_path) {
                        self.by_wd.remove(&pw.wd);
                        // Watch may already be IGNORED by kernel; ignore rm errors.
                        let _ = self.inotify.watches().remove(pw.wd);
                    }
                }
                log::info!(
                    "inotify child teardown matched full path={}",
                    full.display()
                );
                batch.torn_down_paths.push(full);
            }
            if !saw_any || batch.overflow {
                break;
            }
        }
        Ok(batch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn drain_until(w: &mut TeardownWatcher) -> TeardownBatch {
        let mut batch = TeardownBatch::default();
        for _ in 0..50 {
            batch = w.drain_events().unwrap();
            if !batch.torn_down_paths.is_empty() || batch.overflow {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        batch
    }

    #[test]
    fn detects_directory_teardown_via_parent_delete() {
        let base = std::env::temp_dir().join(format!("nm-inotify-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let leaf = base.join("leaf");
        fs::create_dir_all(&leaf).unwrap();

        let mut w = TeardownWatcher::new().unwrap();
        w.watch_path(&leaf).unwrap();
        fs::remove_dir(&leaf).unwrap();

        let batch = drain_until(&mut w);
        assert!(
            batch.torn_down_paths.iter().any(|p| p == &leaf),
            "expected teardown of {leaf:?}, got {:?}",
            batch.torn_down_paths
        );
        let _ = fs::remove_dir_all(&base);
    }

    /// Parent watches see DELETE for *any* sibling. Only the tracked leaf name
    /// must produce a teardown path — unrelated siblings must be ignored.
    #[test]
    fn unrelated_sibling_delete_does_not_invalidate_tracked_child() {
        let base = std::env::temp_dir().join(format!(
            "nm-inotify-sib-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let tracked = base.join("tracked-cgroup");
        let sibling = base.join("unrelated-sibling");
        fs::create_dir_all(&tracked).unwrap();
        fs::create_dir_all(&sibling).unwrap();

        let mut w = TeardownWatcher::new().unwrap();
        assert!(w.watch_path(&tracked).unwrap());

        // Sibling teardown under the same parent watch — must NOT match.
        fs::remove_dir(&sibling).unwrap();
        let after_sibling = drain_until(&mut w);
        assert!(
            after_sibling.torn_down_paths.is_empty(),
            "unrelated sibling delete must not invalidate; got {:?}",
            after_sibling.torn_down_paths
        );
        assert!(
            w.by_path.contains_key(&tracked),
            "tracked path must remain registered after sibling delete"
        );

        // Tracked leaf teardown — must match only that full path.
        fs::remove_dir(&tracked).unwrap();
        let after_tracked = drain_until(&mut w);
        assert_eq!(
            after_tracked.torn_down_paths,
            vec![tracked.clone()],
            "only the tracked child name must invalidate"
        );
        assert!(!w.by_path.contains_key(&tracked));

        let _ = fs::remove_dir_all(&base);
    }

    /// Accumulate drained events until `expect` teardowns (or overflow / timeout).
    fn drain_accumulate(w: &mut TeardownWatcher, expect: usize) -> TeardownBatch {
        let mut acc = TeardownBatch::default();
        for _ in 0..100 {
            let batch = w.drain_events().unwrap();
            acc.torn_down_paths.extend(batch.torn_down_paths);
            if batch.overflow {
                acc.overflow = true;
                break;
            }
            if acc.torn_down_paths.len() >= expect {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        acc
    }

    /// Slice 2b-ii-B: ≥3 tracked children under one parent, burst-deleted.
    ///
    /// Proves parent-watch fan-out (not N=1 assumption): every tracked path
    /// appears exactly once, watcher indexes are empty, and the parent watch
    /// is dropped only after the last tracked child is gone.
    #[test]
    fn burst_teardown_three_tracked_children_under_one_parent() {
        use crate::identity_correlator::invalidate::plan_teardown;
        use crate::identity_correlator::side_table::{SideEntry, SideTable};

        let base = std::env::temp_dir().join(format!(
            "nm-inotify-burst-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();

        let leaves = [base.join("ctr-0"), base.join("ctr-1"), base.join("ctr-2")];
        for leaf in &leaves {
            fs::create_dir_all(leaf).unwrap();
        }

        let mut table = SideTable::new();
        for (i, leaf) in leaves.iter().enumerate() {
            let id = (100 + i) as u64;
            table.insert(
                id,
                SideEntry {
                    pod_uid: "pod-burst-uid".into(),
                    namespace: "default".into(),
                    service_account: "sa".into(),
                    spiffe_id: "spiffe://t/ns/default/sa/sa".into(),
                    cgroup_path: leaf.clone(),
                    inode: id,
                },
            );
        }
        assert_eq!(table.len(), 3);

        let mut w = TeardownWatcher::new().unwrap();
        for leaf in &leaves {
            assert!(w.watch_path(leaf).unwrap());
        }
        assert_eq!(w.by_path.len(), 3);
        assert_eq!(
            w.by_parent.len(),
            1,
            "all three children share one parent watch"
        );
        assert_eq!(w.by_parent.get(&base).map(|pw| pw.children.len()), Some(3));

        // Burst teardown: back-to-back rmdir with no intentional delay.
        for leaf in &leaves {
            fs::remove_dir(leaf).unwrap();
        }

        let batch = drain_accumulate(&mut w, 3);
        assert!(
            !batch.overflow,
            "this test exercises the per-event path, not Q_OVERFLOW"
        );

        let mut got = batch.torn_down_paths.clone();
        got.sort();
        let mut expected = leaves.to_vec();
        expected.sort();
        assert_eq!(
            got, expected,
            "torn_down_paths must contain every tracked path exactly once"
        );
        assert_eq!(
            batch.torn_down_paths.len(),
            3,
            "no duplicates (len must equal unique set)"
        );
        let unique: std::collections::HashSet<_> = batch.torn_down_paths.iter().collect();
        assert_eq!(unique.len(), 3);

        // Correlator-side cleanup for each reported path (mirrors drain→plan_teardown).
        for path in &batch.torn_down_paths {
            let id = table
                .cgroup_id_for_path(path)
                .expect("side-table must still know path before plan_teardown");
            assert_eq!(plan_teardown(&mut table, id), Some(id));
        }
        assert!(
            table.is_empty(),
            "side-table by_cgroup/by_path/by_pod must be clean after burst"
        );

        // Watcher indexes: parent dropped when last tracked child gone.
        assert!(
            w.by_path.is_empty(),
            "by_path must be empty; leftover={:?}",
            w.by_path.keys().collect::<Vec<_>>()
        );
        assert!(
            w.by_parent.is_empty(),
            "parent watch must drop when children set empties; leftover={:?}",
            w.by_parent.keys().collect::<Vec<_>>()
        );
        assert!(
            w.by_wd.is_empty(),
            "by_wd must clear with parent; leftover={:?}",
            w.by_wd.keys().collect::<Vec<_>>()
        );

        let _ = fs::remove_dir_all(&base);
    }

    /// Mid-burst: after the first of three tracked children is torn down, the
    /// parent watch must still be armed for the remaining two (N>1 regression).
    #[test]
    fn parent_watch_retained_until_last_of_three_children_gone() {
        let base = std::env::temp_dir().join(format!(
            "nm-inotify-retain-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let leaves = [base.join("a"), base.join("b"), base.join("c")];
        for leaf in &leaves {
            fs::create_dir_all(leaf).unwrap();
        }

        let mut w = TeardownWatcher::new().unwrap();
        for leaf in &leaves {
            w.watch_path(leaf).unwrap();
        }

        fs::remove_dir(&leaves[0]).unwrap();
        let first = drain_accumulate(&mut w, 1);
        assert_eq!(first.torn_down_paths, vec![leaves[0].clone()]);
        assert!(w.by_parent.contains_key(&base));
        assert_eq!(w.by_parent.get(&base).unwrap().children.len(), 2);
        assert_eq!(w.by_path.len(), 2);

        fs::remove_dir(&leaves[1]).unwrap();
        fs::remove_dir(&leaves[2]).unwrap();
        let rest = drain_accumulate(&mut w, 2);
        let mut got = rest.torn_down_paths;
        got.sort();
        let mut expect = vec![leaves[1].clone(), leaves[2].clone()];
        expect.sort();
        assert_eq!(got, expect);
        assert!(w.by_parent.is_empty());
        assert!(w.by_path.is_empty());
        assert!(w.by_wd.is_empty());

        let _ = fs::remove_dir_all(&base);
    }

    /// Slice 2b-ii-B: under a 3-child burst, if the correlator takes the
    /// Q_OVERFLOW fail-closed path (missing-path sweep) before/without fully
    /// consuming per-child DELETE events, all three side-table rows still clear.
    #[test]
    fn overflow_path_with_three_tracked_entries_clears_side_table() {
        use crate::identity_correlator::invalidate::plan_missing_path_sweep;
        use crate::identity_correlator::side_table::{SideEntry, SideTable};

        let base = std::env::temp_dir().join(format!(
            "nm-inotify-ovf3-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let leaves = [base.join("x"), base.join("y"), base.join("z")];
        for leaf in &leaves {
            fs::create_dir_all(leaf).unwrap();
        }

        let mut table = SideTable::new();
        let mut w = TeardownWatcher::new().unwrap();
        for (i, leaf) in leaves.iter().enumerate() {
            let id = (300 + i) as u64;
            table.insert(
                id,
                SideEntry {
                    pod_uid: "pod-ovf".into(),
                    namespace: "default".into(),
                    service_account: "sa".into(),
                    spiffe_id: "spiffe://t/ns/default/sa/sa".into(),
                    cgroup_path: leaf.clone(),
                    inode: id,
                },
            );
            w.watch_path(leaf).unwrap();
        }

        // Burst delete — do not drain; simulate overflow taking the resync path.
        for leaf in &leaves {
            fs::remove_dir(leaf).unwrap();
        }
        let mut ids = plan_missing_path_sweep(&mut table);
        ids.sort_unstable();
        assert_eq!(ids, vec![300, 301, 302]);
        assert!(table.is_empty());

        // Hygiene: drop watches (correlator Rearm after sweep with remaining paths).
        w.clear_all_watches().unwrap();
        assert!(w.by_path.is_empty());
        assert!(w.by_parent.is_empty());
        assert!(w.by_wd.is_empty());

        let _ = fs::remove_dir_all(&base);
    }
}
