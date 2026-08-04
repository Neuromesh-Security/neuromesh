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
}
