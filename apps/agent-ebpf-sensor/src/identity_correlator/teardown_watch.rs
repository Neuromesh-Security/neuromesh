//! inotify-based cgroup directory teardown watch (Slice 2b-i).
//!
//! Watches each side-table `cgroup_path` for `DELETE_SELF` / `MOVE_SELF`.
//! On `Q_OVERFLOW`, signals the correlator to run a forced fail-closed resync.

use anyhow::{Context, Result};
use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use std::collections::HashMap;
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

/// Tracks inotify watches for registered cgroup directories.
pub struct TeardownWatcher {
    inotify: Inotify,
    by_wd: HashMap<WatchDescriptor, PathBuf>,
    by_path: HashMap<PathBuf, WatchDescriptor>,
}

impl AsRawFd for TeardownWatcher {
    fn as_raw_fd(&self) -> RawFd {
        self.inotify.as_raw_fd()
    }
}

impl TeardownWatcher {
    pub fn new() -> Result<Self> {
        let inotify = Inotify::init().context("inotify_init1 failed")?;
        Ok(Self {
            inotify,
            by_wd: HashMap::new(),
            by_path: HashMap::new(),
        })
    }

    /// Watch an absolute cgroup directory for teardown.
    pub fn watch_path(&mut self, path: &Path) -> Result<()> {
        if self.by_path.contains_key(path) {
            return Ok(());
        }
        if !path.exists() {
            return Ok(());
        }
        let mask = WatchMask::DELETE_SELF | WatchMask::MOVE_SELF | WatchMask::ONLYDIR;
        let wd = self
            .inotify
            .watches()
            .add(path, mask)
            .with_context(|| format!("inotify add_watch {}", path.display()))?;
        self.by_path.insert(path.to_path_buf(), wd);
        self.by_wd.insert(wd, path.to_path_buf());
        Ok(())
    }

    pub fn unwatch_path(&mut self, path: &Path) -> Result<()> {
        let Some(wd) = self.by_path.remove(path) else {
            return Ok(());
        };
        self.by_wd.remove(&wd);
        let _ = self.inotify.watches().remove(wd);
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
    pub fn rearm_paths<I, P>(&mut self, paths: I) -> Result<()>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        self.clear_all_watches()?;
        for p in paths {
            self.watch_path(p.as_ref())?;
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
                if ev.mask.contains(EventMask::Q_OVERFLOW) {
                    batch.overflow = true;
                    tracing::error!(
                        target: "neuromesh::identity_correlator",
                        "SECURITY: inotify queue overflow — forcing fail-closed correlator resync"
                    );
                    continue;
                }
                if ev.mask.contains(EventMask::DELETE_SELF)
                    || ev.mask.contains(EventMask::MOVE_SELF)
                    || ev.mask.contains(EventMask::IGNORED)
                {
                    if let Some(path) = self.by_wd.remove(&ev.wd) {
                        self.by_path.remove(&path);
                        batch.torn_down_paths.push(path);
                    }
                }
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

    #[test]
    fn detects_directory_teardown() {
        let base = std::env::temp_dir().join(format!("nm-inotify-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let leaf = base.join("leaf");
        fs::create_dir_all(&leaf).unwrap();

        let mut w = TeardownWatcher::new().unwrap();
        w.watch_path(&leaf).unwrap();
        fs::remove_dir(&leaf).unwrap();

        let mut batch = TeardownBatch::default();
        for _ in 0..50 {
            batch = w.drain_events().unwrap();
            if !batch.torn_down_paths.is_empty() || batch.overflow {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(
            batch.torn_down_paths.iter().any(|p| p == &leaf),
            "expected teardown of {leaf:?}, got {:?}",
            batch.torn_down_paths
        );
        let _ = fs::remove_dir_all(&base);
    }
}
