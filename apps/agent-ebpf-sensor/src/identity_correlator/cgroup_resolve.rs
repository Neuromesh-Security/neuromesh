//! Resolve `cgroup_id` (cgroup v2 inode) → absolute directory path by walking
//! the cgroup hierarchy. Linux only.

use anyhow::{bail, Context, Result};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Walk `cgroup_root` depth-first; return the directory whose inode equals `cgroup_id`.
pub fn path_for_cgroup_id(cgroup_root: &Path, cgroup_id: u64) -> Result<PathBuf> {
    if !cgroup_root.is_dir() {
        bail!(
            "cgroup root {} is not a directory",
            cgroup_root.display()
        );
    }
    match find_inode(cgroup_root, cgroup_id)? {
        Some(p) => Ok(p),
        None => bail!(
            "no cgroup directory under {} with inode/cgroup_id={cgroup_id}",
            cgroup_root.display()
        ),
    }
}

/// Read the inode of a cgroup directory (equals `bpf_get_current_cgroup_id()` on v2).
pub fn inode_of_path(path: &Path) -> Result<u64> {
    let meta = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    Ok(meta.ino())
}

fn find_inode(dir: &Path, target: u64) -> Result<Option<PathBuf>> {
    let meta = fs::metadata(dir).with_context(|| format!("stat {}", dir.display()))?;
    if meta.ino() == target {
        return Ok(Some(dir.to_path_buf()));
    }

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Ok(None),
        Err(e) => {
            return Err(e).with_context(|| format!("read_dir {}", dir.display()));
        }
    };

    for ent in entries {
        let ent = ent.with_context(|| format!("readdir {}", dir.display()))?;
        let ft = ent
            .file_type()
            .with_context(|| format!("file_type {}", ent.path().display()))?;
        if !ft.is_dir() {
            continue;
        }
        // Skip non-cgroup noise if present.
        let name = ent.file_name();
        let name = name.to_string_lossy();
        if name == "." || name == ".." {
            continue;
        }
        if let Some(found) = find_inode(&ent.path(), target)? {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn finds_temp_dir_inode() {
        let dir = std::env::temp_dir().join(format!("neuromesh-cgroup-resolve-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let leaf = dir.join("leaf");
        fs::create_dir_all(&leaf).unwrap();
        let ino = inode_of_path(&leaf).unwrap();
        let found = path_for_cgroup_id(&dir, ino).unwrap();
        assert_eq!(found, leaf);
        let _ = fs::remove_dir_all(&dir);
    }
}
