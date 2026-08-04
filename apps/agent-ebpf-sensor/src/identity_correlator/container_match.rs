//! Match K8s `containerID` strings to cgroup leaf directories (Slice 2b-ii-A).

use std::path::{Path, PathBuf};

/// Strip `<runtime>://` from a K8s `status.*.containerID` value.
///
/// Returns `None` for empty / whitespace-only. If no `://` is present, returns
/// the trimmed string as-is (defensive).
pub fn strip_runtime_prefix(container_id: &str) -> Option<String> {
    let s = container_id.trim();
    if s.is_empty() {
        return None;
    }
    if let Some((_, rest)) = s.split_once("://") {
        let rest = rest.trim();
        if rest.is_empty() {
            return None;
        }
        return Some(rest.to_string());
    }
    Some(s.to_string())
}

/// Whether a cgroup child basename (dir or `.scope`) matches `raw_id`.
pub fn child_matches_raw_id(child_name: &str, raw_id: &str) -> bool {
    if raw_id.is_empty() {
        return false;
    }
    if child_name == raw_id {
        return true;
    }
    // systemd: cri-containerd-<id>.scope / crio-<id>.scope / docker-<id>.scope
    if child_name.contains(raw_id) && child_name.ends_with(".scope") {
        return true;
    }
    // Short prefix match (some runtimes truncate directory names).
    if raw_id.len() >= 12 && child_name.len() >= 12 && raw_id.starts_with(child_name) {
        return true;
    }
    if child_name.len() >= 12 && raw_id.len() >= 12 && child_name.starts_with(&raw_id[..12]) {
        return true;
    }
    false
}

/// Candidate pod-level directories for both kubelet cgroup drivers.
pub fn candidate_pod_dirs(cgroup_root: &Path, pod_uid: &str) -> Vec<PathBuf> {
    let uid = pod_uid.trim();
    let uid_under = uid.replace('-', "_");
    let mut out = Vec::with_capacity(8);
    // cgroupfs
    out.push(cgroup_root.join("kubepods").join(format!("pod{uid}")));
    out.push(
        cgroup_root
            .join("kubepods")
            .join("burstable")
            .join(format!("pod{uid}")),
    );
    out.push(
        cgroup_root
            .join("kubepods")
            .join("besteffort")
            .join(format!("pod{uid}")),
    );
    // systemd
    let slice_root = cgroup_root.join("kubepods.slice");
    out.push(slice_root.join(format!("kubepods-pod{uid_under}.slice")));
    out.push(
        slice_root
            .join("kubepods-burstable.slice")
            .join(format!("kubepods-burstable-pod{uid_under}.slice")),
    );
    out.push(
        slice_root
            .join("kubepods-besteffort.slice")
            .join(format!("kubepods-besteffort-pod{uid_under}.slice")),
    );
    out
}

/// First existing candidate pod directory, if any.
pub fn find_existing_pod_dir(cgroup_root: &Path, pod_uid: &str) -> Option<PathBuf> {
    candidate_pod_dirs(cgroup_root, pod_uid)
        .into_iter()
        .find(|p| p.is_dir())
}

/// Find the container leaf under `pod_dir` matching `raw_id`.
pub fn find_container_leaf(pod_dir: &Path, raw_id: &str) -> Option<PathBuf> {
    let entries = std::fs::read_dir(pod_dir).ok()?;
    for ent in entries.flatten() {
        let name = ent.file_name();
        let name = name.to_string_lossy();
        if child_matches_raw_id(&name, raw_id) {
            let p = ent.path();
            if p.is_dir() {
                return Some(p);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn strips_containerd_prefix() {
        let id = "containerd://abc123def4567890abc123def4567890abc123def4567890abc123def4567890";
        let raw = strip_runtime_prefix(id).unwrap();
        assert!(raw.starts_with("abc123"));
        assert!(!raw.contains("://"));
    }

    #[test]
    fn strips_crio_and_docker() {
        assert_eq!(
            strip_runtime_prefix("cri-o://deadbeef").as_deref(),
            Some("deadbeef")
        );
        assert_eq!(
            strip_runtime_prefix("docker://cafe").as_deref(),
            Some("cafe")
        );
    }

    #[test]
    fn empty_container_id_skips() {
        assert!(strip_runtime_prefix("").is_none());
        assert!(strip_runtime_prefix("   ").is_none());
        assert!(strip_runtime_prefix("containerd://").is_none());
    }

    #[test]
    fn child_match_cgroupfs_exact() {
        let raw = "81591f675f72aabbccddeeff00112233445566778899aabbccddeeff00112233";
        assert!(child_matches_raw_id(raw, raw));
    }

    #[test]
    fn child_match_systemd_scope() {
        let raw = "abc123def456";
        assert!(child_matches_raw_id(
            &format!("cri-containerd-{raw}.scope"),
            raw
        ));
        assert!(child_matches_raw_id(&format!("crio-{raw}.scope"), raw));
    }

    #[test]
    fn find_leaf_on_temp_tree() {
        let base = std::env::temp_dir().join(format!(
            "nm-cmatch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&base);
        let pod = base.join("kubepods").join("podaaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        let leaf_name = "81591f675f72aabbccddeeff00112233445566778899aabbccddeeff00112233";
        fs::create_dir_all(pod.join(leaf_name)).unwrap();
        let pod_dir = find_existing_pod_dir(&base, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let leaf = find_container_leaf(&pod_dir, leaf_name).unwrap();
        assert_eq!(leaf.file_name().unwrap().to_string_lossy(), leaf_name);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn systemd_candidate_uses_underscores() {
        let dirs = candidate_pod_dirs(Path::new("/sys/fs/cgroup"), "a-b-c-d-e");
        assert!(dirs.iter().any(|p| p
            .to_string_lossy()
            .contains("kubepods-burstable-poda_b_c_d_e.slice")));
    }
}
