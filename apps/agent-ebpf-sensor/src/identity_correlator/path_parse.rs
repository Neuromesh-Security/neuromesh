//! Parse Kubernetes cgroup path layouts (cgroupfs + systemd drivers).
//!
//! Exact formats (design report / kubelet):
//! - **cgroupfs:** `.../kubepods/[burstable|besteffort/]pod<UID>/<container_id>`
//!   Guaranteed QoS often omits the middle QoS directory.
//! - **systemd:** `.../kubepods.slice/kubepods-<qos>.slice/kubepods-<qos>-pod<UID>.slice/...`
//!   Pod UID hyphens are replaced with underscores in the path.
//!
//! Pure string parsing — unit-testable on any OS.

use std::path::Path;

/// Which kubelet cgroup driver layout produced the path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupPathStyle {
    Cgroupfs,
    Systemd,
}

/// Parsed pod identity from a host cgroup path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCgroupPath {
    /// Pod UID in canonical dashed form (`xxxxxxxx-xxxx-...`).
    pub pod_uid: String,
    pub container_id: Option<String>,
    pub qos: Option<String>,
    pub style: CgroupPathStyle,
}

/// Normalize a pod UID from either dashed or systemd-underscore form.
pub fn normalize_pod_uid(raw: &str) -> String {
    raw.replace('_', "-")
}

/// Extract pod UID + optional container id from a cgroup filesystem path.
///
/// Returns `None` when the path is not a recognizable Kubernetes pod cgroup.
pub fn parse_cgroup_path(path: &str) -> Option<ParsedCgroupPath> {
    let normalized = path.replace('\\', "/");
    if let Some(p) = parse_systemd(&normalized) {
        return Some(p);
    }
    parse_cgroupfs(&normalized)
}

fn path_components(path: &str) -> Vec<&str> {
    Path::new(path)
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .filter(|s| !s.is_empty() && *s != "/")
        .collect()
}

fn parse_cgroupfs(path: &str) -> Option<ParsedCgroupPath> {
    let comps = path_components(path);
    let kubepods_idx = comps.iter().position(|c| *c == "kubepods")?;

    // After kubepods: either podUID, or qos/podUID, then optional container id.
    let rest = &comps[kubepods_idx + 1..];
    if rest.is_empty() {
        return None;
    }

    let (qos, pod_comp, container_id) = if rest[0].starts_with("pod") {
        (None, rest[0], rest.get(1).copied())
    } else if rest.len() >= 2 && rest[1].starts_with("pod") {
        (Some(rest[0].to_string()), rest[1], rest.get(2).copied())
    } else {
        return None;
    };

    let uid_raw = pod_comp.strip_prefix("pod")?;
    if uid_raw.is_empty() {
        return None;
    }

    Some(ParsedCgroupPath {
        pod_uid: normalize_pod_uid(uid_raw),
        container_id: container_id
            .filter(|c| !c.is_empty() && !c.starts_with("pod"))
            .map(|s| s.to_string()),
        qos,
        style: CgroupPathStyle::Cgroupfs,
    })
}

fn parse_systemd(path: &str) -> Option<ParsedCgroupPath> {
    let comps = path_components(path);
    let _ = comps.iter().position(|c| *c == "kubepods.slice")?;

    // Look for a component matching kubepods-<qos>-pod<UID>.slice or
    // kubepods-pod<UID>.slice (guaranteed).
    let mut qos: Option<String> = None;
    let mut pod_uid: Option<String> = None;
    let mut container_id: Option<String> = None;

    for comp in &comps {
        if let Some(uid) = extract_systemd_pod_uid(comp) {
            // kubepods-burstable-podUID.slice → qos from prefix
            qos = extract_systemd_qos(comp);
            pod_uid = Some(uid);
            continue;
        }
        if pod_uid.is_some() {
            // cri-containerd-*.scope / docker-*.scope / cri-o-*.scope
            if comp.ends_with(".scope") {
                container_id = Some((*comp).to_string());
            }
        }
    }

    let pod_uid = pod_uid?;
    Some(ParsedCgroupPath {
        pod_uid,
        container_id,
        qos,
        style: CgroupPathStyle::Systemd,
    })
}

fn extract_systemd_qos(comp: &str) -> Option<String> {
    // kubepods-burstable-pod….slice or kubepods-besteffort-pod….slice
    let base = comp.strip_suffix(".slice")?;
    let rest = base.strip_prefix("kubepods-")?;
    if rest.starts_with("pod") {
        return None; // guaranteed: kubepods-podUID.slice
    }
    let qos = rest.split("-pod").next()?;
    if qos == "burstable" || qos == "besteffort" {
        Some(qos.to_string())
    } else {
        None
    }
}

fn extract_systemd_pod_uid(comp: &str) -> Option<String> {
    let base = comp.strip_suffix(".slice")?;
    // Find "-pod" marker (UID uses underscores).
    let idx = base.find("-pod")?;
    let uid_raw = &base[idx + 4..];
    if uid_raw.is_empty() || uid_raw.contains("kubepods") {
        return None;
    }
    // Must look like a UUID with underscores (36 chars dashed → 36 with _)
    // or at least contain underscores typical of systemd encoding.
    Some(normalize_pod_uid(uid_raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroupfs_burstable_with_container() {
        let p = parse_cgroup_path(
            "/sys/fs/cgroup/kubepods/burstable/podc52a7741-f290-4dde-b6e4-34e623dbc69e/81591f675f72",
        )
        .expect("parse");
        assert_eq!(p.pod_uid, "c52a7741-f290-4dde-b6e4-34e623dbc69e");
        assert_eq!(p.container_id.as_deref(), Some("81591f675f72"));
        assert_eq!(p.qos.as_deref(), Some("burstable"));
        assert_eq!(p.style, CgroupPathStyle::Cgroupfs);
    }

    #[test]
    fn cgroupfs_guaranteed_no_qos_dir() {
        let p = parse_cgroup_path(
            "/sys/fs/cgroup/kubepods/podaaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/deadbeef",
        )
        .expect("parse");
        assert_eq!(p.pod_uid, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        assert!(p.qos.is_none());
        assert_eq!(p.style, CgroupPathStyle::Cgroupfs);
    }

    #[test]
    fn systemd_burstable_pod_slice() {
        let p = parse_cgroup_path(
            "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podc52a7741_f290_4dde_b6e4_34e623dbc69e.slice/cri-containerd-abc123.scope",
        )
        .expect("parse");
        assert_eq!(p.pod_uid, "c52a7741-f290-4dde-b6e4-34e623dbc69e");
        assert_eq!(p.qos.as_deref(), Some("burstable"));
        assert_eq!(p.style, CgroupPathStyle::Systemd);
        assert!(p
            .container_id
            .as_deref()
            .unwrap()
            .contains("cri-containerd"));
    }

    #[test]
    fn systemd_guaranteed_pod_slice() {
        let p = parse_cgroup_path(
            "/sys/fs/cgroup/kubepods.slice/kubepods-podaaaaaaaa_bbbb_cccc_dddd_eeeeeeeeeeee.slice/cri-o-xyz.scope",
        )
        .expect("parse");
        assert_eq!(p.pod_uid, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        assert!(p.qos.is_none());
        assert_eq!(p.style, CgroupPathStyle::Systemd);
    }

    #[test]
    fn non_k8s_path_returns_none() {
        assert!(parse_cgroup_path("/sys/fs/cgroup/neuromesh-slice2a/allow").is_none());
        assert!(parse_cgroup_path("/sys/fs/cgroup/system.slice/foo.service").is_none());
    }

    #[test]
    fn normalize_underscores() {
        assert_eq!(
            normalize_pod_uid("c52a7741_f290_4dde_b6e4_34e623dbc69e"),
            "c52a7741-f290-4dde-b6e4-34e623dbc69e"
        );
    }
}
