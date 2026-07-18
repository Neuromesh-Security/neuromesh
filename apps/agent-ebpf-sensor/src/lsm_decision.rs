//! Userspace mirror of the LSM decision-critical fail-closed contract (Issue #54).
//!
//! The eBPF hook in `ebpf/src/main.rs` cannot unit-test `bpf_probe_read_kernel`
//! failures directly. This module encodes the same allow/deny outcomes the
//! enforcement path must produce so tests can prove:
//! - probe failure on the filename pointer → DENY
//! - probe failure on path bytes → DENY (never zero-prefix ALLOW)
//! - successful reads keep the same allow/deny outcomes as the deny-list matchers

use crate::path_deny::map_backed_is_blacklisted;
use neuromesh_common::{PathDenyEntry, PATH_DENY_KEY_BYTES};

/// LSM allow — matches kernel `bprm_check_security` "0 means proceed".
pub const LSM_ALLOW: i32 = 0;

/// LSM deny — maps to `-EPERM` (`ebpf/src/main.rs` `LSM_DENY`).
pub const LSM_DENY: i32 = -1;

/// Result of capturing the path prefix used for deny matching.
///
/// Mirrors the two failure modes that previously fail-opened in
/// `read_bprm_filename_ptr` / `read_bprm_path_prefix`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathCapture {
    /// Successfully read `PATH_DENY_KEY_BYTES` from the bprm filename.
    Ok([u8; PATH_DENY_KEY_BYTES]),
    /// `bpf_probe_read_kernel` failed reading `linux_binprm->filename`.
    FilenamePointerUnreadable,
    /// Filename pointer was obtained, but reading the path bytes failed.
    PathBytesUnreadable,
}

/// Decision-critical enforcement outcome for a path-capture result.
///
/// Failures to obtain the path → [`LSM_DENY`]. Successful captures apply the
/// deny-list match only (identical to map-backed / legacy `starts_with` logic).
pub fn decision_from_path_capture(capture: PathCapture, deny_entries: &[PathDenyEntry]) -> i32 {
    match capture {
        PathCapture::FilenamePointerUnreadable | PathCapture::PathBytesUnreadable => LSM_DENY,
        PathCapture::Ok(prefix) => {
            if map_backed_is_blacklisted(&prefix, deny_entries) {
                LSM_DENY
            } else {
                LSM_ALLOW
            }
        }
    }
}

/// Outer LSM wrapper contract: any `Err` from the try-path is DENY, not ALLOW.
pub fn lsm_hook_result(try_path: Result<i32, i64>) -> i32 {
    match try_path {
        Ok(ret) => ret,
        Err(_) => LSM_DENY,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path_deny::{bootstrap_entries, legacy_hardcoded_is_blacklisted};

    fn bootstrap() -> Vec<PathDenyEntry> {
        bootstrap_entries().expect("bootstrap deny list")
    }

    fn window(path: &str) -> [u8; PATH_DENY_KEY_BYTES] {
        let mut buf = [0u8; PATH_DENY_KEY_BYTES];
        let n = path.len().min(PATH_DENY_KEY_BYTES);
        buf[..n].copy_from_slice(&path.as_bytes()[..n]);
        buf
    }

    #[test]
    fn filename_pointer_probe_failure_is_deny() {
        let entries = bootstrap();
        assert_eq!(
            decision_from_path_capture(PathCapture::FilenamePointerUnreadable, &entries),
            LSM_DENY
        );
        assert_eq!(
            lsm_hook_result(Err(-14)), // EFAULT-class probe failure
            LSM_DENY
        );
    }

    #[test]
    fn path_bytes_probe_failure_is_deny_not_zero_prefix_allow() {
        let entries = bootstrap();
        // The old bug returned Ok([0;16]), which does not match any deny prefix
        // and would ALLOW. Fail-closed must DENY instead.
        assert_eq!(
            decision_from_path_capture(PathCapture::PathBytesUnreadable, &entries),
            LSM_DENY
        );
        assert_ne!(
            decision_from_path_capture(PathCapture::Ok([0u8; PATH_DENY_KEY_BYTES]), &entries),
            LSM_DENY,
            "a successfully-read all-zero window is not a deny-list hit; only probe *failure* denies"
        );
        assert_eq!(
            decision_from_path_capture(PathCapture::Ok([0u8; PATH_DENY_KEY_BYTES]), &entries),
            LSM_ALLOW
        );
    }

    #[test]
    fn successful_reads_preserve_allow_deny_vs_legacy_and_map() {
        let entries = bootstrap();
        let cases = [
            "/tmp/evil",
            "/tmp/",
            "/tmp2/x",
            "/dev/shm/x",
            "/var/tmp/y",
            "/usr/bin/ls",
            "",
            "/home/user",
        ];
        for path in cases {
            let prefix = window(path);
            let expected = if legacy_hardcoded_is_blacklisted(&prefix) {
                LSM_DENY
            } else {
                LSM_ALLOW
            };
            assert_eq!(
                legacy_hardcoded_is_blacklisted(&prefix),
                map_backed_is_blacklisted(&prefix, &entries),
                "legacy vs map disagree for {path:?}"
            );
            assert_eq!(
                decision_from_path_capture(PathCapture::Ok(prefix), &entries),
                expected,
                "decision drift for successful read of {path:?}"
            );
            assert_eq!(
                lsm_hook_result(Ok(expected)),
                expected,
                "hook wrapper must not alter successful Ok outcomes"
            );
        }
    }

    #[test]
    fn try_path_err_never_fail_opens_via_hook_wrapper() {
        // Explicit regression: the previous contract was Err(_) => 0 (ALLOW).
        assert_eq!(lsm_hook_result(Err(-1)), LSM_DENY);
        assert_eq!(lsm_hook_result(Err(0)), LSM_DENY);
        assert_eq!(lsm_hook_result(Ok(LSM_ALLOW)), LSM_ALLOW);
        assert_eq!(lsm_hook_result(Ok(LSM_DENY)), LSM_DENY);
    }
}
