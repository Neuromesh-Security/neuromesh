//! Path-prefix deny list: bootstrap defaults, equivalence helpers, BPF array writer.
//!
//! Phase 1 replaces the LSM's hardcoded `starts_with` against `/tmp/`,
//! `/dev/shm/`, `/var/tmp/` with a lookup against the `PATH_DENY_LIST` BPF
//! array. This module owns the userspace side of that contract: bootstrap
//! population (fail-closed), sync apply, and tests proving map-backed matching
//! is identical to the legacy hardcoded compare.

use anyhow::{bail, Context, Result};
use aya::maps::{Array, MapData};
use neuromesh_common::{
    PathDenyEntry, BOOTSTRAP_PATH_DENY_PREFIXES, PATH_DENY_KEY_BYTES, PATH_DENY_MAX_ENTRIES,
};
use std::time::{Duration, Instant};

/// How long without a successful sync before policy is marked STALE.
pub const POLICY_STALE_AFTER: Duration = Duration::from_secs(5 * 60);

/// Default sync cadence for fetching `/v1/policy-bundle`.
pub const POLICY_SYNC_INTERVAL: Duration = Duration::from_secs(30);

/// Handles for the two BPF arrays that back the deny list.
pub struct PathDenyMaps {
    pub list: Array<MapData, PathDenyEntry>,
    pub count: Array<MapData, u32>,
}

/// Tracks last successful sync for STALE signalling.
#[derive(Debug, Clone)]
pub struct PolicySyncState {
    pub last_success: Instant,
    pub last_version: String,
    pub stale: bool,
}

impl PolicySyncState {
    pub fn fresh(version: impl Into<String>) -> Self {
        Self {
            last_success: Instant::now(),
            last_version: version.into(),
            stale: false,
        }
    }

    pub fn mark_success(&mut self, version: impl Into<String>) {
        self.last_success = Instant::now();
        self.last_version = version.into();
        self.stale = false;
    }

    pub fn refresh_stale_flag(&mut self) {
        self.stale = self.last_success.elapsed() > POLICY_STALE_AFTER;
    }
}

/// Legacy hardcoded deny logic — frozen for equivalence tests.
pub fn legacy_hardcoded_is_blacklisted(path: &[u8]) -> bool {
    path_starts_with(path, b"/tmp/")
        || path_starts_with(path, b"/dev/shm/")
        || path_starts_with(path, b"/var/tmp/")
}

/// Map-backed deny logic: deny iff any active entry matches (same `starts_with`
/// semantics as the LSM loop over `PATH_DENY_LIST`).
pub fn map_backed_is_blacklisted(path: &[u8], entries: &[PathDenyEntry]) -> bool {
    entries.iter().any(|entry| entry.matches(path))
}

fn path_starts_with(path: &[u8], prefix: &[u8]) -> bool {
    if path.len() < prefix.len() {
        return false;
    }
    path.iter()
        .zip(prefix.iter())
        .all(|(left, right)| left == right)
}

/// Build the bootstrap entry set from [`BOOTSTRAP_PATH_DENY_PREFIXES`].
pub fn bootstrap_entries() -> Result<Vec<PathDenyEntry>> {
    let mut out = Vec::with_capacity(BOOTSTRAP_PATH_DENY_PREFIXES.len());
    for prefix in BOOTSTRAP_PATH_DENY_PREFIXES {
        let entry = PathDenyEntry::from_prefix(prefix).with_context(|| {
            format!(
                "bootstrap deny prefix {:?} is empty or longer than {} bytes",
                prefix, PATH_DENY_KEY_BYTES
            )
        })?;
        out.push(entry);
    }
    if out.is_empty() {
        bail!("bootstrap deny list must not be empty (fail-closed)");
    }
    if out.len() as u32 > PATH_DENY_MAX_ENTRIES {
        bail!(
            "bootstrap deny list has {} entries; max is {}",
            out.len(),
            PATH_DENY_MAX_ENTRIES
        );
    }
    Ok(out)
}

/// Write `entries` into the BPF arrays. Never leaves `count == 0` if `entries`
/// is non-empty. Order: write slots, then set count (avoids a transient empty
/// window that would fail-open).
pub fn apply_deny_entries(maps: &mut PathDenyMaps, entries: &[PathDenyEntry]) -> Result<()> {
    if entries.is_empty() {
        bail!("refusing to apply empty deny list (would fail-open)");
    }
    if entries.len() as u32 > PATH_DENY_MAX_ENTRIES {
        bail!(
            "deny list has {} entries; max is {}",
            entries.len(),
            PATH_DENY_MAX_ENTRIES
        );
    }

    for (i, entry) in entries.iter().enumerate() {
        if entry.len == 0 || entry.len as usize > PATH_DENY_KEY_BYTES {
            bail!("deny entry {i} has invalid len {}", entry.len);
        }
        maps.list
            .set(i as u32, entry, 0)
            .with_context(|| format!("failed to write PATH_DENY_LIST[{i}]"))?;
    }

    let count = entries.len() as u32;
    maps.count
        .set(0, count, 0)
        .context("failed to write PATH_DENY_COUNT")?;

    // Clear unused slots so a later shrink cannot leave stale matches if count
    // is ever mis-read (defence in depth).
    let empty = PathDenyEntry::default();
    for i in count..PATH_DENY_MAX_ENTRIES {
        maps.list
            .set(i, empty, 0)
            .with_context(|| format!("failed to clear PATH_DENY_LIST[{i}]"))?;
    }

    Ok(())
}

/// Populate the maps with the fail-closed bootstrap prefixes. Must run before
/// the LSM program is attached.
pub fn bootstrap_deny_maps(maps: &mut PathDenyMaps) -> Result<PolicySyncState> {
    let entries = bootstrap_entries()?;
    apply_deny_entries(maps, &entries)?;
    Ok(PolicySyncState::fresh("bootstrap"))
}

/// Parse a policy-bundle JSON body into deny entries.
pub fn entries_from_bundle_json(body: &str) -> Result<(String, Vec<PathDenyEntry>)> {
    #[derive(serde::Deserialize)]
    struct BundleDoc {
        schema_version: u32,
        version: String,
        deny_path_prefixes: Vec<String>,
    }

    let doc: BundleDoc = serde_json::from_str(body).context("malformed policy-bundle JSON")?;
    if doc.schema_version != 1 {
        bail!(
            "unsupported policy-bundle schema_version {} (expected 1)",
            doc.schema_version
        );
    }
    if doc.version.is_empty() {
        bail!("policy-bundle missing version");
    }
    if doc.deny_path_prefixes.is_empty() {
        bail!("policy-bundle deny_path_prefixes is empty (refusing fail-open)");
    }

    let mut entries = Vec::with_capacity(doc.deny_path_prefixes.len());
    for prefix in &doc.deny_path_prefixes {
        let bytes = prefix.as_bytes();
        let entry = PathDenyEntry::from_prefix(bytes).with_context(|| {
            format!("bundle prefix {prefix:?} is empty or longer than {PATH_DENY_KEY_BYTES} bytes")
        })?;
        entries.push(entry);
    }
    Ok((doc.version, entries))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(path: &str) -> [u8; PATH_DENY_KEY_BYTES] {
        let mut buf = [0u8; PATH_DENY_KEY_BYTES];
        let n = path.len().min(PATH_DENY_KEY_BYTES);
        buf[..n].copy_from_slice(&path.as_bytes()[..n]);
        buf
    }

    #[test]
    fn bootstrap_entries_match_historical_hardcoded_set() {
        let entries = bootstrap_entries().unwrap();
        assert_eq!(entries.len(), 3);
        assert!(entries[0].matches(b"/tmp/x"));
        assert!(entries[1].matches(b"/dev/shm/x"));
        assert!(entries[2].matches(b"/var/tmp/x"));
    }

    #[test]
    fn equivalence_legacy_vs_map_backed_on_edge_cases() {
        let entries = bootstrap_entries().unwrap();
        let cases = [
            "/tmp/payload",
            "/tmp/",
            "/tmp",
            "/tmp2/x",
            "/dev/shm/evil",
            "/dev/shm",
            "/var/tmp/x",
            "/var/tmp",
            "/bin/ls",
            "/usr/bin/bash",
            "",
            "/",
            "/tm",
            "/var/tmp/aaaaaaaa", // longer than 16-byte window when truncated
        ];

        for case in cases {
            let path = window(case);
            let legacy = legacy_hardcoded_is_blacklisted(&path);
            let mapped = map_backed_is_blacklisted(&path, &entries);
            assert_eq!(
                legacy, mapped,
                "mismatch for path window of {case:?}: legacy={legacy} map={mapped}"
            );
        }
    }

    #[test]
    fn exact_prefix_longer_path_and_near_miss() {
        let entries = bootstrap_entries().unwrap();
        assert!(map_backed_is_blacklisted(&window("/tmp/"), &entries));
        assert!(map_backed_is_blacklisted(&window("/tmp/a"), &entries));
        assert!(!map_backed_is_blacklisted(&window("/tmp2/"), &entries));
        assert!(!map_backed_is_blacklisted(&window("/TMP/x"), &entries)); // case-sensitive
    }

    #[test]
    fn empty_path_and_boundary_length_window() {
        let entries = bootstrap_entries().unwrap();
        assert!(!map_backed_is_blacklisted(&window(""), &entries));
        // 16-byte window exactly filled with a denied prefix + tail
        let path = window("/var/tmp/1234567"); // 16 chars
        assert_eq!(path.len(), 16);
        assert!(legacy_hardcoded_is_blacklisted(&path));
        assert!(map_backed_is_blacklisted(&path, &entries));
    }

    #[test]
    fn refuse_empty_bundle_prefixes() {
        let err = entries_from_bundle_json(
            r#"{"schema_version":1,"version":"sha256:abc","deny_path_prefixes":[]}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn parse_valid_bundle() {
        let (version, entries) = entries_from_bundle_json(
            r#"{"schema_version":1,"version":"sha256:dead","deny_path_prefixes":["/tmp/","/dev/shm/","/var/tmp/"]}"#,
        )
        .unwrap();
        assert_eq!(version, "sha256:dead");
        assert_eq!(entries.len(), 3);
        assert!(map_backed_is_blacklisted(&window("/tmp/x"), &entries));
    }

    #[test]
    fn sync_state_becomes_stale_after_ttl() {
        let mut state = PolicySyncState {
            last_success: Instant::now() - POLICY_STALE_AFTER - Duration::from_secs(1),
            last_version: "bootstrap".into(),
            stale: false,
        };
        state.refresh_stale_flag();
        assert!(state.stale);
        state.mark_success("sha256:new");
        assert!(!state.stale);
    }
}
