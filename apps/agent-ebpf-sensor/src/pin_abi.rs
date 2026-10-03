//! Pinned BPF map ABI validation and legacy migration (Issue #208 / ADR-002).
//!
//! aya 0.14 `create_pinned_by_name` reuses an existing pin FD without checking
//! `value_size` / `key_size`. A pre-#134 `PATH_DENY_LIST` (value_size 20) makes
//! the post-#134 verifier reject `nm_lsm_bprm` with EACCES while the old LSM
//! link keeps enforcing — fail-safe but unavailable.
//!
//! This module runs **before** `EbpfLoader::load`, migrates the known 16→32
//! layout without dropping the live LSM attach, and refuses unknown layouts.

use anyhow::{bail, Context, Result};
use neuromesh_common::{
    LegacyPathDenyEntry, PathDenyEntry, PinnedMapAbi, BOOTSTRAP_PATH_DENY_PREFIXES,
    PATH_DENY_COUNT_MAP, PATH_DENY_ENTRY_SIZE_LEGACY, PATH_DENY_KEY_BYTES,
    PATH_DENY_KEY_BYTES_LEGACY, PATH_DENY_LIST_MAP, PATH_DENY_MAX_ENTRIES, PINNED_MAP_ABI,
    PROCESS_EVENTS_MAP, RATE_LIMIT_BUCKET_MAP,
};
use std::fs;
use std::path::{Path, PathBuf};

/// bpffs subdirectory prefix for staged legacy pins (no `.` — kernel `-EPERM`).
pub const LEGACY_ABI_DIR_PREFIX: &str = "legacy_abi_";

/// Observed map create attrs from a live pin (or a test double).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedMapInfo {
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

impl ObservedMapInfo {
    pub fn matches_expected(&self, expected: &PinnedMapAbi) -> bool {
        self.map_type == expected.map_type
            && self.key_size == expected.key_size
            && self.value_size == expected.value_size
            && self.max_entries == expected.max_entries
    }

    /// Known migratable layout: pre-#134 PATH_DENY_LIST (u32 + [u8;16]).
    pub fn is_legacy_path_deny_list(&self) -> bool {
        self.map_type == neuromesh_common::BPF_MAP_TYPE_ARRAY
            && self.key_size == 4
            && self.value_size == PATH_DENY_ENTRY_SIZE_LEGACY as u32
            && self.max_entries == PATH_DENY_MAX_ENTRIES
    }
}

/// Classifier + migration planning result (before load).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinAbiState {
    /// No enforcement map pins at canonical names.
    Cold,
    /// All present pinned maps match [`PINNED_MAP_ABI`].
    Compatible,
    /// Pre-#134 deny-list pins present; migrate before load.
    LegacyMigratable,
    /// `legacy_abi_*` staging dir present — resume interrupted migration.
    MigrationInProgress { legacy_dir: PathBuf },
    /// Unknown / unsupported layout — refuse (F4).
    Incompatible { map: String, detail: String },
}

/// Seed source after a successful prepare-for-load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenySeedOverride {
    /// Fresh maps; write bootstrap prefixes.
    Bootstrap,
    /// Compatible resume — keep whatever is already in the new/existing maps.
    ResumePinned,
    /// Write these widened (or bootstrap fallback) entries after load.
    MigratedEntries {
        entries: Vec<PathDenyEntry>,
        from_legacy: bool,
    },
}

/// Outcome recorded for metrics / logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationResult {
    Compatible,
    Migrated,
    ResumedMigration,
    BootstrapFallback,
    ProcessMapRecreated,
}

/// I/O surface for unit tests (tempdirs + fake map info).
pub trait PinAbiIo {
    fn exists(&self, path: &Path) -> bool;
    fn is_dir(&self, path: &Path) -> bool;
    fn create_dir_all(&self, path: &Path) -> Result<()>;
    fn rename(&self, from: &Path, to: &Path) -> Result<()>;
    fn remove_file(&self, path: &Path) -> Result<()>;
    fn remove_dir_all(&self, path: &Path) -> Result<()>;
    fn read_dir_names(&self, path: &Path) -> Result<Vec<String>>;
    fn map_info(&self, pin_path: &Path) -> Result<ObservedMapInfo>;
    /// Read legacy PATH_DENY_LIST + COUNT from a pin directory (canonical or legacy_abi_*).
    fn read_legacy_deny_entries(&self, map_dir: &Path) -> Result<Vec<PathDenyEntry>>;
}

/// Production I/O backed by the real filesystem + aya `MapInfo` / map lookups.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealPinAbiIo;

impl PinAbiIo for RealPinAbiIo {
    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn is_dir(&self, path: &Path) -> bool {
        path.is_dir()
    }

    fn create_dir_all(&self, path: &Path) -> Result<()> {
        fs::create_dir_all(path).with_context(|| format!("create_dir_all {}", path.display()))
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        fs::rename(from, to)
            .with_context(|| format!("rename {} → {}", from.display(), to.display()))
    }

    fn remove_file(&self, path: &Path) -> Result<()> {
        fs::remove_file(path).with_context(|| format!("remove_file {}", path.display()))
    }

    fn remove_dir_all(&self, path: &Path) -> Result<()> {
        fs::remove_dir_all(path).with_context(|| format!("remove_dir_all {}", path.display()))
    }

    fn read_dir_names(&self, path: &Path) -> Result<Vec<String>> {
        if !path.is_dir() {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        for entry in fs::read_dir(path).with_context(|| format!("read_dir {}", path.display()))? {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
        names.sort();
        Ok(names)
    }

    fn map_info(&self, pin_path: &Path) -> Result<ObservedMapInfo> {
        #[cfg(target_os = "linux")]
        {
            use aya::maps::MapInfo;
            let info = MapInfo::from_pin(pin_path)
                .with_context(|| format!("MapInfo::from_pin({}) failed", pin_path.display()))?;
            let raw_type = info
                .map_type()
                .map(|t| t as isize as u32)
                .with_context(|| format!("decode map type for {}", pin_path.display()))?;
            Ok(ObservedMapInfo {
                map_type: raw_type,
                key_size: info.key_size(),
                value_size: info.value_size(),
                max_entries: info.max_entries(),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            bail!(
                "MapInfo::from_pin unavailable on this host ({})",
                pin_path.display()
            );
        }
    }

    fn read_legacy_deny_entries(&self, map_dir: &Path) -> Result<Vec<PathDenyEntry>> {
        #[cfg(target_os = "linux")]
        {
            use aya::maps::{Array, Map, MapData};
            let list_path = map_dir.join(PATH_DENY_LIST_MAP);
            let count_path = map_dir.join(PATH_DENY_COUNT_MAP);
            // aya 0.14: Array::try_from takes `Map`, not bare `MapData`.
            let list_map = Map::from_map_data(
                MapData::from_pin(&list_path)
                    .with_context(|| format!("open legacy {}", list_path.display()))?,
            )
            .with_context(|| format!("classify legacy map {}", list_path.display()))?;
            let count_map = Map::from_map_data(
                MapData::from_pin(&count_path)
                    .with_context(|| format!("open legacy {}", count_path.display()))?,
            )
            .with_context(|| format!("classify legacy map {}", count_path.display()))?;
            let list: Array<_, LegacyPathDenyEntry> = Array::try_from(list_map)
                .context("legacy PATH_DENY_LIST is not Array<LegacyPathDenyEntry>")?;
            let count: Array<_, u32> =
                Array::try_from(count_map).context("legacy PATH_DENY_COUNT is not Array<u32>")?;
            let active = count.get(&0, 0).context("read legacy PATH_DENY_COUNT[0]")?;
            if active == 0 {
                bail!("legacy PATH_DENY_COUNT[0] == 0 — refuse empty deny list (fail-open)");
            }
            let n = active.min(PATH_DENY_MAX_ENTRIES);
            let mut out = Vec::with_capacity(n as usize);
            for i in 0..n {
                let legacy = list
                    .get(&i, 0)
                    .with_context(|| format!("read legacy PATH_DENY_LIST[{i}]"))?;
                let wide = legacy.widen().with_context(|| {
                    format!("legacy PATH_DENY_LIST[{i}] has invalid len={}", legacy.len)
                })?;
                out.push(wide);
            }
            if out.is_empty() {
                bail!("legacy deny list produced zero widened entries");
            }
            Ok(out)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = map_dir;
            bail!("legacy deny map reads require Linux + bpffs");
        }
    }
}

/// List `legacy_abi_*` directories under `pin_root`.
pub fn list_legacy_abi_dirs<I: PinAbiIo>(io: &I, pin_root: &Path) -> Result<Vec<PathBuf>> {
    let mut dirs = Vec::new();
    for name in io.read_dir_names(pin_root)? {
        if name.starts_with(LEGACY_ABI_DIR_PREFIX) && !name.contains('.') {
            let p = pin_root.join(&name);
            if io.is_dir(&p) {
                dirs.push(p);
            }
        }
    }
    dirs.sort();
    Ok(dirs)
}

fn expected_abi(name: &str) -> Option<&'static PinnedMapAbi> {
    PINNED_MAP_ABI.iter().find(|m| m.name == name)
}

/// Classify pin directory ABI state (read-only).
pub fn assess_pin_abi<I: PinAbiIo>(io: &I, pin_root: &Path) -> Result<PinAbiState> {
    let legacy_dirs = list_legacy_abi_dirs(io, pin_root)?;
    let list_path = pin_root.join(PATH_DENY_LIST_MAP);
    let count_path = pin_root.join(PATH_DENY_COUNT_MAP);
    let list_exists = io.exists(&list_path);
    let count_exists = io.exists(&count_path);

    if !legacy_dirs.is_empty() && !(list_exists && count_exists) {
        return Ok(PinAbiState::MigrationInProgress {
            legacy_dir: legacy_dirs[0].clone(),
        });
    }

    if !list_exists && !count_exists {
        // Process-map pins alone do not make an enforcement cold start into Compatible.
        return Ok(PinAbiState::Cold);
    }

    if list_exists != count_exists {
        return Ok(PinAbiState::Incompatible {
            map: if list_exists {
                PATH_DENY_LIST_MAP
            } else {
                PATH_DENY_COUNT_MAP
            }
            .to_string(),
            detail: "PATH_DENY_LIST / PATH_DENY_COUNT pin pair incomplete".into(),
        });
    }

    let list_info = io.map_info(&list_path)?;
    let count_info = io.map_info(&count_path)?;

    let list_exp = expected_abi(PATH_DENY_LIST_MAP).expect("table");
    let count_exp = expected_abi(PATH_DENY_COUNT_MAP).expect("table");

    if list_info.is_legacy_path_deny_list() && count_info.matches_expected(count_exp) {
        return Ok(PinAbiState::LegacyMigratable);
    }

    if !list_info.matches_expected(list_exp) {
        return Ok(PinAbiState::Incompatible {
            map: PATH_DENY_LIST_MAP.into(),
            detail: format!(
                "pinned type={} key={} value={} max={} — expected type={} key={} value={} max={} \
                 (ENFORCEMENT_PIN_ABI_VERSION={})",
                list_info.map_type,
                list_info.key_size,
                list_info.value_size,
                list_info.max_entries,
                list_exp.map_type,
                list_exp.key_size,
                list_exp.value_size,
                list_exp.max_entries,
                neuromesh_common::ENFORCEMENT_PIN_ABI_VERSION,
            ),
        });
    }
    if !count_info.matches_expected(count_exp) {
        return Ok(PinAbiState::Incompatible {
            map: PATH_DENY_COUNT_MAP.into(),
            detail: format!(
                "pinned value_size={} max={} — expected value_size={} max={}",
                count_info.value_size,
                count_info.max_entries,
                count_exp.value_size,
                count_exp.max_entries
            ),
        });
    }

    // Compatible enforcement maps. Still validate process maps if present.
    for name in [PROCESS_EVENTS_MAP, RATE_LIMIT_BUCKET_MAP] {
        let path = pin_root.join(name);
        if !io.exists(&path) {
            continue;
        }
        let info = io.map_info(&path)?;
        let exp = expected_abi(name).expect("table");
        if !info.matches_expected(exp) {
            // Process maps: recreate is allowed — signal via a dedicated path
            // in prepare (not Incompatible for enforcement).
            tracing::warn!(
                target: "neuromesh::pin_abi",
                map = name,
                pinned_value_size = info.value_size,
                expected_value_size = exp.value_size,
                "process/visibility map ABI mismatch — will recreate (non-enforcement state)"
            );
        }
    }

    if !legacy_dirs.is_empty() {
        // Compatible canonical maps + leftover staging → treat as Compatible;
        // prepare will clean staging after attach.
        return Ok(PinAbiState::Compatible);
    }

    Ok(PinAbiState::Compatible)
}

fn next_legacy_dir_name<I: PinAbiIo>(io: &I, pin_root: &Path) -> Result<String> {
    let existing = list_legacy_abi_dirs(io, pin_root)?;
    let mut n = 0u32;
    loop {
        let name = format!("{LEGACY_ABI_DIR_PREFIX}{n}");
        let path = pin_root.join(&name);
        if !existing.iter().any(|p| p == &path) && !io.exists(&path) {
            return Ok(name);
        }
        n = n.saturating_add(1);
        if n > 1024 {
            bail!(
                "exhausted legacy_abi_* namespace under {}",
                pin_root.display()
            );
        }
    }
}

/// Move canonical deny-map pins into a new `legacy_abi_<n>/` directory.
/// LSM link pin is intentionally left in place (F2).
pub fn stage_legacy_deny_pins<I: PinAbiIo>(io: &I, pin_root: &Path) -> Result<PathBuf> {
    let name = next_legacy_dir_name(io, pin_root)?;
    let dest = pin_root.join(&name);
    io.create_dir_all(&dest)?;
    let list = pin_root.join(PATH_DENY_LIST_MAP);
    let count = pin_root.join(PATH_DENY_COUNT_MAP);
    if !io.exists(&list) || !io.exists(&count) {
        bail!("stage_legacy_deny_pins: canonical deny pins missing");
    }
    io.rename(&list, &dest.join(PATH_DENY_LIST_MAP))?;
    io.rename(&count, &dest.join(PATH_DENY_COUNT_MAP))?;
    tracing::warn!(
        target: "neuromesh::pin_abi",
        legacy_dir = %dest.display(),
        "staged legacy PATH_DENY_* pins for ABI migration; LSM link pin retained (no enforcement gap)"
    );
    Ok(dest)
}

/// Recreate process maps that do not match the expected ABI (non-enforcement).
pub fn recreate_mismatched_process_maps<I: PinAbiIo>(
    io: &I,
    pin_root: &Path,
) -> Result<Vec<&'static str>> {
    let mut removed = Vec::new();
    for name in [PROCESS_EVENTS_MAP, RATE_LIMIT_BUCKET_MAP] {
        let path = pin_root.join(name);
        if !io.exists(&path) {
            continue;
        }
        let info = io.map_info(&path)?;
        let exp = expected_abi(name).expect("table");
        if info.matches_expected(exp) {
            continue;
        }
        // Stage aside rather than unlink when possible (crash-safe audit trail).
        let staging = pin_root.join(format!("{LEGACY_ABI_DIR_PREFIX}proc_{name}"));
        // proc staging is a file rename target directory
        let _ = io.remove_dir_all(&staging);
        io.create_dir_all(&staging)?;
        io.rename(&path, &staging.join(name))?;
        tracing::warn!(
            target: "neuromesh::pin_abi",
            map = name,
            staging = %staging.display(),
            "removed mismatched process map pin (ringbuf/rate-limit only — not enforcement)"
        );
        removed.push(name);
    }
    Ok(removed)
}

fn bootstrap_entries_fallback() -> Result<Vec<PathDenyEntry>> {
    let mut out = Vec::with_capacity(BOOTSTRAP_PATH_DENY_PREFIXES.len());
    for prefix in BOOTSTRAP_PATH_DENY_PREFIXES {
        let entry = PathDenyEntry::from_prefix(prefix).with_context(|| {
            format!(
                "bootstrap prefix {prefix:?} invalid for PATH_DENY_KEY_BYTES={PATH_DENY_KEY_BYTES}"
            )
        })?;
        out.push(entry);
    }
    if out.is_empty() {
        bail!("bootstrap deny list empty");
    }
    Ok(out)
}

/// Prepare pin root for load: migrate/stage as needed; return seed override.
pub fn prepare_pin_root_for_load<I: PinAbiIo>(
    io: &I,
    pin_root: &Path,
) -> Result<(DenySeedOverride, Vec<MigrationResult>)> {
    let mut results = Vec::new();
    let state = assess_pin_abi(io, pin_root)?;

    match state {
        PinAbiState::Incompatible { map, detail } => {
            bail!(
                "pinned BPF map ABI incompatible for {map}: {detail} — refusing to start \
                 (fail-closed; see docs/runbooks/agent-pin-recovery.md). Do NOT delete pins \
                 on production nodes without understanding the enforcement gap."
            );
        }
        PinAbiState::Cold => {
            let proc = recreate_mismatched_process_maps(io, pin_root)?;
            if !proc.is_empty() {
                results.push(MigrationResult::ProcessMapRecreated);
            }
            Ok((DenySeedOverride::Bootstrap, results))
        }
        PinAbiState::Compatible => {
            let proc = recreate_mismatched_process_maps(io, pin_root)?;
            if !proc.is_empty() {
                results.push(MigrationResult::ProcessMapRecreated);
            }
            results.push(MigrationResult::Compatible);
            Ok((DenySeedOverride::ResumePinned, results))
        }
        PinAbiState::LegacyMigratable => {
            let entries = match io.read_legacy_deny_entries(pin_root) {
                Ok(e) => e,
                Err(e) => {
                    tracing::error!(
                        target: "neuromesh::pin_abi",
                        error = %e,
                        "failed to read legacy deny pins — will stage pins and seed bootstrap (STALE until PE sync)"
                    );
                    let _legacy = stage_legacy_deny_pins(io, pin_root)?;
                    let proc = recreate_mismatched_process_maps(io, pin_root)?;
                    if !proc.is_empty() {
                        results.push(MigrationResult::ProcessMapRecreated);
                    }
                    results.push(MigrationResult::BootstrapFallback);
                    return Ok((
                        DenySeedOverride::MigratedEntries {
                            entries: bootstrap_entries_fallback()?,
                            from_legacy: false,
                        },
                        results,
                    ));
                }
            };
            let _legacy = stage_legacy_deny_pins(io, pin_root)?;
            let proc = recreate_mismatched_process_maps(io, pin_root)?;
            if !proc.is_empty() {
                results.push(MigrationResult::ProcessMapRecreated);
            }
            results.push(MigrationResult::Migrated);
            Ok((
                DenySeedOverride::MigratedEntries {
                    entries,
                    from_legacy: true,
                },
                results,
            ))
        }
        PinAbiState::MigrationInProgress { legacy_dir } => {
            let entries = match io.read_legacy_deny_entries(&legacy_dir) {
                Ok(e) => {
                    results.push(MigrationResult::ResumedMigration);
                    DenySeedOverride::MigratedEntries {
                        entries: e,
                        from_legacy: true,
                    }
                }
                Err(e) => {
                    tracing::error!(
                        target: "neuromesh::pin_abi",
                        error = %e,
                        legacy_dir = %legacy_dir.display(),
                        "MigrationInProgress but legacy entries unreadable — bootstrap fallback"
                    );
                    results.push(MigrationResult::BootstrapFallback);
                    DenySeedOverride::MigratedEntries {
                        entries: bootstrap_entries_fallback()?,
                        from_legacy: false,
                    }
                }
            };
            // Ensure canonical names are free.
            for name in [PATH_DENY_LIST_MAP, PATH_DENY_COUNT_MAP] {
                let p = pin_root.join(name);
                if io.exists(&p) {
                    // Partial load left canonical pins — remove so load creates fresh ABI.
                    io.remove_file(&p)?;
                }
            }
            let proc = recreate_mismatched_process_maps(io, pin_root)?;
            if !proc.is_empty() {
                results.push(MigrationResult::ProcessMapRecreated);
            }
            Ok((entries, results))
        }
    }
}

/// Delete `legacy_abi_*` staging dirs after the new LSM link is live.
pub fn cleanup_legacy_abi_dirs<I: PinAbiIo>(io: &I, pin_root: &Path) -> Result<()> {
    for dir in list_legacy_abi_dirs(io, pin_root)? {
        // Also clean proc_* staging dirs that share the prefix.
        io.remove_dir_all(&dir)?;
        tracing::info!(
            target: "neuromesh::pin_abi",
            legacy_dir = %dir.display(),
            "removed legacy ABI staging directory after successful LSM handoff"
        );
    }
    Ok(())
}

/// Widen helper exposed for property tests.
pub fn widen_legacy_entry(legacy: LegacyPathDenyEntry) -> Option<PathDenyEntry> {
    legacy.widen()
}

/// Property: widened matcher ≡ legacy starts_with on significant bytes.
pub fn legacy_match_equivalent(path: &[u8], legacy: &LegacyPathDenyEntry) -> bool {
    let len = legacy.len as usize;
    if len == 0 || len > PATH_DENY_KEY_BYTES_LEGACY {
        return false;
    }
    let legacy_hit = path.len() >= len && path[..len] == legacy.bytes[..len];
    match legacy.widen() {
        Some(wide) => legacy_hit == wide.matches(path),
        None => !legacy_hit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neuromesh_common::PATH_DENY_ENTRY_SIZE;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeIo {
        files: Mutex<HashMap<PathBuf, Vec<u8>>>,
        dirs: Mutex<Vec<PathBuf>>,
        info: Mutex<HashMap<PathBuf, ObservedMapInfo>>,
        legacy_entries: Mutex<HashMap<PathBuf, Vec<PathDenyEntry>>>,
    }

    impl FakeIo {
        fn touch_dir(&self, p: &Path) {
            self.dirs.lock().unwrap().push(p.to_path_buf());
        }
        fn touch_file(&self, p: &Path) {
            self.files
                .lock()
                .unwrap()
                .insert(p.to_path_buf(), Vec::new());
        }
        fn set_info(&self, p: &Path, info: ObservedMapInfo) {
            self.touch_file(p);
            self.info.lock().unwrap().insert(p.to_path_buf(), info);
        }
    }

    impl PinAbiIo for FakeIo {
        fn exists(&self, path: &Path) -> bool {
            self.files.lock().unwrap().contains_key(path)
                || self.dirs.lock().unwrap().iter().any(|d| d == path)
        }
        fn is_dir(&self, path: &Path) -> bool {
            self.dirs.lock().unwrap().iter().any(|d| d == path)
        }
        fn create_dir_all(&self, path: &Path) -> Result<()> {
            self.touch_dir(path);
            Ok(())
        }
        fn rename(&self, from: &Path, to: &Path) -> Result<()> {
            let mut files = self.files.lock().unwrap();
            let mut info = self.info.lock().unwrap();
            let bytes = files
                .remove(from)
                .ok_or_else(|| anyhow::anyhow!("missing {}", from.display()))?;
            files.insert(to.to_path_buf(), bytes);
            if let Some(i) = info.remove(from) {
                info.insert(to.to_path_buf(), i);
            }
            Ok(())
        }
        fn remove_file(&self, path: &Path) -> Result<()> {
            self.files.lock().unwrap().remove(path);
            self.info.lock().unwrap().remove(path);
            Ok(())
        }
        fn remove_dir_all(&self, path: &Path) -> Result<()> {
            self.dirs
                .lock()
                .unwrap()
                .retain(|d| d != path && !d.starts_with(path));
            let mut files = self.files.lock().unwrap();
            files.retain(|p, _| !p.starts_with(path));
            let mut info = self.info.lock().unwrap();
            info.retain(|p, _| !p.starts_with(path));
            Ok(())
        }
        fn read_dir_names(&self, path: &Path) -> Result<Vec<String>> {
            let mut names = Vec::new();
            for d in self.dirs.lock().unwrap().iter() {
                if d.parent() == Some(path) {
                    if let Some(n) = d.file_name().and_then(|s| s.to_str()) {
                        names.push(n.to_string());
                    }
                }
            }
            for f in self.files.lock().unwrap().keys() {
                if f.parent() == Some(path) {
                    if let Some(n) = f.file_name().and_then(|s| s.to_str()) {
                        names.push(n.to_string());
                    }
                }
            }
            names.sort();
            names.dedup();
            Ok(names)
        }
        fn map_info(&self, pin_path: &Path) -> Result<ObservedMapInfo> {
            self.info
                .lock()
                .unwrap()
                .get(pin_path)
                .copied()
                .ok_or_else(|| anyhow::anyhow!("no info for {}", pin_path.display()))
        }
        fn read_legacy_deny_entries(&self, map_dir: &Path) -> Result<Vec<PathDenyEntry>> {
            self.legacy_entries
                .lock()
                .unwrap()
                .get(map_dir)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no legacy entries for {}", map_dir.display()))
        }
    }

    fn current_list_info() -> ObservedMapInfo {
        ObservedMapInfo {
            map_type: neuromesh_common::BPF_MAP_TYPE_ARRAY,
            key_size: 4,
            value_size: PATH_DENY_ENTRY_SIZE as u32,
            max_entries: PATH_DENY_MAX_ENTRIES,
        }
    }

    fn legacy_list_info() -> ObservedMapInfo {
        ObservedMapInfo {
            map_type: neuromesh_common::BPF_MAP_TYPE_ARRAY,
            key_size: 4,
            value_size: PATH_DENY_ENTRY_SIZE_LEGACY as u32,
            max_entries: PATH_DENY_MAX_ENTRIES,
        }
    }

    fn count_info() -> ObservedMapInfo {
        ObservedMapInfo {
            map_type: neuromesh_common::BPF_MAP_TYPE_ARRAY,
            key_size: 4,
            value_size: 4,
            max_entries: 1,
        }
    }

    #[test]
    fn classify_cold() {
        let io = FakeIo::default();
        let root = PathBuf::from("/pins");
        io.touch_dir(&root);
        assert_eq!(assess_pin_abi(&io, &root).unwrap(), PinAbiState::Cold);
    }

    #[test]
    fn classify_compatible() {
        let io = FakeIo::default();
        let root = PathBuf::from("/pins");
        io.touch_dir(&root);
        io.set_info(&root.join(PATH_DENY_LIST_MAP), current_list_info());
        io.set_info(&root.join(PATH_DENY_COUNT_MAP), count_info());
        assert_eq!(assess_pin_abi(&io, &root).unwrap(), PinAbiState::Compatible);
    }

    #[test]
    fn classify_legacy_migratable_incident_208() {
        let io = FakeIo::default();
        let root = PathBuf::from("/pins");
        io.touch_dir(&root);
        io.set_info(&root.join(PATH_DENY_LIST_MAP), legacy_list_info());
        io.set_info(&root.join(PATH_DENY_COUNT_MAP), count_info());
        assert_eq!(
            assess_pin_abi(&io, &root).unwrap(),
            PinAbiState::LegacyMigratable
        );
    }

    #[test]
    fn classify_incompatible_unknown_value_size() {
        let io = FakeIo::default();
        let root = PathBuf::from("/pins");
        io.touch_dir(&root);
        io.set_info(
            &root.join(PATH_DENY_LIST_MAP),
            ObservedMapInfo {
                map_type: neuromesh_common::BPF_MAP_TYPE_ARRAY,
                key_size: 4,
                value_size: 99,
                max_entries: PATH_DENY_MAX_ENTRIES,
            },
        );
        io.set_info(&root.join(PATH_DENY_COUNT_MAP), count_info());
        match assess_pin_abi(&io, &root).unwrap() {
            PinAbiState::Incompatible { map, .. } => assert_eq!(map, PATH_DENY_LIST_MAP),
            other => panic!("expected Incompatible, got {other:?}"),
        }
    }

    #[test]
    fn classify_migration_in_progress() {
        let io = FakeIo::default();
        let root = PathBuf::from("/pins");
        let legacy = root.join("legacy_abi_0");
        io.touch_dir(&root);
        io.touch_dir(&legacy);
        io.touch_file(&legacy.join(PATH_DENY_LIST_MAP));
        io.touch_file(&legacy.join(PATH_DENY_COUNT_MAP));
        match assess_pin_abi(&io, &root).unwrap() {
            PinAbiState::MigrationInProgress { legacy_dir } => {
                assert_eq!(legacy_dir, legacy);
            }
            other => panic!("expected MigrationInProgress, got {other:?}"),
        }
    }

    #[test]
    fn prepare_migrates_and_frees_canonical_names() {
        let io = FakeIo::default();
        let root = PathBuf::from("/pins");
        io.touch_dir(&root);
        io.set_info(&root.join(PATH_DENY_LIST_MAP), legacy_list_info());
        io.set_info(&root.join(PATH_DENY_COUNT_MAP), count_info());
        let entry = PathDenyEntry::from_prefix(b"/tmp/").unwrap();
        io.legacy_entries
            .lock()
            .unwrap()
            .insert(root.clone(), vec![entry]);

        let (seed, results) = prepare_pin_root_for_load(&io, &root).unwrap();
        assert!(results.contains(&MigrationResult::Migrated));
        assert!(!io.exists(&root.join(PATH_DENY_LIST_MAP)));
        assert!(!io.exists(&root.join(PATH_DENY_COUNT_MAP)));
        assert!(io.exists(&root.join("legacy_abi_0").join(PATH_DENY_LIST_MAP)));
        match seed {
            DenySeedOverride::MigratedEntries {
                entries,
                from_legacy,
            } => {
                assert!(from_legacy);
                assert_eq!(entries.len(), 1);
                assert!(entries[0].matches(b"/tmp/x"));
            }
            other => panic!("unexpected seed {other:?}"),
        }
    }

    #[test]
    fn prepare_refuses_incompatible() {
        let io = FakeIo::default();
        let root = PathBuf::from("/pins");
        io.touch_dir(&root);
        io.set_info(
            &root.join(PATH_DENY_LIST_MAP),
            ObservedMapInfo {
                map_type: neuromesh_common::BPF_MAP_TYPE_ARRAY,
                key_size: 4,
                value_size: 12,
                max_entries: 64,
            },
        );
        io.set_info(&root.join(PATH_DENY_COUNT_MAP), count_info());
        let err = prepare_pin_root_for_load(&io, &root).unwrap_err();
        assert!(err.to_string().contains("incompatible"), "{err}");
    }

    #[test]
    fn prepare_migration_in_progress_idempotent() {
        let io = FakeIo::default();
        let root = PathBuf::from("/pins");
        let legacy = root.join("legacy_abi_0");
        io.touch_dir(&root);
        io.touch_dir(&legacy);
        let entry = PathDenyEntry::from_prefix(b"/opt/neuromesh/staging/").unwrap();
        io.legacy_entries
            .lock()
            .unwrap()
            .insert(legacy.clone(), vec![entry]);
        io.touch_file(&legacy.join(PATH_DENY_LIST_MAP));
        io.touch_file(&legacy.join(PATH_DENY_COUNT_MAP));

        let (seed, results) = prepare_pin_root_for_load(&io, &root).unwrap();
        assert!(results.contains(&MigrationResult::ResumedMigration));
        match &seed {
            DenySeedOverride::MigratedEntries { entries, .. } => {
                assert!(entries[0].matches(b"/opt/neuromesh/staging/x"));
            }
            other => panic!("{other:?}"),
        }
        // Second run converges the same way.
        let (seed2, _) = prepare_pin_root_for_load(&io, &root).unwrap();
        assert_eq!(seed, seed2);
    }

    #[test]
    fn cleanup_removes_legacy_dirs() {
        let io = FakeIo::default();
        let root = PathBuf::from("/pins");
        let legacy = root.join("legacy_abi_0");
        io.touch_dir(&root);
        io.touch_dir(&legacy);
        io.touch_file(&legacy.join(PATH_DENY_LIST_MAP));
        cleanup_legacy_abi_dirs(&io, &root).unwrap();
        assert!(!io.exists(&legacy));
    }

    #[test]
    fn widen_property_matches_legacy_on_random_paths() {
        let mut legacy = LegacyPathDenyEntry {
            len: 9,
            bytes: [0; PATH_DENY_KEY_BYTES_LEGACY],
        };
        legacy.bytes[..9].copy_from_slice(b"/dev/shm/");
        let paths: &[&[u8]] = &[
            b"/dev/shm/x",
            b"/dev/shm/",
            b"/tmp/x",
            b"/dev/shm",
            b"/dev/shm/../no",
        ];
        for p in paths {
            assert!(legacy_match_equivalent(p, &legacy), "mismatch on {p:?}");
        }
    }

    #[test]
    fn incident_208_regression_name() {
        // Named after the incident for git-blame / CI grep discoverability.
        let info = legacy_list_info();
        assert!(info.is_legacy_path_deny_list());
        assert_eq!(info.value_size, 20);
        assert_eq!(PATH_DENY_ENTRY_SIZE, 36);
    }
}
