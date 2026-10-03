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

/// bpffs subdirectory prefix for staged legacy deny pins (no `.` — kernel `-EPERM`).
/// Only `legacy_abi_<digits>` dirs are deny staging; never use this for process maps.
pub const LEGACY_ABI_DIR_PREFIX: &str = "legacy_abi_";

/// bpffs subdirectory prefix for staged mismatched process/visibility maps.
/// Kept separate from [`LEGACY_ABI_DIR_PREFIX`] so process-only staging cannot
/// look like an interrupted deny-list migration (false `MigrationInProgress`).
pub const PROC_ABI_DIR_PREFIX: &str = "proc_abi_";

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
    /// Deny `legacy_abi_<n>` staging present without complete canonical pins —
    /// resume interrupted migration. Process-only `proc_abi_*` is not this state.
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
    fn read_legacy_deny_entries(&self, map_dir: &Path) -> Result<Vec<PathDenyEntry>> {
        self.read_legacy_deny_entries_at(
            &map_dir.join(PATH_DENY_LIST_MAP),
            &map_dir.join(PATH_DENY_COUNT_MAP),
        )
    }

    /// Read legacy deny entries when LIST and COUNT may live in different directories
    /// (crash mid-stage: COUNT already under `legacy_abi_<n>/`, LIST still canonical).
    fn read_legacy_deny_entries_at(
        &self,
        list_path: &Path,
        count_path: &Path,
    ) -> Result<Vec<PathDenyEntry>>;
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

    fn read_legacy_deny_entries_at(
        &self,
        list_path: &Path,
        count_path: &Path,
    ) -> Result<Vec<PathDenyEntry>> {
        #[cfg(target_os = "linux")]
        {
            use aya::maps::{Array, Map, MapData};
            // aya 0.14: Array::try_from takes `Map`, not bare `MapData`.
            let list_map = Map::from_map_data(
                MapData::from_pin(list_path)
                    .with_context(|| format!("open legacy {}", list_path.display()))?,
            )
            .with_context(|| format!("classify legacy map {}", list_path.display()))?;
            let count_map = Map::from_map_data(
                MapData::from_pin(count_path)
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
            let _ = (list_path, count_path);
            bail!("legacy deny map reads require Linux + bpffs");
        }
    }
}

/// Parse numeric suffix of a `legacy_abi_<n>` directory name.
fn legacy_abi_numeric_suffix(name: &str) -> Option<u32> {
    let rest = name.strip_prefix(LEGACY_ABI_DIR_PREFIX)?;
    if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    rest.parse().ok()
}

/// List deny-only `legacy_abi_<digits>` directories under `pin_root`.
///
/// Matches `^legacy_abi_[0-9]+$` only — `legacy_abi_proc_*` and other non-numeric
/// suffixes are intentionally excluded. Sorted by numeric suffix ascending
/// (so `legacy_abi_2` precedes `legacy_abi_10`).
pub fn list_legacy_abi_dirs<I: PinAbiIo>(io: &I, pin_root: &Path) -> Result<Vec<PathBuf>> {
    let mut dirs: Vec<(u32, PathBuf)> = Vec::new();
    for name in io.read_dir_names(pin_root)? {
        let Some(n) = legacy_abi_numeric_suffix(&name) else {
            continue;
        };
        let p = pin_root.join(&name);
        if io.is_dir(&p) {
            dirs.push((n, p));
        }
    }
    dirs.sort_by_key(|(n, _)| *n);
    Ok(dirs.into_iter().map(|(_, p)| p).collect())
}

/// List `proc_abi_*` process-map staging directories under `pin_root`.
pub fn list_proc_abi_dirs<I: PinAbiIo>(io: &I, pin_root: &Path) -> Result<Vec<PathBuf>> {
    let mut dirs = Vec::new();
    for name in io.read_dir_names(pin_root)? {
        if name.starts_with(PROC_ABI_DIR_PREFIX) && !name.contains('.') {
            let p = pin_root.join(&name);
            if io.is_dir(&p) {
                dirs.push(p);
            }
        }
    }
    dirs.sort();
    Ok(dirs)
}

/// Pick the deny staging directory that holds migratable pins.
///
/// Prefers the highest numeric `legacy_abi_<n>` that contains `PATH_DENY_LIST`
/// (and ideally COUNT). Never returns `legacy_dirs[0]` by string sort — that
/// would pick `legacy_abi_10` over `legacy_abi_2` incorrectly when only the
/// latter holds data (or the reverse when both exist and we need the latest).
pub fn select_deny_legacy_dir<I: PinAbiIo>(io: &I, pin_root: &Path) -> Result<Option<PathBuf>> {
    let dirs = list_legacy_abi_dirs(io, pin_root)?;
    let mut best: Option<(u32, PathBuf)> = None;
    for dir in dirs {
        let name = dir.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let Some(n) = legacy_abi_numeric_suffix(name) else {
            continue;
        };
        let has_list = io.exists(&dir.join(PATH_DENY_LIST_MAP));
        let has_count = io.exists(&dir.join(PATH_DENY_COUNT_MAP));
        if !has_list && !has_count {
            continue;
        }
        // Prefer dirs that have LIST; among equals, highest n wins.
        let score = (has_list as u8, has_count as u8, n);
        let replace = match &best {
            None => true,
            Some((bn, bdir)) => {
                let b_has_list = io.exists(&bdir.join(PATH_DENY_LIST_MAP));
                let b_has_count = io.exists(&bdir.join(PATH_DENY_COUNT_MAP));
                let bscore = (b_has_list as u8, b_has_count as u8, *bn);
                score >= bscore
            }
        };
        if replace {
            best = Some((n, dir));
        }
    }
    Ok(best.map(|(_, p)| p))
}

/// Where LIST and COUNT pins currently live during (or after) staging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenyPinLocations {
    pub list: PathBuf,
    pub count: PathBuf,
}

/// Resolve LIST/COUNT paths when a crash may have left them split across
/// `legacy_abi_<n>/` and the canonical pin root.
///
/// Prefers the staging copy when present (that is the migrated-aside source of
/// truth during resume); otherwise falls back to the canonical name.
pub fn resolve_deny_pin_locations<I: PinAbiIo>(
    io: &I,
    pin_root: &Path,
    legacy_dir: &Path,
) -> Result<DenyPinLocations> {
    let canon_list = pin_root.join(PATH_DENY_LIST_MAP);
    let canon_count = pin_root.join(PATH_DENY_COUNT_MAP);
    let leg_list = legacy_dir.join(PATH_DENY_LIST_MAP);
    let leg_count = legacy_dir.join(PATH_DENY_COUNT_MAP);

    let list = if io.exists(&leg_list) {
        leg_list
    } else if io.exists(&canon_list) {
        canon_list
    } else {
        bail!(
            "PATH_DENY_LIST missing from both {} and {}",
            legacy_dir.display(),
            pin_root.display()
        );
    };

    let count = if io.exists(&leg_count) {
        leg_count
    } else if io.exists(&canon_count) {
        canon_count
    } else {
        bail!(
            "PATH_DENY_COUNT missing from both {} and {}",
            legacy_dir.display(),
            pin_root.display()
        );
    };

    Ok(DenyPinLocations { list, count })
}

/// After a successful in-memory read, free canonical names so load can create
/// fresh ABI-sized maps. Never call this before entries are safely in memory —
/// a canonical pin may still hold the only copy of unread deny data (F3).
fn free_canonical_deny_pins_after_read<I: PinAbiIo>(io: &I, pin_root: &Path) -> Result<()> {
    for name in [PATH_DENY_LIST_MAP, PATH_DENY_COUNT_MAP] {
        let p = pin_root.join(name);
        if io.exists(&p) {
            io.remove_file(&p)?;
        }
    }
    Ok(())
}

fn expected_abi(name: &str) -> Option<&'static PinnedMapAbi> {
    PINNED_MAP_ABI.iter().find(|m| m.name == name)
}

/// Classify pin directory ABI state (read-only).
pub fn assess_pin_abi<I: PinAbiIo>(io: &I, pin_root: &Path) -> Result<PinAbiState> {
    let list_path = pin_root.join(PATH_DENY_LIST_MAP);
    let count_path = pin_root.join(PATH_DENY_COUNT_MAP);
    let list_exists = io.exists(&list_path);
    let count_exists = io.exists(&count_path);

    // Deny-only staging: process-only `proc_abi_*` must NOT force MigrationInProgress
    // (would falsely BootstrapFallback on cold start with leftover process staging).
    if let Some(legacy_dir) = select_deny_legacy_dir(io, pin_root)? {
        if !(list_exists && count_exists) {
            return Ok(PinAbiState::MigrationInProgress { legacy_dir });
        }
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

    // Compatible canonical maps + leftover deny/proc staging → Compatible;
    // prepare/cleanup will remove staging after LSM handoff.
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
    // Rename COUNT first, then LIST.
    //
    // Why: a crash between the two renames must remain recoverable without
    // losing unread deny data (F3). COUNT-first leaves LIST at the canonical
    // name (stable path) while COUNT is already under legacy_abi_<n>/.
    // `resolve_deny_pin_locations` then reads COUNT from legacy and LIST from
    // canonical. LIST-first would also be resolvable, but keeping the denser
    // policy payload on the canonical path longer is the safer mid-crash shape.
    io.rename(&count, &dest.join(PATH_DENY_COUNT_MAP))?;
    io.rename(&list, &dest.join(PATH_DENY_LIST_MAP))?;
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
        // Stage under proc_abi_<name>/ — never legacy_abi_* (deny-migration namespace).
        let staging = pin_root.join(format!("{PROC_ABI_DIR_PREFIX}{name}"));
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
            let locs = resolve_deny_pin_locations(io, pin_root, &legacy_dir)?;
            let entries = match io.read_legacy_deny_entries_at(&locs.list, &locs.count) {
                Ok(e) => {
                    // Data is now in memory — safe to free any remaining canonical
                    // names so load can create fresh ABI-sized maps (F3 preserved).
                    free_canonical_deny_pins_after_read(io, pin_root)?;
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
                        list = %locs.list.display(),
                        count = %locs.count.display(),
                        "MigrationInProgress but legacy entries unreadable — bootstrap fallback"
                    );
                    // Do NOT delete a canonical pin that may still hold the only
                    // copy of unread deny data. Only free a canonical name when a
                    // staging copy already exists (so we are not destroying the
                    // sole unread source).
                    for name in [PATH_DENY_LIST_MAP, PATH_DENY_COUNT_MAP] {
                        let canon = pin_root.join(name);
                        let staged = legacy_dir.join(name);
                        if io.exists(&canon) && io.exists(&staged) {
                            io.remove_file(&canon)?;
                        } else if io.exists(&canon) && !io.exists(&staged) {
                            tracing::warn!(
                                target: "neuromesh::pin_abi",
                                pin = %canon.display(),
                                "retaining unread canonical deny pin (sole copy);                                  load may fail closed rather than destroy F3 data"
                            );
                        }
                    }
                    results.push(MigrationResult::BootstrapFallback);
                    DenySeedOverride::MigratedEntries {
                        entries: bootstrap_entries_fallback()?,
                        from_legacy: false,
                    }
                }
            };
            let proc = recreate_mismatched_process_maps(io, pin_root)?;
            if !proc.is_empty() {
                results.push(MigrationResult::ProcessMapRecreated);
            }
            Ok((entries, results))
        }
    }
}

/// Delete deny-only `legacy_abi_<n>` staging dirs after the new LSM link is live.
pub fn cleanup_legacy_abi_dirs<I: PinAbiIo>(io: &I, pin_root: &Path) -> Result<()> {
    for dir in list_legacy_abi_dirs(io, pin_root)? {
        io.remove_dir_all(&dir)?;
        tracing::info!(
            target: "neuromesh::pin_abi",
            legacy_dir = %dir.display(),
            "removed legacy ABI staging directory after successful LSM handoff"
        );
    }
    Ok(())
}

/// Delete `proc_abi_*` process-map staging dirs after the new LSM link is live.
pub fn cleanup_proc_abi_dirs<I: PinAbiIo>(io: &I, pin_root: &Path) -> Result<()> {
    for dir in list_proc_abi_dirs(io, pin_root)? {
        io.remove_dir_all(&dir)?;
        tracing::info!(
            target: "neuromesh::pin_abi",
            proc_dir = %dir.display(),
            "removed process ABI staging directory after successful LSM handoff"
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
    use crate::path_deny::{legacy_hardcoded_is_blacklisted, map_backed_is_blacklisted};
    use neuromesh_common::{PATH_DENY_ENTRY_SIZE, PATH_DENY_KEY_BYTES_LEGACY as LEGACY_KEY};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Test double with optional fail-after-N rename crash injection (D4).
    struct FakeIo {
        files: Mutex<HashMap<PathBuf, Vec<u8>>>,
        dirs: Mutex<Vec<PathBuf>>,
        info: Mutex<HashMap<PathBuf, ObservedMapInfo>>,
        legacy_entries: Mutex<HashMap<PathBuf, Vec<PathDenyEntry>>>,
        /// When `Some(n)`, the n-th `rename` call (1-based) returns an error.
        fail_after_renames: Mutex<Option<usize>>,
        rename_count: Mutex<usize>,
    }

    impl Default for FakeIo {
        fn default() -> Self {
            Self {
                files: Mutex::new(HashMap::new()),
                dirs: Mutex::new(Vec::new()),
                info: Mutex::new(HashMap::new()),
                legacy_entries: Mutex::new(HashMap::new()),
                fail_after_renames: Mutex::new(None),
                rename_count: Mutex::new(0),
            }
        }
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
        fn arm_fail_after_renames(&self, n: usize) {
            *self.fail_after_renames.lock().unwrap() = Some(n);
            *self.rename_count.lock().unwrap() = 0;
        }
        fn disarm_crash(&self) {
            *self.fail_after_renames.lock().unwrap() = None;
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
            {
                let mut count = self.rename_count.lock().unwrap();
                *count = count.saturating_add(1);
                if let Some(limit) = *self.fail_after_renames.lock().unwrap() {
                    if *count >= limit {
                        bail!(
                            "injected crash after rename #{count} ({} → {})",
                            from.display(),
                            to.display()
                        );
                    }
                }
            }
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
        fn read_legacy_deny_entries_at(
            &self,
            list_path: &Path,
            count_path: &Path,
        ) -> Result<Vec<PathDenyEntry>> {
            let entries = self.legacy_entries.lock().unwrap();
            // Look up by either parent (split staging: LIST/COUNT in different dirs)
            // or by the pin root / legacy dir keys tests insert.
            for parent in [list_path.parent(), count_path.parent()]
                .into_iter()
                .flatten()
            {
                if let Some(e) = entries.get(parent) {
                    if e.is_empty() {
                        bail!(
                            "legacy PATH_DENY_COUNT[0] == 0 — refuse empty deny list (fail-open)"
                        );
                    }
                    return Ok(e.clone());
                }
            }
            bail!(
                "no legacy entries for list={} count={}",
                list_path.display(),
                count_path.display()
            )
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
        let proc = root.join(format!("{PROC_ABI_DIR_PREFIX}{PROCESS_EVENTS_MAP}"));
        io.touch_dir(&root);
        io.touch_dir(&legacy);
        io.touch_dir(&proc);
        io.touch_file(&legacy.join(PATH_DENY_LIST_MAP));
        io.touch_file(&proc.join(PROCESS_EVENTS_MAP));
        cleanup_legacy_abi_dirs(&io, &root).unwrap();
        assert!(!io.exists(&legacy));
        // Deny cleanup must not touch proc staging.
        assert!(io.exists(&proc));
        cleanup_proc_abi_dirs(&io, &root).unwrap();
        assert!(!io.exists(&proc));
    }

    #[test]
    fn process_only_staging_cold_stays_cold() {
        // D2: leftover proc_abi_* on a cold pin root must NOT look like migration
        // (would falsely BootstrapFallback / MigrationInProgress).
        let io = FakeIo::default();
        let root = PathBuf::from("/pins");
        let proc = root.join(format!("{PROC_ABI_DIR_PREFIX}{PROCESS_EVENTS_MAP}"));
        io.touch_dir(&root);
        io.touch_dir(&proc);
        io.touch_file(&proc.join(PROCESS_EVENTS_MAP));
        assert_eq!(assess_pin_abi(&io, &root).unwrap(), PinAbiState::Cold);
        let (seed, results) = prepare_pin_root_for_load(&io, &root).unwrap();
        assert!(matches!(seed, DenySeedOverride::Bootstrap));
        assert!(!results.contains(&MigrationResult::BootstrapFallback));
    }

    #[test]
    fn both_proc_and_deny_staging_still_migrates() {
        // D2: proc_abi_* coexisting with legacy_abi_<n> must not hide deny migration.
        let io = FakeIo::default();
        let root = PathBuf::from("/pins");
        let legacy = root.join("legacy_abi_0");
        let proc = root.join(format!("{PROC_ABI_DIR_PREFIX}{PROCESS_EVENTS_MAP}"));
        io.touch_dir(&root);
        io.touch_dir(&legacy);
        io.touch_dir(&proc);
        io.touch_file(&legacy.join(PATH_DENY_LIST_MAP));
        io.touch_file(&legacy.join(PATH_DENY_COUNT_MAP));
        io.touch_file(&proc.join(PROCESS_EVENTS_MAP));
        let entry = PathDenyEntry::from_prefix(b"/tmp/").unwrap();
        io.legacy_entries
            .lock()
            .unwrap()
            .insert(legacy.clone(), vec![entry]);

        match assess_pin_abi(&io, &root).unwrap() {
            PinAbiState::MigrationInProgress { legacy_dir } => {
                assert_eq!(legacy_dir, legacy);
            }
            other => panic!("expected MigrationInProgress, got {other:?}"),
        }
        let (seed, results) = prepare_pin_root_for_load(&io, &root).unwrap();
        assert!(results.contains(&MigrationResult::ResumedMigration));
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
    fn select_deny_legacy_dir_prefers_numeric_highest_with_list() {
        // D2: string sort would order legacy_abi_10 before legacy_abi_2; we must
        // pick by content + numeric suffix, not dirs[0] from lexicographic sort.
        let io = FakeIo::default();
        let root = PathBuf::from("/pins");
        let d2 = root.join("legacy_abi_2");
        let d10 = root.join("legacy_abi_10");
        io.touch_dir(&root);
        io.touch_dir(&d2);
        io.touch_dir(&d10);
        // Only legacy_abi_2 holds LIST (string-sort dirs[0] would be legacy_abi_10).
        io.touch_file(&d2.join(PATH_DENY_LIST_MAP));
        io.touch_file(&d2.join(PATH_DENY_COUNT_MAP));

        let listed = list_legacy_abi_dirs(&io, &root).unwrap();
        assert_eq!(listed, vec![d2.clone(), d10.clone()]);

        let selected = select_deny_legacy_dir(&io, &root).unwrap().unwrap();
        assert_eq!(selected, d2);

        // When both have LIST/COUNT, highest numeric n wins.
        io.touch_file(&d10.join(PATH_DENY_LIST_MAP));
        io.touch_file(&d10.join(PATH_DENY_COUNT_MAP));
        let selected = select_deny_legacy_dir(&io, &root).unwrap().unwrap();
        assert_eq!(selected, d10);

        match assess_pin_abi(&io, &root).unwrap() {
            PinAbiState::MigrationInProgress { legacy_dir } => {
                assert_eq!(legacy_dir, d10);
            }
            other => panic!("expected MigrationInProgress toward legacy_abi_10, got {other:?}"),
        }
    }

    #[test]
    fn recreate_process_maps_uses_proc_abi_prefix() {
        let io = FakeIo::default();
        let root = PathBuf::from("/pins");
        io.touch_dir(&root);
        io.set_info(
            &root.join(PROCESS_EVENTS_MAP),
            ObservedMapInfo {
                map_type: neuromesh_common::BPF_MAP_TYPE_RINGBUF,
                key_size: 0,
                value_size: 0,
                max_entries: 1,
            },
        );
        let removed = recreate_mismatched_process_maps(&io, &root).unwrap();
        assert_eq!(removed, vec![PROCESS_EVENTS_MAP]);
        let staging = root.join(format!("{PROC_ABI_DIR_PREFIX}{PROCESS_EVENTS_MAP}"));
        assert!(io.exists(&staging.join(PROCESS_EVENTS_MAP)));
        assert!(list_legacy_abi_dirs(&io, &root).unwrap().is_empty());
        assert_eq!(list_proc_abi_dirs(&io, &root).unwrap(), vec![staging]);
        // Cold with only proc staging.
        assert_eq!(assess_pin_abi(&io, &root).unwrap(), PinAbiState::Cold);
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
    fn crash_between_count_and_list_rename_converges() {
        // D3: stage renames COUNT then LIST. Simulate crash after COUNT rename:
        // COUNT in legacy_abi_0/, LIST still canonical. Resume must read both
        // and preserve entries (never BootstrapFallback / empty deny).
        let io = FakeIo::default();
        let root = PathBuf::from("/pins");
        let legacy = root.join("legacy_abi_0");
        io.touch_dir(&root);
        io.touch_dir(&legacy);

        // Partial stage: COUNT moved, LIST still canonical (post-COUNT, pre-LIST).
        io.set_info(&legacy.join(PATH_DENY_COUNT_MAP), count_info());
        io.set_info(&root.join(PATH_DENY_LIST_MAP), legacy_list_info());

        let entry = PathDenyEntry::from_prefix(b"/opt/neuromesh/staging/").unwrap();
        // Entries discoverable via either parent (resolve reads split paths).
        io.legacy_entries
            .lock()
            .unwrap()
            .insert(root.clone(), vec![entry]);
        io.legacy_entries
            .lock()
            .unwrap()
            .insert(legacy.clone(), vec![entry]);

        let locs = resolve_deny_pin_locations(&io, &root, &legacy).unwrap();
        assert_eq!(locs.list, root.join(PATH_DENY_LIST_MAP));
        assert_eq!(locs.count, legacy.join(PATH_DENY_COUNT_MAP));

        match assess_pin_abi(&io, &root).unwrap() {
            PinAbiState::MigrationInProgress { legacy_dir } => {
                assert_eq!(legacy_dir, legacy);
            }
            other => panic!("expected MigrationInProgress, got {other:?}"),
        }

        let (seed, results) = prepare_pin_root_for_load(&io, &root).unwrap();
        assert!(results.contains(&MigrationResult::ResumedMigration));
        assert!(!results.contains(&MigrationResult::BootstrapFallback));
        match seed {
            DenySeedOverride::MigratedEntries {
                entries,
                from_legacy,
            } => {
                assert!(from_legacy);
                assert!(!entries.is_empty());
                assert!(entries[0].matches(b"/opt/neuromesh/staging/x"));
            }
            other => panic!("unexpected seed {other:?}"),
        }
        // Canonical names freed after successful read.
        assert!(!io.exists(&root.join(PATH_DENY_LIST_MAP)));
        assert!(!io.exists(&root.join(PATH_DENY_COUNT_MAP)));

        // Re-run converges (still MigrationInProgress with LIST+COUNT in legacy).
        io.touch_file(&legacy.join(PATH_DENY_LIST_MAP));
        let (seed2, results2) = prepare_pin_root_for_load(&io, &root).unwrap();
        assert!(results2.contains(&MigrationResult::ResumedMigration));
        match seed2 {
            DenySeedOverride::MigratedEntries { entries, .. } => {
                assert!(!entries.is_empty());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn stage_renames_count_before_list() {
        let io = FakeIo::default();
        let root = PathBuf::from("/pins");
        io.touch_dir(&root);
        io.set_info(&root.join(PATH_DENY_LIST_MAP), legacy_list_info());
        io.set_info(&root.join(PATH_DENY_COUNT_MAP), count_info());
        // Instrument order via a wrapper would be ideal; here we assert final
        // stage layout and that an interrupted COUNT-first shape is the
        // documented recoverable form (see crash_between_count_and_list_rename).
        let dest = stage_legacy_deny_pins(&io, &root).unwrap();
        assert!(io.exists(&dest.join(PATH_DENY_LIST_MAP)));
        assert!(io.exists(&dest.join(PATH_DENY_COUNT_MAP)));
        assert!(!io.exists(&root.join(PATH_DENY_LIST_MAP)));
        assert!(!io.exists(&root.join(PATH_DENY_COUNT_MAP)));
    }

    #[test]
    fn incident_208_regression_name() {
        // Named after the incident for git-blame / CI grep discoverability.
        let info = legacy_list_info();
        assert!(info.is_legacy_path_deny_list());
        assert_eq!(info.value_size, 20);
        assert_eq!(PATH_DENY_ENTRY_SIZE, 36);
    }

    #[test]
    fn incident_208_prepare_legacy_20b_to_canonical_36b_preserves_entries() {
        // D4 regression: drive legacy 20B layout through prepare_pin_root_for_load
        // and assert migrated seed carries operator + bootstrap-shaped entries
        // (canonical names freed for fresh 36B maps).
        let io = FakeIo::default();
        let root = PathBuf::from("/pins");
        io.touch_dir(&root);
        io.set_info(&root.join(PATH_DENY_LIST_MAP), legacy_list_info());
        io.set_info(&root.join(PATH_DENY_COUNT_MAP), count_info());
        assert_eq!(
            io.map_info(&root.join(PATH_DENY_LIST_MAP))
                .unwrap()
                .value_size,
            20
        );
        let entries = vec![
            PathDenyEntry::from_prefix(b"/tmp/").unwrap(),
            PathDenyEntry::from_prefix(b"/dev/shm/").unwrap(),
            PathDenyEntry::from_prefix(b"/var/tmp/").unwrap(),
            PathDenyEntry::from_prefix(b"/opt/neuromesh/staging/").unwrap(),
        ];
        io.legacy_entries
            .lock()
            .unwrap()
            .insert(root.clone(), entries.clone());

        let (seed, results) = prepare_pin_root_for_load(&io, &root).unwrap();
        assert!(results.contains(&MigrationResult::Migrated));
        assert!(!io.exists(&root.join(PATH_DENY_LIST_MAP)));
        assert!(!io.exists(&root.join(PATH_DENY_COUNT_MAP)));
        match seed {
            DenySeedOverride::MigratedEntries {
                entries: migrated,
                from_legacy,
            } => {
                assert!(from_legacy);
                assert_eq!(migrated.len(), entries.len());
                for (a, b) in migrated.iter().zip(entries.iter()) {
                    assert_eq!(a.len, b.len);
                    assert_eq!(a.bytes, b.bytes);
                }
                // Widened entries use the current 36B ABI key width.
                assert!(migrated
                    .iter()
                    .all(|e| e.bytes.len() == PATH_DENY_KEY_BYTES));
                assert_eq!(PATH_DENY_ENTRY_SIZE, 36);
                assert!(migrated
                    .iter()
                    .any(|e| e.matches(b"/opt/neuromesh/staging/x")));
                assert!(
                    !migrated.is_empty(),
                    "deny list must never be empty after migrate"
                );
            }
            other => panic!("unexpected seed {other:?}"),
        }
    }

    #[test]
    fn crash_injection_every_rename_step_converges() {
        // D4: inject a crash at every rename step of migration; disarm and
        // re-run — must converge with non-empty deny seed; unknown layouts still refused.
        let entry = PathDenyEntry::from_prefix(b"/tmp/").unwrap();
        for fail_at in 1usize..=4 {
            let io = FakeIo::default();
            let root = PathBuf::from(format!("/pins_crash_{fail_at}"));
            io.touch_dir(&root);
            io.set_info(&root.join(PATH_DENY_LIST_MAP), legacy_list_info());
            io.set_info(&root.join(PATH_DENY_COUNT_MAP), count_info());
            // Mismatched process map adds extra renames into the crash surface.
            io.set_info(
                &root.join(PROCESS_EVENTS_MAP),
                ObservedMapInfo {
                    map_type: neuromesh_common::BPF_MAP_TYPE_RINGBUF,
                    key_size: 0,
                    value_size: 0,
                    max_entries: 1, // expected is 1MiB — forces recreate rename
                },
            );
            io.legacy_entries
                .lock()
                .unwrap()
                .insert(root.clone(), vec![entry]);
            io.arm_fail_after_renames(fail_at);

            let first = prepare_pin_root_for_load(&io, &root);
            if let Ok(ok) = first {
                // No further rename steps exist at this fail_at — migration already
                // completed without hitting the armed crash point.
                match ok {
                    (DenySeedOverride::MigratedEntries { entries, .. }, results) => {
                        assert!(!entries.is_empty());
                        assert!(
                            results.contains(&MigrationResult::Migrated)
                                || results.contains(&MigrationResult::ResumedMigration)
                        );
                    }
                    other => panic!("fail_at={fail_at}: unexpected ok {other:?}"),
                }
                continue;
            }

            // Resume: disarm crash injection; seed entries under every possible
            // parent resolve may consult (root and any legacy_abi_*).
            io.disarm_crash();
            for dir in list_legacy_abi_dirs(&io, &root).unwrap() {
                io.legacy_entries.lock().unwrap().insert(dir, vec![entry]);
            }
            // If COUNT moved but LIST remains, also keep root key.
            io.legacy_entries
                .lock()
                .unwrap()
                .insert(root.clone(), vec![entry]);

            let (seed, results) = prepare_pin_root_for_load(&io, &root).unwrap();
            assert!(
                results.contains(&MigrationResult::Migrated)
                    || results.contains(&MigrationResult::ResumedMigration),
                "fail_at={fail_at}: results={results:?}"
            );
            assert!(!results.contains(&MigrationResult::BootstrapFallback));
            match seed {
                DenySeedOverride::MigratedEntries { entries, .. } => {
                    assert!(
                        !entries.is_empty(),
                        "fail_at={fail_at}: deny list empty after converge"
                    );
                    assert!(entries[0].matches(b"/tmp/x"));
                }
                other => panic!("fail_at={fail_at}: unexpected seed {other:?}"),
            }
        }

        // Unknown layouts still refused (assertion not weakened).
        let io = FakeIo::default();
        let root = PathBuf::from("/pins_unknown");
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
        let err = prepare_pin_root_for_load(&io, &root).unwrap_err();
        assert!(err.to_string().contains("incompatible"), "{err}");
    }

    #[test]
    fn count_zero_via_trait_errors_then_bootstrap_fallback() {
        // D4: empty deny (count==0 / empty entries) through the trait must error;
        // prepare LegacyMigratable path falls back to BootstrapFallback (non-empty).
        let io = FakeIo::default();
        let root = PathBuf::from("/pins");
        io.touch_dir(&root);
        io.set_info(&root.join(PATH_DENY_LIST_MAP), legacy_list_info());
        io.set_info(&root.join(PATH_DENY_COUNT_MAP), count_info());
        io.legacy_entries
            .lock()
            .unwrap()
            .insert(root.clone(), Vec::new());

        let err = io.read_legacy_deny_entries(&root).unwrap_err();
        assert!(
            err.to_string().contains("fail-open") || err.to_string().contains("0"),
            "{err}"
        );

        let (seed, results) = prepare_pin_root_for_load(&io, &root).unwrap();
        assert!(results.contains(&MigrationResult::BootstrapFallback));
        match seed {
            DenySeedOverride::MigratedEntries {
                entries,
                from_legacy,
            } => {
                assert!(!from_legacy);
                assert!(!entries.is_empty(), "bootstrap deny must be non-empty");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn property_widen_oracle_all_prefix_and_path_lengths() {
        // D4: seeded exhaustive property — prefix lens 1..=16, path lens 0..=40,
        // with mutations; independent oracle via legacy hardcoded / 16B window
        // matcher cross-checked with widen + map-backed matches.
        let mut seed: u64 = 0x0002_08c0_ffee_u64;
        let mut next = || {
            // xorshift64*
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        for prefix_len in 1usize..=LEGACY_KEY {
            for path_len in 0usize..=40 {
                for mutation in 0u8..3 {
                    let mut legacy = LegacyPathDenyEntry {
                        len: prefix_len as u32,
                        bytes: [0; LEGACY_KEY],
                    };
                    for byte in &mut legacy.bytes[..prefix_len] {
                        *byte = (next() as u8).wrapping_add(b'a');
                    }
                    // Ensure printable-ish and stable for starts_with.
                    if legacy.bytes[0] == 0 {
                        legacy.bytes[0] = b'/';
                    }

                    let mut path = vec![0u8; path_len];
                    for byte in path.iter_mut() {
                        *byte = (next() as u8).wrapping_add(b'a');
                    }
                    // Mutation 0: path starts with prefix (when long enough)
                    // Mutation 1: diverge at last prefix byte
                    // Mutation 2: random (already filled)
                    if mutation == 0 && path_len >= prefix_len {
                        path[..prefix_len].copy_from_slice(&legacy.bytes[..prefix_len]);
                    } else if mutation == 1 && path_len >= prefix_len {
                        path[..prefix_len].copy_from_slice(&legacy.bytes[..prefix_len]);
                        path[prefix_len - 1] ^= 0x5a;
                    }

                    let legacy_hit = path.len() >= prefix_len
                        && path[..prefix_len] == legacy.bytes[..prefix_len];

                    // 16-byte window matcher (capture head) cross-check.
                    let mut window = [0u8; LEGACY_KEY];
                    let wlen = path.len().min(LEGACY_KEY);
                    window[..wlen].copy_from_slice(&path[..wlen]);
                    let window_hit =
                        wlen >= prefix_len && window[..prefix_len] == legacy.bytes[..prefix_len];
                    // For paths shorter than prefix, both miss; for longer paths
                    // window head matches legacy_hit on the significant prefix.
                    if path_len <= LEGACY_KEY {
                        assert_eq!(
                            window_hit, legacy_hit,
                            "window oracle diverged prefix_len={prefix_len} path_len={path_len} mut={mutation}"
                        );
                    }

                    assert!(
                        legacy_match_equivalent(&path, &legacy),
                        "widen equivalence failed prefix_len={prefix_len} path_len={path_len} mut={mutation}"
                    );

                    let wide = legacy.widen().expect("valid legacy must widen");
                    assert_eq!(wide.matches(&path), legacy_hit);

                    // Bootstrap hardcoded oracle: only meaningful for exact
                    // bootstrap prefixes, but map-backed must agree with widen.
                    let map_hit = map_backed_is_blacklisted(&path, &[wide]);
                    assert_eq!(map_hit, legacy_hit);

                    // When the legacy prefix equals a bootstrap prefix, hardcoded
                    // oracle must agree on matching paths.
                    for boot in neuromesh_common::BOOTSTRAP_PATH_DENY_PREFIXES {
                        if prefix_len == boot.len() && legacy.bytes[..prefix_len] == boot[..] {
                            assert_eq!(
                                legacy_hardcoded_is_blacklisted(&path),
                                legacy_hit,
                                "hardcoded oracle mismatch on {:?}",
                                boot
                            );
                        }
                    }
                }
            }
        }
    }

    /// Privileged stub: real aya `read_legacy_deny_entries` against bpffs.
    /// Requires root + mounted bpffs; ignored in default CI.
    #[test]
    #[ignore = "requires root + bpffs; run manually on a BPF-LSM host"]
    fn privileged_aya_read_legacy_deny_entries_stub() {
        let pin_root = std::env::var("NEUROMESH_BPF_PIN_ROOT")
            .unwrap_or_else(|_| "/sys/fs/bpf/neuromesh-pin-abi-verify".into());
        let root = PathBuf::from(pin_root);
        assert!(
            root.is_dir(),
            "bpffs pin root missing — create legacy pins before running"
        );
        let entries = RealPinAbiIo
            .read_legacy_deny_entries(&root)
            .expect("aya legacy read");
        assert!(
            !entries.is_empty(),
            "privileged read returned empty deny list (fail-open)"
        );
    }
}
