//! Pin LSM enforcement link + PATH_DENY_* maps so deny survives agent exit.
//!
//! ## Decision (Issue #44 PR A)
//!
//! **Pin the LSM link AND `PATH_DENY_LIST` / `PATH_DENY_COUNT` maps** (not
//! link-only).
//!
//! Reasoning:
//! - A pinned `FdLink` alone keeps `bprm_check_security` attached across
//!   process exit (aya: pin survives FD close; unpinned links detach on Drop).
//! - The deny map FDs are *not* kept alive by the link alone in a way that
//!   lets a *new* agent process update policy without also pinning the maps:
//!   `Ebpf::load()` always creates a fresh program image; without
//!   `map_pin_path`, it would get empty private maps while an old pinned
//!   link could still reference a different map set — split-brain.
//! - Pinning the maps (same pattern as `PROCESS_EVENTS`) lets a restarting
//!   agent `map_pin_path`-reuse the still-populated deny list, resume PE
//!   sync, and replace the LSM link without wiping policy back to the three
//!   bootstrap prefixes (which would temporarily weaken a wider synced list).
//! - Program object pinning is unnecessary: the pinned link keeps the
//!   loaded program referenced; on handoff we load a fresh program wired to
//!   the same pinned maps, attach it, pin the new link, then remove the old
//!   link pin (multi-attach window → no enforcement gap).
//!
//! ## Bootstrap / STALE interaction
//!
//! When both deny-map pins pre-exist and `PATH_DENY_COUNT[0] > 0`, **skip**
//! `bootstrap_deny_maps` (do not overwrite with hardcoded prefixes). Start
//! `PolicySyncState` in a STALE-until-sync posture (`pinned-resume`) so
//! existing STALE logging/semantics still apply until PE sync succeeds.

use anyhow::{bail, Context, Result};
use aya::programs::links::{FdLink, PinnedLink};
use aya::programs::Lsm;
use neuromesh_common::{PATH_DENY_COUNT_MAP, PATH_DENY_LIST_MAP};
use std::fs;
use std::path::{Path, PathBuf};

use crate::bpf_pin::prepare_pin_directory;
use crate::path_deny::{PathDenyMaps, PolicySyncState, POLICY_STALE_AFTER};

/// bpffs filename for the pinned LSM link (under [`crate::bpf_pin::pin_root`]).
///
/// Must not contain `.` — kernel `bpf_lookup` rejects dotted basenames with
/// `-EPERM` (reserved for bpffs extensions).
pub const LSM_LINK_PIN_NAME: &str = "neuromesh_lsm_exec_guard_link";

const LSM_LINK_PIN_TMP_NAME: &str = "neuromesh_lsm_exec_guard_link_tmp";
/// Deny-list maps that must be pinned with the LSM link for safe handoff.
pub const PINNED_ENFORCEMENT_MAPS: &[&str] = &[PATH_DENY_LIST_MAP, PATH_DENY_COUNT_MAP];

/// How to seed deny maps after load, given pre-existing pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyMapSeedPlan {
    /// No pins — write bootstrap prefixes (fail-closed historical defaults).
    Bootstrap,
    /// Pins existed — keep map contents; mark sync state STALE until PE refresh.
    ResumePinned { count: u32 },
}

/// Startup consistency for enforcement pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementPinState {
    /// Neither link nor deny maps pinned — cold start.
    Cold,
    /// Deny maps pinned (link may or may not); safe to reuse maps + attach/replace link.
    MapsReady { link_pinned: bool },
    /// Link pin without both deny maps — refuse (would be split-brain).
    InconsistentLinkWithoutMaps,
}

/// Classify pin directory state before `EbpfLoader::load`.
pub fn classify_enforcement_pins(pin_root: &Path) -> EnforcementPinState {
    let list = pin_root.join(PATH_DENY_LIST_MAP);
    let count = pin_root.join(PATH_DENY_COUNT_MAP);
    let link = pin_root.join(LSM_LINK_PIN_NAME);
    let maps_ok = list.is_file() && count.is_file();
    let link_ok = link.is_file();

    if link_ok && !maps_ok {
        return EnforcementPinState::InconsistentLinkWithoutMaps;
    }
    if maps_ok {
        return EnforcementPinState::MapsReady {
            link_pinned: link_ok,
        };
    }
    EnforcementPinState::Cold
}

/// Decide bootstrap vs resume after maps are opened. `pinned_maps_reused` is
/// true when both deny-map pin files existed *before* load.
pub fn deny_map_seed_plan(pinned_maps_reused: bool, active_count: u32) -> Result<DenyMapSeedPlan> {
    if !pinned_maps_reused {
        return Ok(DenyMapSeedPlan::Bootstrap);
    }
    if active_count == 0 {
        bail!(
            "pinned {PATH_DENY_COUNT_MAP} reports 0 active entries — refusing to resume \
             (empty deny list would fail-open); remove enforcement pins under the pin root \
             and restart for a cold bootstrap, or repair the pinned maps"
        );
    }
    Ok(DenyMapSeedPlan::ResumePinned {
        count: active_count,
    })
}

/// Policy sync state for a resumed pinned deny list: content kept, STALE until sync.
pub fn policy_state_for_pinned_resume() -> PolicySyncState {
    PolicySyncState {
        // Force STALE on first refresh_stale_flag / immediate warn path awareness.
        last_success: std::time::Instant::now()
            - POLICY_STALE_AFTER
            - std::time::Duration::from_secs(1),
        last_version: "pinned-resume".to_string(),
        stale: true,
    }
}

/// Absolute paths used for enforcement pins.
pub fn enforcement_pin_paths(pin_root: &Path) -> EnforcementPinPaths {
    EnforcementPinPaths {
        list: pin_root.join(PATH_DENY_LIST_MAP),
        count: pin_root.join(PATH_DENY_COUNT_MAP),
        link: pin_root.join(LSM_LINK_PIN_NAME),
        link_tmp: pin_root.join(LSM_LINK_PIN_TMP_NAME),
    }
}

#[derive(Debug, Clone)]
pub struct EnforcementPinPaths {
    pub list: PathBuf,
    pub count: PathBuf,
    pub link: PathBuf,
    pub link_tmp: PathBuf,
}

/// Attach `neuromesh_lsm_exec_guard` and pin the link under `pin_root` (fail-closed).
///
/// Handoff: pin to `*_link_tmp`, remove prior `*_link` if present (old attach
/// drops), rename tmp → final, then reopen. While both old and new programs may
/// briefly be attached before the old pin is removed, deny never goes to zero
/// attaches if an old pin existed.
pub fn attach_and_pin_lsm_fail_closed(program: &mut Lsm, pin_root: &Path) -> Result<PinnedLink> {
    prepare_pin_directory(pin_root).context(
        "bpffs pin directory unavailable — refusing to run with an unpinned LSM link \
         (fail-closed; agent exit would otherwise tear down enforcement)",
    )?;

    let paths = enforcement_pin_paths(pin_root);
    if paths.link_tmp.exists() {
        fs::remove_file(&paths.link_tmp).with_context(|| {
            format!(
                "failed to remove stale temp LSM link pin {}",
                paths.link_tmp.display()
            )
        })?;
    }

    let link_id = program
        .attach()
        .context("LSM bprm_check_security attach failed (fail-closed)")?;
    let owned = program
        .take_link(link_id)
        .context("failed to take ownership of LSM link for bpffs pin (fail-closed)")?;
    let fd_link: FdLink = owned.into();

    let pinned_tmp = fd_link.pin(&paths.link_tmp).with_context(|| {
        format!(
            "failed to pin LSM link to {} — refusing unpinned enforcement (fail-closed)",
            paths.link_tmp.display()
        )
    })?;

    // Drop the PinnedLink wrapper for tmp without unpinning: close the FD only.
    // The pin file keeps the attach alive (aya FdLink::pin docs).
    drop(pinned_tmp);

    if paths.link.exists() {
        fs::remove_file(&paths.link).with_context(|| {
            format!(
                "failed to remove previous LSM link pin {} during handoff (fail-closed)",
                paths.link.display()
            )
        })?;
    }

    fs::rename(&paths.link_tmp, &paths.link).with_context(|| {
        format!(
            "failed to finalize LSM link pin at {} (fail-closed)",
            paths.link.display()
        )
    })?;

    PinnedLink::from_pin(&paths.link).with_context(|| {
        format!(
            "LSM link pin written to {} but could not be re-opened — fail-closed",
            paths.link.display()
        )
    })
}

/// Read active deny count from opened maps (for seed plan).
pub fn active_deny_count(maps: &PathDenyMaps) -> Result<u32> {
    let count = maps
        .count
        .get(&0, 0)
        .context("failed to read PATH_DENY_COUNT[0]")?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::time::Duration;

    #[test]
    fn classify_cold_when_nothing_pinned() {
        let dir = tempfile_dir();
        assert_eq!(classify_enforcement_pins(&dir), EnforcementPinState::Cold);
    }

    #[test]
    fn classify_maps_ready_with_and_without_link() {
        let dir = tempfile_dir();
        touch(&dir.join(PATH_DENY_LIST_MAP));
        touch(&dir.join(PATH_DENY_COUNT_MAP));
        assert_eq!(
            classify_enforcement_pins(&dir),
            EnforcementPinState::MapsReady { link_pinned: false }
        );
        touch(&dir.join(LSM_LINK_PIN_NAME));
        assert_eq!(
            classify_enforcement_pins(&dir),
            EnforcementPinState::MapsReady { link_pinned: true }
        );
    }

    #[test]
    fn classify_inconsistent_link_without_maps() {
        let dir = tempfile_dir();
        touch(&dir.join(LSM_LINK_PIN_NAME));
        assert_eq!(
            classify_enforcement_pins(&dir),
            EnforcementPinState::InconsistentLinkWithoutMaps
        );
    }

    #[test]
    fn seed_plan_bootstrap_when_not_reused() {
        assert_eq!(
            deny_map_seed_plan(false, 0).unwrap(),
            DenyMapSeedPlan::Bootstrap
        );
        assert_eq!(
            deny_map_seed_plan(false, 3).unwrap(),
            DenyMapSeedPlan::Bootstrap
        );
    }

    #[test]
    fn seed_plan_resume_requires_nonzero_count() {
        let err = deny_map_seed_plan(true, 0).unwrap_err();
        assert!(
            err.to_string().contains("fail-open") || err.to_string().contains("0 active"),
            "{err}"
        );
        assert_eq!(
            deny_map_seed_plan(true, 3).unwrap(),
            DenyMapSeedPlan::ResumePinned { count: 3 }
        );
    }

    #[test]
    fn pinned_resume_state_is_stale() {
        let state = policy_state_for_pinned_resume();
        assert!(state.stale);
        assert_eq!(state.last_version, "pinned-resume");
        assert!(state.last_success.elapsed() > POLICY_STALE_AFTER);
    }

    fn tempfile_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "neuromesh-lsm-pin-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn touch(path: &Path) {
        File::create(path).unwrap();
    }
}
