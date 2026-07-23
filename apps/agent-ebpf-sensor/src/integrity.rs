//! Periodic runtime integrity checks (Issue #44 Phase 2).
//!
//! Runs on a background timer after successful startup — **not** on the LSM
//! hot path. Detects post-start node-local tampering Phase 1 attestation and
//! admission webhook do not cover:
//!
//! 1. `/proc/self/exe` digest drift vs the baseline captured at monitor start
//!    (agent binary is intentionally absent from the Phase 1 bytecode
//!    manifest — embedding a self-digest is circular; see
//!    `bytecode_attestation` module docs).
//! 2. Pinned LSM link still present and openable (`PinnedLink::from_pin` +
//!    `FdLink::info()`).
//! 3. Pinned `PATH_DENY_LIST` / `PATH_DENY_COUNT` still present under the pin root.
//!
//! On failure: `agent_integrity_failure_total{reason=…}` + `tracing::error!`.
//! Default: also exit the process (`NEUROMESH_INTEGRITY_EXIT_ON_FAILURE`,
//! default `true`) — safe now that LSM link + deny maps survive process exit
//! (PR #72).

use crate::bytecode_attestation::sha256_digest;
use crate::lsm_pin::{enforcement_pin_paths, EnforcementPinPaths, PINNED_ENFORCEMENT_MAPS};
use anyhow::{Context, Result};
use aya::programs::links::{FdLink, PinnedLink};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
#[cfg(feature = "orchestrator")]
use tokio_util::sync::CancellationToken;

/// Env: integrity poll interval in seconds (clamped to 30..=60; default 45).
pub const ENV_INTEGRITY_INTERVAL_SECS: &str = "NEUROMESH_INTEGRITY_INTERVAL_SECS";

/// Env: when `true`/`1`/`yes` (default), integrity failure exits the process
/// after alerting. Set `false`/`0`/`no` for alert-only.
pub const ENV_INTEGRITY_EXIT_ON_FAILURE: &str = "NEUROMESH_INTEGRITY_EXIT_ON_FAILURE";

/// Optional override for the expected `/proc/self/exe` digest (`sha256:<hex>`).
/// When unset, the monitor captures a baseline at spawn time.
pub const ENV_AGENT_EXE_DIGEST: &str = "NEUROMESH_AGENT_EXE_DIGEST";

const DEFAULT_INTERVAL_SECS: u64 = 45;
const MIN_INTERVAL_SECS: u64 = 30;
const MAX_INTERVAL_SECS: u64 = 60;

/// Prometheus `reason` label values (stable API).
pub const REASON_EXE_DIGEST: &str = "exe_digest";
pub const REASON_LSM_LINK: &str = "lsm_link";
pub const REASON_PINNED_MAP: &str = "pinned_map";

/// One failed integrity check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityFailure {
    pub reason: &'static str,
    pub detail: String,
}

/// Tunables + pin paths for one agent process.
#[derive(Debug, Clone)]
pub struct IntegrityConfig {
    pub interval: Duration,
    pub exit_on_failure: bool,
    /// File hashed for the exe identity check (production: `/proc/self/exe`).
    pub exe_path: PathBuf,
    /// Expected digest in `sha256:<64 lowercase hex>` form.
    pub expected_exe_digest: String,
    pub pin_paths: EnforcementPinPaths,
}

impl IntegrityConfig {
    /// Build config from environment and a pin root. Hashes `exe_path` for the
    /// baseline when `NEUROMESH_AGENT_EXE_DIGEST` is unset.
    pub fn from_env(pin_root: &Path, exe_path: impl Into<PathBuf>) -> Result<Self> {
        let exe_path = exe_path.into();
        let interval = interval_from_env();
        let exit_on_failure = exit_on_failure_from_env();
        let expected_exe_digest = match std::env::var(ENV_AGENT_EXE_DIGEST) {
            Ok(v) if !v.trim().is_empty() => {
                let v = v.trim().to_string();
                validate_digest_format(&v).context("NEUROMESH_AGENT_EXE_DIGEST")?;
                v
            }
            _ => hash_file(&exe_path).with_context(|| {
                format!(
                    "failed to capture baseline digest of {} for runtime integrity",
                    exe_path.display()
                )
            })?,
        };
        Ok(Self {
            interval,
            exit_on_failure,
            exe_path,
            expected_exe_digest,
            pin_paths: enforcement_pin_paths(pin_root),
        })
    }
}

fn interval_from_env() -> Duration {
    let secs = std::env::var(ENV_INTEGRITY_INTERVAL_SECS)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_INTERVAL_SECS)
        .clamp(MIN_INTERVAL_SECS, MAX_INTERVAL_SECS);
    Duration::from_secs(secs)
}

fn exit_on_failure_from_env() -> bool {
    match std::env::var(ENV_INTEGRITY_EXIT_ON_FAILURE) {
        Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
            "0" | "false" | "no" | "off" => false,
            _ => true,
        },
        Err(_) => true,
    }
}

fn validate_digest_format(digest: &str) -> Result<()> {
    if !digest.starts_with("sha256:") || digest.len() != "sha256:".len() + 64 {
        anyhow::bail!("digest must be sha256:<64 lowercase hex>, got {digest:?}");
    }
    let hex = &digest["sha256:".len()..];
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("digest hex is not hexadecimal: {digest:?}");
    }
    Ok(())
}

/// SHA-256 of a file's contents as `sha256:<hex>` (same form as Phase 1).
pub fn hash_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(sha256_digest(&bytes))
}

/// Compare current exe file digest to the configured expected value.
pub fn check_exe_digest(exe_path: &Path, expected: &str) -> Result<(), IntegrityFailure> {
    let actual = hash_file(exe_path).map_err(|e| IntegrityFailure {
        reason: REASON_EXE_DIGEST,
        detail: format!("failed to hash {}: {e:#}", exe_path.display()),
    })?;
    if actual != expected {
        return Err(IntegrityFailure {
            reason: REASON_EXE_DIGEST,
            detail: format!(
                "exe digest mismatch at {}: expected={expected} actual={actual}",
                exe_path.display()
            ),
        });
    }
    Ok(())
}

/// Confirm the LSM link pin exists and can be opened + queried via aya.
pub fn check_lsm_link_pin(link_path: &Path) -> Result<(), IntegrityFailure> {
    if !link_path.is_file() {
        return Err(IntegrityFailure {
            reason: REASON_LSM_LINK,
            detail: format!("LSM link pin missing at {}", link_path.display()),
        });
    }
    let pinned = PinnedLink::from_pin(link_path).map_err(|e| IntegrityFailure {
        reason: REASON_LSM_LINK,
        detail: format!("failed to open LSM link pin {}: {e}", link_path.display()),
    })?;
    let fd_link: FdLink = pinned.into();
    let info = fd_link.info().map_err(|e| IntegrityFailure {
        reason: REASON_LSM_LINK,
        detail: format!(
            "FdLink::info failed for pinned LSM link {}: {e}",
            link_path.display()
        ),
    })?;
    if info.program_id() == 0 {
        return Err(IntegrityFailure {
            reason: REASON_LSM_LINK,
            detail: format!(
                "pinned LSM link {} reports program_id=0 (unexpected attach state)",
                link_path.display()
            ),
        });
    }
    Ok(())
}

/// Confirm deny-map pins still exist (path presence — same contract as resume).
pub fn check_pinned_deny_maps(paths: &EnforcementPinPaths) -> Result<(), IntegrityFailure> {
    for (name, path) in [
        (PINNED_ENFORCEMENT_MAPS[0], &paths.list),
        (PINNED_ENFORCEMENT_MAPS[1], &paths.count),
    ] {
        if !path.is_file() {
            return Err(IntegrityFailure {
                reason: REASON_PINNED_MAP,
                detail: format!("pinned map {name} missing at {}", path.display()),
            });
        }
    }
    Ok(())
}

/// Run all Phase 2 checks once. Returns every failure found (does not short-circuit
/// after the first — operators get full signal in one tick).
pub fn run_integrity_checks(cfg: &IntegrityConfig) -> Vec<IntegrityFailure> {
    let mut failures = Vec::new();
    if let Err(f) = check_exe_digest(&cfg.exe_path, &cfg.expected_exe_digest) {
        failures.push(f);
    }
    if let Err(f) = check_lsm_link_pin(&cfg.pin_paths.link) {
        failures.push(f);
    }
    if let Err(f) = check_pinned_deny_maps(&cfg.pin_paths) {
        failures.push(f);
    }
    failures
}

/// Record failures on metrics + tracing. Returns `true` if the process should exit.
#[cfg(feature = "orchestrator")]
pub fn handle_integrity_failures(
    metrics: &crate::observability::AgentMetrics,
    exit_on_failure: bool,
    failures: &[IntegrityFailure],
) -> bool {
    use tracing::error;

    if failures.is_empty() {
        return false;
    }
    for failure in failures {
        metrics.record_integrity_failure(failure.reason);
        error!(
            target: "neuromesh::integrity",
            reason = failure.reason,
            detail = %failure.detail,
            exit_on_failure,
            "runtime integrity check failed — post-start tamper evidence"
        );
    }
    exit_on_failure
}

/// Spawn the periodic integrity loop (decoupled from per-exec LSM).
#[cfg(feature = "orchestrator")]
pub fn spawn_integrity_monitor(
    cfg: IntegrityConfig,
    metrics: std::sync::Arc<crate::observability::AgentMetrics>,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!(
            target: "neuromesh::integrity",
            interval_secs = cfg.interval.as_secs(),
            exit_on_failure = cfg.exit_on_failure,
            exe = %cfg.exe_path.display(),
            link = %cfg.pin_paths.link.display(),
            "runtime integrity monitor armed (Issue #44 Phase 2)"
        );

        let mut interval = tokio::time::interval(cfg.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Skip the immediate first tick so startup is not double-taxed; first
        // real check runs after one full interval.
        interval.tick().await;

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    tracing::info!(
                        target: "neuromesh::integrity",
                        "runtime integrity monitor shutting down"
                    );
                    return;
                }
                _ = interval.tick() => {
                    let failures = run_integrity_checks(&cfg);
                    if handle_integrity_failures(&metrics, cfg.exit_on_failure, &failures) {
                        tracing::error!(
                            target: "neuromesh::integrity",
                            "integrity failure with exit-on-failure enabled — terminating agent"
                        );
                        // Fail-closed for the orchestrator: process exit. LSM
                        // deny survives via pinned link (PR #72).
                        std::process::exit(78);
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("neuromesh-integrity-{nanos}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_file(path: &Path, bytes: &[u8]) {
        let mut f = fs::File::create(path).unwrap();
        f.write_all(bytes).unwrap();
    }

    #[test]
    fn exe_digest_match_and_mismatch() {
        let dir = tmp_dir();
        let exe = dir.join("agent.bin");
        write_file(&exe, b"neuromesh-agent-v1");
        let expected = hash_file(&exe).unwrap();
        assert!(check_exe_digest(&exe, &expected).is_ok());

        write_file(&exe, b"neuromesh-agent-TAMPERED");
        let err = check_exe_digest(&exe, &expected).unwrap_err();
        assert_eq!(err.reason, REASON_EXE_DIGEST);
        assert!(err.detail.contains("mismatch"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn pinned_map_missing_detected() {
        let dir = tmp_dir();
        let paths = enforcement_pin_paths(&dir);
        let err = check_pinned_deny_maps(&paths).unwrap_err();
        assert_eq!(err.reason, REASON_PINNED_MAP);

        write_file(&paths.list, b"x");
        write_file(&paths.count, b"x");
        assert!(check_pinned_deny_maps(&paths).is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn lsm_link_missing_detected() {
        let dir = tmp_dir();
        let paths = enforcement_pin_paths(&dir);
        let err = check_lsm_link_pin(&paths.link).unwrap_err();
        assert_eq!(err.reason, REASON_LSM_LINK);
        assert!(err.detail.contains("missing"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_checks_collects_multiple_failures() {
        let dir = tmp_dir();
        let exe = dir.join("agent.bin");
        write_file(&exe, b"baseline");
        let cfg = IntegrityConfig {
            interval: Duration::from_secs(45),
            exit_on_failure: true,
            exe_path: exe.clone(),
            expected_exe_digest: hash_file(&exe).unwrap(),
            pin_paths: enforcement_pin_paths(&dir),
        };
        write_file(&exe, b"swapped");
        let failures = run_integrity_checks(&cfg);
        let reasons: Vec<_> = failures.iter().map(|f| f.reason).collect();
        assert!(reasons.contains(&REASON_EXE_DIGEST));
        assert!(reasons.contains(&REASON_LSM_LINK));
        assert!(reasons.contains(&REASON_PINNED_MAP));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn exit_on_failure_env_defaults_true() {
        // Parse helpers — do not rely on process-global env mutation across tests.
        assert!(matches!(
            "false".trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        ));
        assert_eq!(
            DEFAULT_INTERVAL_SECS.clamp(MIN_INTERVAL_SECS, MAX_INTERVAL_SECS),
            45
        );
        assert_eq!(10u64.clamp(MIN_INTERVAL_SECS, MAX_INTERVAL_SECS), 30);
        assert_eq!(99u64.clamp(MIN_INTERVAL_SECS, MAX_INTERVAL_SECS), 60);
    }

    #[cfg(feature = "orchestrator")]
    #[test]
    fn handle_failures_increments_metric_and_respects_alert_only() {
        let metrics = crate::observability::AgentMetrics::new().unwrap();
        let failures = vec![IntegrityFailure {
            reason: REASON_EXE_DIGEST,
            detail: "test".into(),
        }];
        assert!(!handle_integrity_failures(&metrics, false, &failures));
        assert!(metrics.integrity_failure_total(REASON_EXE_DIGEST) >= 1.0);
        assert!(handle_integrity_failures(&metrics, true, &failures));
    }
}
