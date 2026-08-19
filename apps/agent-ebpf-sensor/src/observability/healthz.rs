//! HTTP `/healthz` for Kubernetes liveness — shared listener with Prometheus.
//!
//! # Liveness contract (fail-closed on enforcement plane only)
//!
//! **503 Unhealthy (kubelet should restart)** when either:
//! - the pinned LSM link is missing or not openable via bpffs, or
//! - pinned `PATH_DENY_LIST` / `PATH_DENY_COUNT` map files are missing.
//!
//! These checks reuse the same helpers as the periodic integrity monitor
//! (`integrity::check_lsm_link_pin`, `integrity::check_pinned_deny_maps`).
//!
//! **200 OK (live)** even when policy sync is STALE or PE is unreachable.
//! Sync failures retain last-known-good deny prefixes by design; restarting
//! the agent would not repair a control-plane outage and would disrupt
//! visibility monitors unnecessarily.
//!
//! Policy sync status is exposed in the JSON body for operators (`stale`,
//! `last_version`) but does **not** gate liveness.

use crate::integrity::{check_lsm_link_pin, check_pinned_deny_maps, IntegrityFailure};
use crate::lsm_pin::EnforcementPinPaths;
use crate::path_deny::PolicySyncState;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Snapshot returned by `GET /healthz`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthReport {
    pub live: bool,
    pub lsm_link_pin_ok: bool,
    pub deny_map_pins_ok: bool,
    pub enforcement_failures: Vec<String>,
    pub policy_sync_stale: bool,
    pub policy_sync_version: String,
}

/// Shared probe state: enforcement pin paths + policy-sync snapshot.
#[derive(Clone)]
pub struct AgentHealthProbe {
    pin_paths: EnforcementPinPaths,
    policy_sync: Arc<RwLock<PolicySyncState>>,
}

impl AgentHealthProbe {
    pub fn new(pin_paths: EnforcementPinPaths, policy_sync: Arc<RwLock<PolicySyncState>>) -> Self {
        Self {
            pin_paths,
            policy_sync,
        }
    }

    /// Evaluate current health. Safe to call from the HTTP handler hot path.
    pub fn evaluate(&self) -> HealthReport {
        let enforcement = evaluate_enforcement(&self.pin_paths);
        let policy = evaluate_policy_sync(&self.policy_sync);

        HealthReport {
            live: enforcement.ok,
            lsm_link_pin_ok: enforcement.lsm_link_pin_ok,
            deny_map_pins_ok: enforcement.deny_map_pins_ok,
            enforcement_failures: enforcement
                .failures
                .into_iter()
                .map(|f| format!("{}: {}", f.reason, f.detail))
                .collect(),
            policy_sync_stale: policy.stale,
            policy_sync_version: policy.version,
        }
    }

    /// Serialize the report as JSON for `GET /healthz`.
    pub fn to_json(report: &HealthReport) -> String {
        #[derive(Serialize)]
        struct Checks {
            lsm_link_pin: &'static str,
            deny_map_pins: &'static str,
        }
        #[derive(Serialize)]
        struct PolicySync {
            stale: bool,
            last_version: String,
            affects_liveness: bool,
        }
        #[derive(Serialize)]
        struct Body {
            status: &'static str,
            service: &'static str,
            checks: Checks,
            policy_sync: PolicySync,
            enforcement_failures: Vec<String>,
        }

        let body = Body {
            status: if report.live { "ok" } else { "unhealthy" },
            service: "agent-ebpf-sensor",
            checks: Checks {
                lsm_link_pin: if report.lsm_link_pin_ok {
                    "ok"
                } else {
                    "failed"
                },
                deny_map_pins: if report.deny_map_pins_ok {
                    "ok"
                } else {
                    "failed"
                },
            },
            policy_sync: PolicySync {
                stale: report.policy_sync_stale,
                last_version: report.policy_sync_version.clone(),
                affects_liveness: false,
            },
            enforcement_failures: report.enforcement_failures.clone(),
        };
        serde_json::to_string(&body)
            .unwrap_or_else(|_| r#"{"status":"unhealthy","service":"agent-ebpf-sensor"}"#.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EnforcementHealth {
    ok: bool,
    lsm_link_pin_ok: bool,
    deny_map_pins_ok: bool,
    failures: Vec<IntegrityFailure>,
}

fn evaluate_enforcement(pin_paths: &EnforcementPinPaths) -> EnforcementHealth {
    let mut failures = Vec::new();
    let lsm_link_pin_ok = match check_lsm_link_pin(&pin_paths.link) {
        Ok(()) => true,
        Err(f) => {
            failures.push(f);
            false
        }
    };
    let deny_map_pins_ok = match check_pinned_deny_maps(pin_paths) {
        Ok(()) => true,
        Err(f) => {
            failures.push(f);
            false
        }
    };
    EnforcementHealth {
        ok: failures.is_empty(),
        lsm_link_pin_ok,
        deny_map_pins_ok,
        failures,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicySyncHealth {
    stale: bool,
    version: String,
}

fn evaluate_policy_sync(state: &Arc<RwLock<PolicySyncState>>) -> PolicySyncHealth {
    // Health handler may run on the Tokio runtime worker; use try_read so a
    // contended policy_sync write lock does not block the probe indefinitely.
    let snapshot = state
        .try_read()
        .map(|guard| PolicySyncHealth {
            stale: guard.stale,
            version: guard.last_version.clone(),
        })
        .unwrap_or_else(|_| PolicySyncHealth {
            stale: true,
            version: "unknown".into(),
        });
    snapshot
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn probe_with_paths(link: PathBuf, list: PathBuf, count: PathBuf) -> AgentHealthProbe {
        let paths = EnforcementPinPaths {
            link,
            link_tmp: PathBuf::from("/tmp/unused-link-tmp"),
            list,
            count,
        };
        AgentHealthProbe::new(
            paths,
            Arc::new(RwLock::new(PolicySyncState::fresh("bootstrap"))),
        )
    }

    #[test]
    fn liveness_fails_when_lsm_pin_missing() {
        let probe = probe_with_paths(
            PathBuf::from("/nonexistent/neuromesh_lsm_exec_guard_link"),
            PathBuf::from("/nonexistent/PATH_DENY_LIST"),
            PathBuf::from("/nonexistent/PATH_DENY_COUNT"),
        );
        let report = probe.evaluate();
        assert!(!report.live);
        assert!(!report.lsm_link_pin_ok);
        assert!(!report.deny_map_pins_ok);
        assert!(!report.enforcement_failures.is_empty());
    }

    #[test]
    fn policy_sync_stale_does_not_fail_liveness_alone() {
        let paths = EnforcementPinPaths {
            link: PathBuf::from("/nonexistent/link"),
            link_tmp: PathBuf::from("/tmp/unused"),
            list: PathBuf::from("/nonexistent/list"),
            count: PathBuf::from("/nonexistent/count"),
        };
        let state = Arc::new(RwLock::new(PolicySyncState {
            last_success: std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(600))
                .unwrap_or_else(std::time::Instant::now),
            last_version: "sha256:stale".into(),
            stale: true,
        }));
        let probe = AgentHealthProbe::new(paths, Arc::clone(&state));
        let report = probe.evaluate();
        assert!(report.policy_sync_stale);
        assert_eq!(report.policy_sync_version, "sha256:stale");
        // Enforcement still fails here (missing pins), not because of stale sync.
        assert!(!report.live);
    }

    #[test]
    fn json_marks_stale_without_affecting_liveness_flag() {
        let report = HealthReport {
            live: true,
            lsm_link_pin_ok: true,
            deny_map_pins_ok: true,
            enforcement_failures: vec![],
            policy_sync_stale: true,
            policy_sync_version: "sha256:abc".into(),
        };
        let body = AgentHealthProbe::to_json(&report);
        assert!(body.contains("\"status\":\"ok\""));
        assert!(body.contains("\"stale\":true"));
        assert!(body.contains("\"affects_liveness\":false"));
    }
}
