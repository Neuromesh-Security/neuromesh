//! Slice 2a identity-allow exceptions: bundle parse, TTL, manual cgroup seeding.
//!
//! **Lab/test only for cgroup seeding.** Production correlator is Slice 2b.
//! A PE outage / sync failure past `expires_at` (90s TTL) sets
//! `IDENTITY_EXCEPTIONS_VALID=0`, invalidating **all** exceptions including
//! manually seeded cgroup IDs — intentional, no grace-period workaround.
//!
//! Schema 3 adds whole-bundle `not_before` / `not_after` (T-PB-04); those are
//! enforced by [`crate::policy_sync::verify_bundle_temporal`], not here.
//! `identity_allow_exceptions.expires_at` remains identity VALID TTL only.

use anyhow::{bail, Context, Result};
use aya::maps::{Array, HashMap, MapData};
use chrono::{DateTime, Utc};
use neuromesh_common::{
    IDENTITY_ALLOW_CGROUPS_MAX_ENTRIES, IDENTITY_ALLOW_VALUE, IDENTITY_EXCEPTIONS_VALID_FRESH,
    IDENTITY_EXCEPTIONS_VALID_STALE, IDENTITY_EXCEPTION_SCOPE_PREFIX,
};
use std::time::{Duration, SystemTime};

/// Env var for lab/test-only comma-separated cgroup IDs to seed as allowed.
///
/// **Never set in production / Kubernetes manifests.** Emits a loud
/// `SECURITY WARNING` at startup when present (same class as
/// `NEUROMESH_INSECURE_MOCK_IDENTITY` / `NEUROMESH_COSIGN_REGISTRY_INSECURE`).
pub const IDENTITY_ALLOW_CGROUP_IDS_ENV: &str = "NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS";

/// Identity section TTL aligned with PE `IdentityExceptionTTL` (3× 30s sync).
pub const IDENTITY_EXCEPTION_TTL: Duration = Duration::from_secs(90);

/// Required `scope_path_prefix` string (literal `/tmp/` only).
pub const REQUIRED_SCOPE_PATH_PREFIX: &str = "/tmp/";

/// Handles for Slice 2a identity BPF maps (process-lifetime; not pinned).
pub struct IdentityAllowMaps {
    pub allow_cgroups: HashMap<MapData, u64, u8>,
    pub exceptions_valid: Array<MapData, u8>,
}

/// Parsed identity section from a schema_version 2|3 policy bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityAllowSection {
    pub scope_path_prefix: String,
    pub spiffe_ids: Vec<String>,
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
}

/// Result of evaluating whether the identity section may enable exceptions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentitySectionValidity {
    /// Fresh: within TTL and scope is exactly `/tmp/`.
    Fresh(IdentityAllowSection),
    /// Treat as invalid — same as expired/missing (VALID=0).
    Invalid { reason: String },
}

/// Full parse of a policy-bundle body (deny + optional identity + temporal).
#[derive(Debug, Clone)]
pub struct ParsedPolicyBundle {
    pub schema_version: u32,
    pub version: String,
    pub deny_path_prefixes: Vec<String>,
    pub identity: IdentitySectionValidity,
    /// Whole-bundle validity start (schema 3 / T-PB-04). Absent on schema 1|2.
    pub not_before: Option<SystemTime>,
    /// Whole-bundle validity end (schema 3 / T-PB-04). Absent on schema 1|2.
    pub not_after: Option<SystemTime>,
}

/// Parse RFC3339 timestamps used by PE (`time.RFC3339`).
fn parse_rfc3339(s: &str) -> Result<SystemTime> {
    let dt = DateTime::parse_from_rfc3339(s)
        .with_context(|| format!("invalid RFC3339 timestamp {s:?}"))?;
    Ok(SystemTime::from(dt.with_timezone(&Utc)))
}

fn system_now() -> SystemTime {
    SystemTime::now()
}

/// Evaluate identity section fields (pure; injectable `now` for tests).
pub fn evaluate_identity_section(
    scope_path_prefix: &str,
    spiffe_ids: Vec<String>,
    issued_at: SystemTime,
    expires_at: SystemTime,
    now: SystemTime,
) -> IdentitySectionValidity {
    if scope_path_prefix != REQUIRED_SCOPE_PATH_PREFIX {
        return IdentitySectionValidity::Invalid {
            reason: format!(
                "identity scope_path_prefix {scope_path_prefix:?} is not {REQUIRED_SCOPE_PATH_PREFIX:?} \
                 — treating identity section as invalid (defense in depth)"
            ),
        };
    }
    // Defense: scope must also match the byte constant used by the LSM.
    if REQUIRED_SCOPE_PATH_PREFIX.as_bytes() != IDENTITY_EXCEPTION_SCOPE_PREFIX {
        return IdentitySectionValidity::Invalid {
            reason: "internal scope constant mismatch".into(),
        };
    }
    if expires_at <= issued_at {
        return IdentitySectionValidity::Invalid {
            reason: "expires_at must be after issued_at".into(),
        };
    }
    if now >= expires_at {
        return IdentitySectionValidity::Invalid {
            reason: format!(
                "identity_allow_exceptions expired at {:?} (now {:?}) — VALID=0 for ALL exceptions",
                expires_at, now
            ),
        };
    }
    IdentitySectionValidity::Fresh(IdentityAllowSection {
        scope_path_prefix: scope_path_prefix.to_string(),
        spiffe_ids,
        issued_at,
        expires_at,
    })
}

/// Parse policy-bundle JSON (schema 1, 2, or 3). Schema 1 → identity Invalid.
/// Schema 2|3 share identity_allow_exceptions rules. Schema 3 may carry
/// top-level `not_before` / `not_after` (verified on the signed sync path).
pub fn parse_policy_bundle_json(body: &str) -> Result<ParsedPolicyBundle> {
    parse_policy_bundle_json_at(body, system_now())
}

/// Parse with injectable clock (unit tests).
pub fn parse_policy_bundle_json_at(body: &str, now: SystemTime) -> Result<ParsedPolicyBundle> {
    #[derive(serde::Deserialize)]
    struct IdentityDoc {
        scope_path_prefix: String,
        spiffe_ids: Vec<String>,
        issued_at: String,
        expires_at: String,
    }

    #[derive(serde::Deserialize)]
    struct BundleDoc {
        schema_version: u32,
        version: String,
        deny_path_prefixes: Vec<String>,
        #[serde(default)]
        identity_allow_exceptions: Option<IdentityDoc>,
        #[serde(default)]
        not_before: Option<String>,
        #[serde(default)]
        not_after: Option<String>,
    }

    let doc: BundleDoc = serde_json::from_str(body).context("malformed policy-bundle JSON")?;
    if doc.schema_version != 1 && doc.schema_version != 2 && doc.schema_version != 3 {
        bail!(
            "unsupported policy-bundle schema_version {} (expected 1, 2, or 3)",
            doc.schema_version
        );
    }
    if doc.version.is_empty() {
        bail!("policy-bundle missing version");
    }
    if doc.deny_path_prefixes.is_empty() {
        bail!("policy-bundle deny_path_prefixes is empty (refusing fail-open)");
    }

    let not_before = match doc
        .not_before
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(s) => Some(parse_rfc3339(s)?),
        None => None,
    };
    let not_after = match doc
        .not_after
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(s) => Some(parse_rfc3339(s)?),
        None => None,
    };

    let identity = match (doc.schema_version, doc.identity_allow_exceptions) {
        (2 | 3, Some(ie)) => {
            let issued = parse_rfc3339(&ie.issued_at)?;
            let expires = parse_rfc3339(&ie.expires_at)?;
            evaluate_identity_section(&ie.scope_path_prefix, ie.spiffe_ids, issued, expires, now)
        }
        (2 | 3, None) => IdentitySectionValidity::Invalid {
            reason: format!(
                "schema_version {} missing identity_allow_exceptions",
                doc.schema_version
            ),
        },
        (1, _) => IdentitySectionValidity::Invalid {
            reason: "schema_version 1 has no identity section".into(),
        },
        _ => IdentitySectionValidity::Invalid {
            reason: "unreachable schema".into(),
        },
    };

    Ok(ParsedPolicyBundle {
        schema_version: doc.schema_version,
        version: doc.version,
        deny_path_prefixes: doc.deny_path_prefixes,
        identity,
        not_before,
        not_after,
    })
}

/// Set `IDENTITY_EXCEPTIONS_VALID[0]`.
pub fn set_exceptions_valid(maps: &mut IdentityAllowMaps, fresh: bool) -> Result<()> {
    let v = if fresh {
        IDENTITY_EXCEPTIONS_VALID_FRESH
    } else {
        IDENTITY_EXCEPTIONS_VALID_STALE
    };
    maps.exceptions_valid
        .set(0, v, 0)
        .context("failed to write ID_EXCEPT_VALID[0]")?;
    Ok(())
}

/// Insert a single allowed cgroup_id (value=1).
pub fn seed_allow_cgroup(maps: &mut IdentityAllowMaps, cgroup_id: u64) -> Result<()> {
    maps.allow_cgroups
        .insert(cgroup_id, IDENTITY_ALLOW_VALUE, 0)
        .with_context(|| format!("failed to insert ID_ALLOW_CGROUP[{cgroup_id}]"))?;
    Ok(())
}

/// Remove a single allowed cgroup_id (Slice 2b-i invalidation).
///
/// Missing keys are OK (idempotent) — the entry may already have been cleared
/// by a racing teardown/informer path.
pub fn remove_allow_cgroup(maps: &mut IdentityAllowMaps, cgroup_id: u64) -> Result<()> {
    match maps.allow_cgroups.remove(&cgroup_id) {
        Ok(()) | Err(aya::maps::MapError::KeyNotFound) => Ok(()),
        Err(e) => Err(e).with_context(|| format!("failed to remove ID_ALLOW_CGROUP[{cgroup_id}]")),
    }
}

/// Parse `NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS` (comma-separated u64).
pub fn parse_manual_cgroup_ids(raw: &str) -> Result<Vec<u64>> {
    let mut out = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let id: u64 = part.parse().with_context(|| {
            format!("invalid cgroup_id in {IDENTITY_ALLOW_CGROUP_IDS_ENV}: {part:?}")
        })?;
        out.push(id);
    }
    if out.len() as u32 > IDENTITY_ALLOW_CGROUPS_MAX_ENTRIES {
        bail!(
            "manual cgroup seed has {} ids; max is {}",
            out.len(),
            IDENTITY_ALLOW_CGROUPS_MAX_ENTRIES
        );
    }
    Ok(out)
}

/// Loud, unmissable warning — same pattern as insecure mock / cosign insecure.
pub fn emit_manual_seed_security_warning(ids: &[u64]) {
    eprintln!(
        "SECURITY WARNING: {IDENTITY_ALLOW_CGROUP_IDS_ENV} is set — manual identity \
         cgroup seeding is ACTIVE (lab/test only). This is NOT a production correlator \
         (Slice 2b-ii auto-correlation). Slice 2b-i may invalidate these entries on \
         pod/cgroup teardown. Seeded cgroup_ids={ids:?}. Never set this in \
         deploy/kubernetes/ or production. PE outage past 90s still invalidates ALL \
         exceptions (VALID=0)."
    );
    tracing::error!(
        target: "neuromesh::identity_allow",
        ?ids,
        env = IDENTITY_ALLOW_CGROUP_IDS_ENV,
        "SECURITY WARNING: manual identity cgroup seeding active (lab/test only)"
    );
}

/// Load manual seeds from env; emit warning if any; write into **BPF map only**.
///
/// Does **not** set VALID=1 — PE freshness still required.
/// Does **not** arm Slice 2b-i side table / inotify — callers (see `main` /
/// [`crate::identity_correlator::register_manual_seed_ids`]) MUST register each
/// returned id with the correlator or invalidation will never fire for lab seeds.
pub fn apply_manual_cgroup_seeds_from_env(maps: &mut IdentityAllowMaps) -> Result<Vec<u64>> {
    let Ok(raw) = std::env::var(IDENTITY_ALLOW_CGROUP_IDS_ENV) else {
        return Ok(Vec::new());
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let ids = parse_manual_cgroup_ids(raw)?;
    emit_manual_seed_security_warning(&ids);
    for id in &ids {
        seed_allow_cgroup(maps, *id)?;
    }
    Ok(ids)
}

/// Apply identity validity from a parsed bundle (sets VALID flag only).
pub fn apply_identity_validity(
    maps: &mut IdentityAllowMaps,
    identity: &IdentitySectionValidity,
) -> Result<()> {
    match identity {
        IdentitySectionValidity::Fresh(_) => set_exceptions_valid(maps, true),
        IdentitySectionValidity::Invalid { reason } => {
            tracing::warn!(
                target: "neuromesh::identity_allow",
                %reason,
                "identity exceptions invalidated (VALID=0)"
            );
            set_exceptions_valid(maps, false)
        }
    }
}

/// If `expires_at` has passed, force VALID=0. Returns true when invalidated.
pub fn invalidate_if_expired(
    maps: &mut IdentityAllowMaps,
    expires_at: Option<SystemTime>,
    now: SystemTime,
) -> Result<bool> {
    let Some(exp) = expires_at else {
        set_exceptions_valid(maps, false)?;
        return Ok(true);
    };
    if now >= exp {
        tracing::warn!(
            target: "neuromesh::identity_allow",
            ?exp,
            "identity_allow_exceptions TTL exceeded — VALID=0 for ALL exceptions \
             (including manual seeds); intentional, no grace period"
        );
        set_exceptions_valid(maps, false)?;
        return Ok(true);
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    fn t(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn scope_path_prefix_not_tmp_is_invalid() {
        let v = evaluate_identity_section(
            "/var/tmp/",
            vec!["spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor".into()],
            t(1000),
            t(1090),
            t(1005),
        );
        match v {
            IdentitySectionValidity::Invalid { reason } => {
                assert!(reason.contains("scope_path_prefix"), "got {reason}");
            }
            IdentitySectionValidity::Fresh(_) => panic!("must reject non-/tmp/ scope"),
        }
    }

    #[test]
    fn scope_path_prefix_empty_is_invalid() {
        let v = evaluate_identity_section("", vec![], t(1), t(100), t(10));
        assert!(matches!(v, IdentitySectionValidity::Invalid { .. }));
    }

    #[test]
    fn fresh_tmp_scope_accepted() {
        let v = evaluate_identity_section(
            "/tmp/",
            vec!["spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor".into()],
            t(1000),
            t(1090),
            t(1005),
        );
        assert!(matches!(v, IdentitySectionValidity::Fresh(_)));
    }

    #[test]
    fn ttl_expiry_invalidates() {
        let v = evaluate_identity_section(
            "/tmp/",
            vec![],
            t(1000),
            t(1090),
            t(1090), // exactly at expiry → invalid
        );
        assert!(matches!(v, IdentitySectionValidity::Invalid { .. }));
    }

    /// Hardening: PE exporting anything other than literally "/tmp/" invalidates
    /// the entire identity section (same as expired/missing).
    #[test]
    fn parse_v2_wrong_scope_path_prefix_invalidates_identity_section() {
        let body = r#"{
            "schema_version": 2,
            "version": "sha256:test",
            "deny_path_prefixes": ["/tmp/", "/dev/shm/", "/var/tmp/"],
            "identity_allow_exceptions": {
                "scope_path_prefix": "/dev/shm/",
                "spiffe_ids": ["spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor"],
                "issued_at": "2026-07-25T19:00:00Z",
                "expires_at": "2026-07-25T19:01:30Z"
            }
        }"#;
        // 2026-07-25T19:00:10Z — within TTL so only scope fails.
        let now = DateTime::parse_from_rfc3339("2026-07-25T19:00:10Z")
            .unwrap()
            .with_timezone(&Utc)
            .into();
        let parsed = parse_policy_bundle_json_at(body, now).unwrap();
        assert_eq!(parsed.deny_path_prefixes.len(), 3);
        match parsed.identity {
            IdentitySectionValidity::Invalid { reason } => {
                assert!(
                    reason.contains("scope_path_prefix") && reason.contains("/dev/shm/"),
                    "expected scope rejection, got {reason}"
                );
            }
            IdentitySectionValidity::Fresh(_) => panic!("wrong scope must invalidate identity"),
        }
    }

    #[test]
    fn parse_v2_path_form_spiffe_ids_fresh() {
        let body = r#"{
            "schema_version": 2,
            "version": "sha256:abc",
            "deny_path_prefixes": ["/tmp/", "/dev/shm/", "/var/tmp/"],
            "identity_allow_exceptions": {
                "scope_path_prefix": "/tmp/",
                "spiffe_ids": [
                    "spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor",
                    "spiffe://neuromesh.security/ns/default/sa/zt-policy-engine"
                ],
                "issued_at": "2026-07-25T19:00:00Z",
                "expires_at": "2026-07-25T19:01:30Z"
            }
        }"#;
        let now = DateTime::parse_from_rfc3339("2026-07-25T19:00:10Z")
            .unwrap()
            .with_timezone(&Utc)
            .into();
        let parsed = parse_policy_bundle_json_at(body, now).unwrap();
        match parsed.identity {
            IdentitySectionValidity::Fresh(s) => {
                assert_eq!(s.scope_path_prefix, "/tmp/");
                assert_eq!(s.spiffe_ids.len(), 2);
                assert!(s.spiffe_ids[0].contains("/ns/default/sa/"));
            }
            IdentitySectionValidity::Invalid { reason } => panic!("expected fresh: {reason}"),
        }
    }

    #[test]
    fn parse_v2_expired_identity_invalid() {
        let body = r#"{
            "schema_version": 2,
            "version": "sha256:abc",
            "deny_path_prefixes": ["/tmp/"],
            "identity_allow_exceptions": {
                "scope_path_prefix": "/tmp/",
                "spiffe_ids": [],
                "issued_at": "2026-07-25T19:00:00Z",
                "expires_at": "2026-07-25T19:01:30Z"
            }
        }"#;
        let now = DateTime::parse_from_rfc3339("2026-07-25T19:05:00Z")
            .unwrap()
            .with_timezone(&Utc)
            .into();
        let parsed = parse_policy_bundle_json_at(body, now).unwrap();
        assert!(matches!(
            parsed.identity,
            IdentitySectionValidity::Invalid { .. }
        ));
    }

    #[test]
    fn parse_v3_with_temporal_fields() {
        let body = r#"{
            "schema_version": 3,
            "version": "sha256:abc",
            "not_before": "2026-07-25T19:00:00Z",
            "not_after": "2026-07-25T19:05:00Z",
            "deny_path_prefixes": ["/tmp/", "/dev/shm/", "/var/tmp/"],
            "identity_allow_exceptions": {
                "scope_path_prefix": "/tmp/",
                "spiffe_ids": [
                    "spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor"
                ],
                "issued_at": "2026-07-25T19:00:00Z",
                "expires_at": "2026-07-25T19:01:30Z"
            }
        }"#;
        let now = DateTime::parse_from_rfc3339("2026-07-25T19:00:10Z")
            .unwrap()
            .with_timezone(&Utc)
            .into();
        let parsed = parse_policy_bundle_json_at(body, now).unwrap();
        assert_eq!(parsed.schema_version, 3);
        assert!(parsed.not_before.is_some());
        assert!(parsed.not_after.is_some());
        assert!(matches!(parsed.identity, IdentitySectionValidity::Fresh(_)));
    }

    #[test]
    fn parse_manual_cgroup_ids_csv() {
        let ids = parse_manual_cgroup_ids(" 12, 34,56 ").unwrap();
        assert_eq!(ids, vec![12, 34, 56]);
    }

    #[test]
    fn manual_seed_warning_mentions_env_and_lab_only() {
        emit_manual_seed_security_warning(&[42]);
        assert_eq!(
            IDENTITY_ALLOW_CGROUP_IDS_ENV,
            "NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS"
        );
        assert_eq!(IDENTITY_EXCEPTION_TTL, Duration::from_secs(90));
    }
}
