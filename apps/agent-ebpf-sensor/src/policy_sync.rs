//! Periodic sync of the path-prefix deny list + identity exceptions from
//! zt-policy-engine (schema_version 3: identity + whole-bundle temporal binding).
//!
//! Fail-closed contract:
//! - Bootstrap (pre-attach) seeds the BPF maps with the historical hardcoded set.
//! - Sync failure leaves last-known-good **deny** map contents untouched.
//! - Identity exceptions: PE `expires_at` (90s TTL) — when exceeded, VALID=0 for
//!   **ALL** exceptions (including manual seeds). No grace-period workaround.
//! - Whole-bundle temporal (T-PB-04): `not_before` / `not_after` inside signed
//!   body; reject `bundle_expired` / `bundle_not_yet_valid` /
//!   `bundle_temporal_missing` before any `apply_*`.
//! - Staleness (> [`path_deny::POLICY_STALE_AFTER`]) is logged/metric'd but never
//!   disables path-deny enforcement.
//! - Auth failure (Issue #55) is a sync failure: no unauthenticated retry.

use crate::identity_allow::{
    self, apply_identity_validity, invalidate_if_expired, IdentityAllowMaps,
    IdentitySectionValidity, ParsedPolicyBundle,
};
use crate::identity_correlator::{
    clear_side_table_hygiene, revoke_not_in_allowlist, IdentityPolicyHooks,
};
use crate::path_deny::{
    apply_deny_entries, PathDenyMaps, PolicySyncState, POLICY_STALE_AFTER, POLICY_SYNC_INTERVAL,
};
use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

/// Environment variable for the policy-engine base URL (e.g. `http://127.0.0.1:8080`).
pub const POLICY_ENGINE_URL_ENV: &str = "NEUROMESH_ZT_POLICY_ENGINE_URL";

/// Shared bearer token for `GET /v1/policy-bundle` (Issue #55). Prefer the file form.
pub const POLICY_BUNDLE_TOKEN_ENV: &str = "NEUROMESH_POLICY_BUNDLE_TOKEN";

/// Absolute path to a file containing the shared bearer token (Secret mount).
pub const POLICY_BUNDLE_TOKEN_FILE_ENV: &str = "NEUROMESH_POLICY_BUNDLE_TOKEN_FILE";

/// HTTP response header carrying Cosign sign-blob-compatible detached signature
/// (standard base64) over the exact policy-bundle body bytes.
pub const POLICY_BUNDLE_SIGNATURE_HEADER: &str = "X-Neuromesh-Policy-Bundle-Signature";

/// Dedicated Cosign public key for policy-bundle verification (preferred).
pub const POLICY_BUNDLE_PUBLIC_KEY_PATH_ENV: &str = "NEUROMESH_POLICY_BUNDLE_PUBLIC_KEY_PATH";

/// Fallback Cosign public key path (same as bytecode attestation).
pub const COSIGN_PUBLIC_KEY_PATH_ENV: &str = "NEUROMESH_COSIGN_PUBLIC_KEY_PATH";

/// Default Cosign public key mount when neither policy-bundle nor Cosign env is set.
pub const DEFAULT_COSIGN_PUBLIC_KEY_PATH: &str = "/etc/neuromesh/cosign/cosign.pub";

/// Default whole-bundle validity window (10 × [`POLICY_SYNC_INTERVAL`]=30s).
/// Aligns with [`POLICY_STALE_AFTER`] (5 min) as one coherent freshness horizon.
pub const BUNDLE_VALIDITY_WINDOW: Duration = Duration::from_secs(300);

/// Accepted clock skew around `not_before` / `not_after` (T-PB-04). Keep tight —
/// not the 90s identity TTL.
pub const BUNDLE_CLOCK_SKEW: Duration = Duration::from_secs(5);

/// Optional override for [`BUNDLE_CLOCK_SKEW`] (seconds) — tests / live harness.
pub const POLICY_BUNDLE_CLOCK_SKEW_SECS_ENV: &str = "NEUROMESH_POLICY_BUNDLE_CLOCK_SKEW_SECS";

/// Load clock skew from env; invalid/empty → [`BUNDLE_CLOCK_SKEW`].
pub fn clock_skew_from_env() -> Duration {
    match std::env::var(POLICY_BUNDLE_CLOCK_SKEW_SECS_ENV) {
        Ok(raw) => {
            let raw = raw.trim();
            if raw.is_empty() {
                return BUNDLE_CLOCK_SKEW;
            }
            match raw.parse::<u64>() {
                Ok(secs) => Duration::from_secs(secs),
                Err(_) => BUNDLE_CLOCK_SKEW,
            }
        }
        Err(_) => BUNDLE_CLOCK_SKEW,
    }
}

/// Load the shared policy-bundle bearer token from file (preferred) or env.
pub fn load_bundle_token() -> Result<String> {
    if let Ok(path) = std::env::var(POLICY_BUNDLE_TOKEN_FILE_ENV) {
        let path = path.trim();
        if !path.is_empty() {
            let pb = PathBuf::from(path);
            if !pb.is_absolute() {
                bail!("{POLICY_BUNDLE_TOKEN_FILE_ENV} must be an absolute path, got {path:?}");
            }
            let raw = std::fs::read_to_string(&pb).with_context(|| {
                format!("read {POLICY_BUNDLE_TOKEN_FILE_ENV} at {}", pb.display())
            })?;
            let token = raw.trim().to_string();
            if token.is_empty() {
                bail!("{POLICY_BUNDLE_TOKEN_FILE_ENV} ({}) is empty", pb.display());
            }
            return Ok(token);
        }
    }
    match std::env::var(POLICY_BUNDLE_TOKEN_ENV) {
        Ok(t) => {
            let token = t.trim().to_string();
            if token.is_empty() {
                bail!("{POLICY_BUNDLE_TOKEN_ENV} is empty");
            }
            Ok(token)
        }
        Err(_) => bail!(
            "policy-bundle auth required when sync is enabled: set {POLICY_BUNDLE_TOKEN_ENV} or \
             {POLICY_BUNDLE_TOKEN_FILE_ENV} (Issue #55) — refusing unauthenticated sync"
        ),
    }
}

/// Load PEM public key for policy-bundle Cosign verify-blob.
///
/// Order: [`POLICY_BUNDLE_PUBLIC_KEY_PATH_ENV`] if set, else
/// [`COSIGN_PUBLIC_KEY_PATH_ENV`] / [`DEFAULT_COSIGN_PUBLIC_KEY_PATH`].
pub fn load_bundle_public_key_pem() -> Result<Vec<u8>> {
    let path = if let Ok(p) = std::env::var(POLICY_BUNDLE_PUBLIC_KEY_PATH_ENV) {
        let p = p.trim().to_string();
        if !p.is_empty() {
            PathBuf::from(p)
        } else {
            fallback_cosign_pubkey_path()
        }
    } else {
        fallback_cosign_pubkey_path()
    };
    if !path.is_absolute() {
        bail!(
            "policy-bundle public key path must be absolute, got {}",
            path.display()
        );
    }
    let pem = std::fs::read(&path).with_context(|| {
        format!(
            "read policy-bundle public key at {} (set {POLICY_BUNDLE_PUBLIC_KEY_PATH_ENV} or {COSIGN_PUBLIC_KEY_PATH_ENV})",
            path.display()
        )
    })?;
    if pem.is_empty() {
        bail!("policy-bundle public key at {} is empty", path.display());
    }
    Ok(pem)
}

fn fallback_cosign_pubkey_path() -> PathBuf {
    match std::env::var(COSIGN_PUBLIC_KEY_PATH_ENV) {
        Ok(p) if !p.trim().is_empty() => PathBuf::from(p.trim()),
        _ => PathBuf::from(DEFAULT_COSIGN_PUBLIC_KEY_PATH),
    }
}

/// Authenticated policy-bundle fetch result (body + detached signature header).
#[derive(Debug, Clone)]
pub struct FetchedBundle {
    pub body: String,
    pub signature_b64: Option<String>,
}

/// Verify Cosign sign-blob-compatible detached signature over exact body bytes.
///
/// Fail-closed: missing header => `signature_missing`; invalid => `signature_invalid`.
pub fn verify_bundle_signature(
    public_key_pem: &[u8],
    body: &str,
    signature_b64: Option<&str>,
) -> Result<()> {
    let Some(sig) = signature_b64.map(str::trim).filter(|s| !s.is_empty()) else {
        bail!(
            "policy-bundle signature_missing: required header {POLICY_BUNDLE_SIGNATURE_HEADER} absent or empty              — retaining last-known-good (no apply)"
        );
    };
    crate::bytecode_attestation::verify_cosign_blob_signature(
        public_key_pem,
        body.as_bytes(),
        sig.as_bytes(),
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "policy-bundle signature_invalid: Cosign verify-blob failed ({e}) — retaining last-known-good (no apply)"
        )
    })
}

/// Verify whole-bundle temporal binding (T-PB-04) before any `apply_*`.
///
/// Signed sync path requires schema_version 3 and non-empty `not_before` /
/// `not_after`. Accept if `now >= not_before - skew` AND `now <= not_after + skew`.
/// Same LKG contract as signature failures.
pub fn verify_bundle_temporal(parsed: &ParsedPolicyBundle, now: SystemTime) -> Result<()> {
    verify_bundle_temporal_with_skew(parsed, now, clock_skew_from_env())
}

/// Temporal check with injectable skew (unit tests).
pub fn verify_bundle_temporal_with_skew(
    parsed: &ParsedPolicyBundle,
    now: SystemTime,
    skew: Duration,
) -> Result<()> {
    if parsed.schema_version != 3 {
        bail!(
            "policy-bundle bundle_temporal_missing: signed sync requires schema_version 3 \
             with not_before/not_after (got schema_version {}) — retaining last-known-good (no apply)",
            parsed.schema_version
        );
    }
    let (Some(not_before), Some(not_after)) = (parsed.not_before, parsed.not_after) else {
        bail!(
            "policy-bundle bundle_temporal_missing: schema_version 3 missing/empty \
             not_before/not_after — retaining last-known-good (no apply)"
        );
    };

    // now >= not_before - skew  ⇔  now + skew >= not_before
    let earliest_ok = match now.checked_add(skew) {
        Some(t) => t,
        None => bail!(
            "policy-bundle bundle_not_yet_valid: clock overflow computing skew window \
             — retaining last-known-good (no apply)"
        ),
    };
    if earliest_ok < not_before {
        bail!(
            "policy-bundle bundle_not_yet_valid: now before not_before (skew={skew:?}) \
             — retaining last-known-good (no apply)"
        );
    }

    // now <= not_after + skew
    let latest_ok = match not_after.checked_add(skew) {
        Some(t) => t,
        None => bail!(
            "policy-bundle bundle_expired: clock overflow computing skew window \
             — retaining last-known-good (no apply)"
        ),
    };
    if now > latest_ok {
        bail!(
            "policy-bundle bundle_expired: now past not_after (skew={skew:?}) \
             — retaining last-known-good (no apply)"
        );
    }
    Ok(())
}

/// Authenticated GET of the raw policy-bundle body.
///
/// Always sends `Authorization: Bearer …`. Never falls back to an unauthenticated GET.
pub async fn fetch_policy_bundle(
    client: &reqwest::Client,
    base_url: &str,
    bearer_token: &str,
) -> Result<FetchedBundle> {
    if bearer_token.trim().is_empty() {
        bail!("refusing policy-bundle sync with empty bearer token (Issue #55)");
    }

    let url = format!("{}/v1/policy-bundle", base_url.trim_end_matches('/'));
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {bearer_token}"))
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .with_context(|| format!("GET {url} failed"))?;

    let status = response.status();
    if status.as_u16() == 401 || status.as_u16() == 403 {
        bail!(
            "GET {url} authentication rejected (HTTP {status}) — retaining last-known-good              (no unauthenticated retry)"
        );
    }
    if !status.is_success() {
        bail!("GET {url} returned HTTP {status}");
    }

    // Diagnostic (Issue #100 / correlator overhead): when the Cosign signature
    // header is absent or not visible-ASCII, dump EVERY response header name so
    // live runs can see what the agent actually received (curl≠agent mismatch).
    let response_header_names: Vec<&str> = response.headers().keys().map(|k| k.as_str()).collect();
    let signature_header_raw = response.headers().get(POLICY_BUNDLE_SIGNATURE_HEADER);
    let signature_b64 = signature_header_raw
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    if signature_b64.is_none() {
        tracing::error!(
            target: "neuromesh::policy_sync",
            %url,
            http_status = %status,
            signature_header_key_present = signature_header_raw.is_some(),
            response_header_names = %response_header_names.join(", "),
            "policy-bundle signature_missing diagnostic: ALL response header names \
             (key_present=true means get() found the header but to_str/trim yielded empty)"
        );
    }

    let body = response
        .text()
        .await
        .context("failed to read policy-bundle body")?;

    Ok(FetchedBundle {
        body,
        signature_b64,
    })
}

/// Fetch + apply one policy bundle (deny + identity validity + PE allowlist cache).
///
/// Updates `hooks.allowlist` when present. Caller must run
/// [`revoke_not_in_allowlist`] / [`clear_side_table_hygiene`] **after** releasing
/// `identity_maps` locks (those helpers re-lock the maps).
#[allow(clippy::too_many_arguments)] // deny/identity maps + optional PE hooks stay explicit
pub async fn sync_once(
    client: &reqwest::Client,
    base_url: &str,
    bearer_token: &str,
    public_key_pem: &[u8],
    deny_maps: &mut PathDenyMaps,
    identity_maps: &mut IdentityAllowMaps,
    state: &mut PolicySyncState,
    identity_expires_at: &mut Option<SystemTime>,
    hooks: Option<&IdentityPolicyHooks>,
) -> Result<IdentitySectionValidity> {
    let fetched = fetch_policy_bundle(client, base_url, bearer_token).await?;
    // Verify BEFORE parse/apply — fail-closed: never call apply_* on unsigned/invalid.
    verify_bundle_signature(
        public_key_pem,
        &fetched.body,
        fetched.signature_b64.as_deref(),
    )?;
    let parsed = identity_allow::parse_policy_bundle_json(&fetched.body)?;
    // T-PB-04: temporal binding AFTER signature+parse, BEFORE any apply_*.
    verify_bundle_temporal(&parsed, SystemTime::now())?;

    // Always refresh identity validity from the live body (expires_at advances
    // even when content version is unchanged).
    apply_identity_validity(identity_maps, &parsed.identity)?;
    *identity_expires_at = match &parsed.identity {
        IdentitySectionValidity::Fresh(s) => Some(s.expires_at),
        IdentitySectionValidity::Invalid { .. } => None,
    };

    // Slice 2b-ii-A: refresh PE allowlist cache on every Fresh apply (including
    // unchanged-version TTL refresh).
    if let Some(hooks) = hooks {
        match &parsed.identity {
            IdentitySectionValidity::Fresh(s) => {
                hooks.allowlist.replace(s.spiffe_ids.iter().cloned());
            }
            IdentitySectionValidity::Invalid { .. } => {
                hooks.allowlist.clear();
            }
        }
    }

    if parsed.version == state.last_version {
        state.mark_success(parsed.version.clone());
        tracing::debug!(
            target: "neuromesh::policy_sync",
            version = %state.last_version,
            "policy bundle unchanged (identity TTL refreshed)"
        );
        return Ok(parsed.identity);
    }

    let mut entries = Vec::with_capacity(parsed.deny_path_prefixes.len());
    for prefix in &parsed.deny_path_prefixes {
        let entry = neuromesh_common::PathDenyEntry::from_prefix(prefix.as_bytes())
            .ok_or_else(|| anyhow::anyhow!("bundle prefix {prefix:?} empty or too long"))?;
        entries.push(entry);
    }
    apply_deny_entries(deny_maps, &entries).context("failed to apply policy bundle to BPF maps")?;
    state.mark_success(parsed.version);
    tracing::info!(
        target: "neuromesh::policy_sync",
        version = %state.last_version,
        prefixes = entries.len(),
        identity_fresh = matches!(parsed.identity, IdentitySectionValidity::Fresh(_)),
        "applied path-prefix deny list + identity validity from zt-policy-engine"
    );
    Ok(parsed.identity)
}

async fn run_allowlist_followup(hooks: &IdentityPolicyHooks, identity: &IdentitySectionValidity) {
    #[cfg(feature = "orchestrator")]
    let metrics = hooks.metrics.as_ref().map(|m| m.as_ref());
    match identity {
        IdentitySectionValidity::Fresh(_) => {
            if let Err(e) = revoke_not_in_allowlist(
                &hooks.allowlist,
                &hooks.state,
                &hooks.maps,
                #[cfg(target_os = "linux")]
                hooks.teardown_tx.as_ref(),
                #[cfg(feature = "orchestrator")]
                metrics,
            )
            .await
            {
                tracing::warn!(
                    target: "neuromesh::policy_sync",
                    error = %e,
                    "PE allowlist revoke reconcile failed"
                );
            }
        }
        IdentitySectionValidity::Invalid { .. } => {
            if let Err(e) = clear_side_table_hygiene(
                &hooks.state,
                &hooks.maps,
                #[cfg(target_os = "linux")]
                hooks.teardown_tx.as_ref(),
                #[cfg(feature = "orchestrator")]
                metrics,
            )
            .await
            {
                tracing::warn!(
                    target: "neuromesh::policy_sync",
                    error = %e,
                    "side-table hygiene clear on Invalid failed"
                );
            }
        }
    }
}

/// Spawn the background sync loop. Errors are logged; deny maps keep last-known-good.
///
/// `identity_maps` is shared with Slice 2b-i correlator invalidation (same
/// `Arc<Mutex<…>>`).
pub fn spawn_policy_sync(
    deny_maps: PathDenyMaps,
    identity_maps: Arc<Mutex<IdentityAllowMaps>>,
    mut state: PolicySyncState,
    hooks: Option<IdentityPolicyHooks>,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    let deny_maps = Arc::new(Mutex::new(deny_maps));
    tokio::spawn(async move {
        let mut identity_expires_at: Option<SystemTime> = None;

        let base_url = match std::env::var(POLICY_ENGINE_URL_ENV) {
            Ok(url) if !url.is_empty() => url,
            _ => {
                tracing::info!(
                    target: "neuromesh::policy_sync",
                    "NEUROMESH_ZT_POLICY_ENGINE_URL unset — policy sync disabled; \
                     enforcing bootstrap deny list only; identity exceptions VALID=0"
                );
                {
                    let mut id = identity_maps.lock().await;
                    let _ = apply_identity_validity(
                        &mut id,
                        &IdentitySectionValidity::Invalid {
                            reason: "policy sync disabled".into(),
                        },
                    );
                }
                if let Some(ref h) = hooks {
                    h.allowlist.clear();
                    run_allowlist_followup(
                        h,
                        &IdentitySectionValidity::Invalid {
                            reason: "policy sync disabled".into(),
                        },
                    )
                    .await;
                }
                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = tokio::time::sleep(POLICY_SYNC_INTERVAL) => {
                            state.mark_success("bootstrap");
                        }
                    }
                }
            }
        };

        let bearer_token = match load_bundle_token() {
            Ok(t) => t,
            Err(error) => {
                tracing::error!(
                    target: "neuromesh::policy_sync",
                    %error,
                    "policy-bundle token unavailable — sync disabled; \
                     enforcing last-known-good bootstrap deny list (no unauthenticated requests)"
                );
                {
                    let mut id = identity_maps.lock().await;
                    let _ = apply_identity_validity(
                        &mut id,
                        &IdentitySectionValidity::Invalid {
                            reason: "token unavailable".into(),
                        },
                    );
                }
                if let Some(ref h) = hooks {
                    h.allowlist.clear();
                    run_allowlist_followup(
                        h,
                        &IdentitySectionValidity::Invalid {
                            reason: "token unavailable".into(),
                        },
                    )
                    .await;
                }
                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = tokio::time::sleep(POLICY_SYNC_INTERVAL) => {
                            state.refresh_stale_flag();
                        }
                    }
                }
            }
        };

        let public_key_pem = match load_bundle_public_key_pem() {
            Ok(pem) => pem,
            Err(error) => {
                tracing::error!(
                    target: "neuromesh::policy_sync",
                    %error,
                    "policy-bundle public key unavailable — sync disabled;                      enforcing last-known-good bootstrap deny list (fail-closed)"
                );
                {
                    let mut id = identity_maps.lock().await;
                    let _ = apply_identity_validity(
                        &mut id,
                        &IdentitySectionValidity::Invalid {
                            reason: "public key unavailable".into(),
                        },
                    );
                }
                if let Some(ref h) = hooks {
                    h.allowlist.clear();
                    run_allowlist_followup(
                        h,
                        &IdentitySectionValidity::Invalid {
                            reason: "public key unavailable".into(),
                        },
                    )
                    .await;
                }
                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = tokio::time::sleep(POLICY_SYNC_INTERVAL) => {
                            state.refresh_stale_flag();
                        }
                    }
                }
            }
        };

        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
        {
            Ok(c) => c,
            Err(error) => {
                tracing::error!(
                    target: "neuromesh::policy_sync",
                    %error,
                    "failed to build HTTP client — policy sync disabled; \
                     enforcing last-known-good bootstrap deny list"
                );
                return;
            }
        };

        tracing::info!(
            target: "neuromesh::policy_sync",
            %base_url,
            interval_secs = POLICY_SYNC_INTERVAL.as_secs(),
            stale_after_secs = POLICY_STALE_AFTER.as_secs(),
            "path-prefix deny-list + identity-exception sync armed (authenticated)"
        );

        let mut interval = tokio::time::interval(POLICY_SYNC_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = interval.tick() => {
                    let identity_outcome = {
                        let mut deny_guard = deny_maps.lock().await;
                        let mut id_guard = identity_maps.lock().await;
                        // TTL gate every tick — outage past expires_at kills ALL exceptions.
                        let _ = invalidate_if_expired(
                            &mut id_guard,
                            identity_expires_at,
                            SystemTime::now(),
                        );
                        match sync_once(
                            &client,
                            &base_url,
                            &bearer_token,
                            &public_key_pem,
                            &mut deny_guard,
                            &mut id_guard,
                            &mut state,
                            &mut identity_expires_at,
                            hooks.as_ref(),
                        )
                        .await
                        {
                            Ok(identity) => Some(identity),
                            Err(error) => {
                                state.refresh_stale_flag();
                                let _ = invalidate_if_expired(
                                    &mut id_guard,
                                    identity_expires_at,
                                    SystemTime::now(),
                                );
                                if state.stale {
                                    tracing::warn!(
                                        target: "neuromesh::policy_sync",
                                        %error,
                                        last_version = %state.last_version,
                                        "policy sync failed; deny list STALE — continuing with last-known-good"
                                    );
                                } else {
                                    tracing::warn!(
                                        target: "neuromesh::policy_sync",
                                        %error,
                                        last_version = %state.last_version,
                                        "policy sync failed — retaining last-known-good deny list"
                                    );
                                }
                                None
                            }
                        }
                    };
                    // Maps unlocked — safe to revoke/clear (re-locks maps).
                    if let (Some(h), Some(ref identity)) = (hooks.as_ref(), identity_outcome) {
                        run_allowlist_followup(h, identity).await;
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::pkcs8::EncodePublicKey as Ed25519EncodePublicKey;
    use ed25519_dalek::{Signer as Ed25519Signer, SigningKey as Ed25519SigningKey};
    use p256::pkcs8::LineEnding;
    use rand_core::OsRng;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Mutex;
    use std::thread;

    /// Serialize env-mutating tests (process-global env).
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    struct TestKey {
        signing: Ed25519SigningKey,
        pub_pem: Vec<u8>,
        pub_path: PathBuf,
        _dir: PathBuf,
    }

    fn generate_test_key() -> TestKey {
        let signing = Ed25519SigningKey::generate(&mut OsRng);
        let pem = signing
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("pem");
        let dir = std::env::temp_dir().join(format!(
            "neuromesh-bundle-key-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let pub_path = dir.join("bundle.pub");
        std::fs::write(&pub_path, pem.as_bytes()).unwrap();
        TestKey {
            signing,
            pub_pem: pem.into_bytes(),
            pub_path: std::fs::canonicalize(&pub_path).unwrap(),
            _dir: dir,
        }
    }

    fn sign_body(sk: &Ed25519SigningKey, body: &str) -> String {
        let sig = Ed25519Signer::sign(sk, body.as_bytes());
        base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
    }

    fn spawn_stub(
        expect_bearer: Option<&'static str>,
        status_line: &'static str,
        body: &'static str,
        signature_b64: Option<String>,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let req_lower = req.to_ascii_lowercase();
            if let Some(token) = expect_bearer {
                let needle = format!("authorization: bearer {token}");
                assert!(
                    req_lower.contains(&needle),
                    "expected bearer {token} in request:\n{req}"
                );
            }
            let sig_hdr = match signature_b64 {
                Some(ref s) => format!("{POLICY_BUNDLE_SIGNATURE_HEADER}: {s}\r\n"),
                None => String::new(),
            };
            let resp = format!(
                "{status_line}\r\nContent-Type: application/json\r\n{sig_hdr}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
        });
        (format!("http://{addr}"), handle)
    }

    fn sample_bundle_v3() -> &'static str {
        r#"{"schema_version":3,"version":"sha256:abad1dea","not_before":"2099-01-01T00:00:00Z","not_after":"2099-01-01T00:05:00Z","deny_path_prefixes":["/tmp/","/dev/shm/","/var/tmp/"],"identity_allow_exceptions":{"scope_path_prefix":"/tmp/","spiffe_ids":["spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor"],"issued_at":"2099-01-01T00:00:00Z","expires_at":"2099-01-01T00:01:30Z"}}"#
    }

    fn parsed_temporal(
        schema: u32,
        not_before: Option<&str>,
        not_after: Option<&str>,
    ) -> ParsedPolicyBundle {
        let nb = not_before.map(|s| {
            chrono::DateTime::parse_from_rfc3339(s)
                .unwrap()
                .with_timezone(&chrono::Utc)
                .into()
        });
        let na = not_after.map(|s| {
            chrono::DateTime::parse_from_rfc3339(s)
                .unwrap()
                .with_timezone(&chrono::Utc)
                .into()
        });
        ParsedPolicyBundle {
            schema_version: schema,
            version: "sha256:test".into(),
            deny_path_prefixes: vec!["/tmp/".into()],
            identity: IdentitySectionValidity::Invalid {
                reason: "test".into(),
            },
            not_before: nb,
            not_after: na,
        }
    }

    fn t_rfc3339(s: &str) -> SystemTime {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&chrono::Utc)
            .into()
    }

    #[test]
    fn verify_bundle_temporal_ok_inside_window() {
        let parsed = parsed_temporal(
            3,
            Some("2026-08-12T12:00:00Z"),
            Some("2026-08-12T12:05:00Z"),
        );
        verify_bundle_temporal_with_skew(
            &parsed,
            t_rfc3339("2026-08-12T12:02:00Z"),
            BUNDLE_CLOCK_SKEW,
        )
        .expect("inside window");
    }

    #[test]
    fn verify_bundle_temporal_expired() {
        let parsed = parsed_temporal(
            3,
            Some("2026-08-12T12:00:00Z"),
            Some("2026-08-12T12:05:00Z"),
        );
        let err = verify_bundle_temporal_with_skew(
            &parsed,
            t_rfc3339("2026-08-12T12:05:06Z"), // past not_after + 5s skew
            BUNDLE_CLOCK_SKEW,
        )
        .unwrap_err();
        assert!(err.to_string().contains("bundle_expired"), "got {err}");
    }

    #[test]
    fn verify_bundle_temporal_not_yet_valid() {
        let parsed = parsed_temporal(
            3,
            Some("2026-08-12T12:00:00Z"),
            Some("2026-08-12T12:05:00Z"),
        );
        let err = verify_bundle_temporal_with_skew(
            &parsed,
            t_rfc3339("2026-08-12T11:59:54Z"), // before not_before - 5s skew
            BUNDLE_CLOCK_SKEW,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("bundle_not_yet_valid"),
            "got {err}"
        );
    }

    #[test]
    fn verify_bundle_temporal_skew_allows_boundary() {
        let parsed = parsed_temporal(
            3,
            Some("2026-08-12T12:00:00Z"),
            Some("2026-08-12T12:05:00Z"),
        );
        // Exactly at not_before - 5s → OK
        verify_bundle_temporal_with_skew(
            &parsed,
            t_rfc3339("2026-08-12T11:59:55Z"),
            BUNDLE_CLOCK_SKEW,
        )
        .expect("skew early boundary");
        // Exactly at not_after + 5s → OK
        verify_bundle_temporal_with_skew(
            &parsed,
            t_rfc3339("2026-08-12T12:05:05Z"),
            BUNDLE_CLOCK_SKEW,
        )
        .expect("skew late boundary");
    }

    #[test]
    fn verify_bundle_temporal_missing_fields() {
        let parsed = parsed_temporal(3, None, None);
        let err = verify_bundle_temporal_with_skew(
            &parsed,
            t_rfc3339("2026-08-12T12:00:00Z"),
            BUNDLE_CLOCK_SKEW,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("bundle_temporal_missing"),
            "got {err}"
        );
    }

    #[test]
    fn verify_bundle_temporal_schema2_rejected() {
        let parsed = parsed_temporal(
            2,
            Some("2026-08-12T12:00:00Z"),
            Some("2026-08-12T12:05:00Z"),
        );
        let err = verify_bundle_temporal_with_skew(
            &parsed,
            t_rfc3339("2026-08-12T12:02:00Z"),
            BUNDLE_CLOCK_SKEW,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("bundle_temporal_missing"),
            "got {err}"
        );
    }

    #[test]
    fn load_bundle_token_from_file() {
        let _guard = env_lock();
        let dir = std::env::temp_dir().join(format!(
            "neuromesh-token-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("token");
        std::fs::write(&path, "  secret-from-file\n").unwrap();
        let abs = std::fs::canonicalize(&path).unwrap();
        std::env::set_var(POLICY_BUNDLE_TOKEN_FILE_ENV, &abs);
        std::env::remove_var(POLICY_BUNDLE_TOKEN_ENV);
        let got = load_bundle_token().expect("token");
        assert_eq!(got, "secret-from-file");
        std::env::remove_var(POLICY_BUNDLE_TOKEN_FILE_ENV);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_bundle_token_missing_fails_closed() {
        let _guard = env_lock();
        std::env::remove_var(POLICY_BUNDLE_TOKEN_FILE_ENV);
        std::env::remove_var(POLICY_BUNDLE_TOKEN_ENV);
        assert!(load_bundle_token().is_err());
    }

    #[test]
    fn load_bundle_public_key_prefers_policy_bundle_path() {
        let _guard = env_lock();
        let key = generate_test_key();
        std::env::set_var(POLICY_BUNDLE_PUBLIC_KEY_PATH_ENV, &key.pub_path);
        std::env::remove_var(COSIGN_PUBLIC_KEY_PATH_ENV);
        let pem = load_bundle_public_key_pem().expect("pem");
        assert_eq!(pem, key.pub_pem);
        std::env::remove_var(POLICY_BUNDLE_PUBLIC_KEY_PATH_ENV);
    }

    #[test]
    fn verify_bundle_signature_round_trip() {
        let key = generate_test_key();
        let body = sample_bundle_v3();
        let sig = sign_body(&key.signing, body);
        verify_bundle_signature(&key.pub_pem, body, Some(&sig)).expect("ok");
    }

    #[test]
    fn verify_bundle_signature_missing() {
        let key = generate_test_key();
        let err = verify_bundle_signature(&key.pub_pem, sample_bundle_v3(), None).unwrap_err();
        assert!(err.to_string().contains("signature_missing"), "got {err}");
    }

    #[test]
    fn verify_bundle_signature_invalid() {
        let key = generate_test_key();
        let err = verify_bundle_signature(&key.pub_pem, sample_bundle_v3(), Some("YWJjZGVm"))
            .unwrap_err();
        assert!(err.to_string().contains("signature_invalid"), "got {err}");
    }

    #[test]
    fn verify_bundle_signature_tampered_body() {
        let key = generate_test_key();
        let body = sample_bundle_v3();
        let sig = sign_body(&key.signing, body);
        let tampered = body.replace("abad1dea", "deadbeef");
        let err = verify_bundle_signature(&key.pub_pem, &tampered, Some(&sig)).unwrap_err();
        assert!(err.to_string().contains("signature_invalid"), "got {err}");
    }

    #[tokio::test]
    async fn fetch_valid_token_returns_body_and_signature() {
        let key = generate_test_key();
        let body = sample_bundle_v3();
        let sig = sign_body(&key.signing, body);
        let (base, join) = spawn_stub(
            Some("good-token"),
            "HTTP/1.1 200 OK",
            body,
            Some(sig.clone()),
        );
        let client = reqwest::Client::new();
        let fetched = fetch_policy_bundle(&client, &base, "good-token")
            .await
            .expect("fetch");
        assert!(fetched.body.contains("deny_path_prefixes"));
        assert_eq!(fetched.signature_b64.as_deref(), Some(sig.as_str()));
        let (version, entries) = crate::path_deny::entries_from_bundle_json(&fetched.body).unwrap();
        assert_eq!(version, "sha256:abad1dea");
        assert_eq!(entries.len(), 3);
        join.join().unwrap();
    }

    #[tokio::test]
    async fn fetch_missing_token_rejected_no_unauthenticated_retry() {
        let (base, join) = spawn_stub(None, "HTTP/1.1 401 Unauthorized", "unauthorized", None);
        let client = reqwest::Client::new();
        let err = fetch_policy_bundle(&client, &base, "any-token")
            .await
            .expect_err("401");
        let msg = err.to_string();
        assert!(
            msg.contains("authentication rejected") && msg.contains("no unauthenticated retry"),
            "got {msg}"
        );
        join.join().unwrap();
    }

    #[tokio::test]
    async fn fetch_invalid_token_rejected() {
        let (base, join) = spawn_stub(
            Some("wrong"),
            "HTTP/1.1 401 Unauthorized",
            "unauthorized",
            None,
        );
        let client = reqwest::Client::new();
        let err = fetch_policy_bundle(&client, &base, "wrong")
            .await
            .expect_err("401");
        assert!(err.to_string().contains("authentication rejected"));
        join.join().unwrap();
    }

    #[tokio::test]
    async fn auth_rejection_retains_last_known_good_sync_state() {
        let (base, join) = spawn_stub(
            Some("expired-or-wrong"),
            "HTTP/1.1 401 Unauthorized",
            "unauthorized",
            None,
        );
        let client = reqwest::Client::new();
        let mut state = PolicySyncState::fresh("sha256:last-known-good");
        let version_before = state.last_version.clone();
        let success_before = state.last_success;

        let err = fetch_policy_bundle(&client, &base, "expired-or-wrong")
            .await
            .expect_err("401");
        assert!(
            err.to_string().contains("retaining last-known-good"),
            "got {err}"
        );
        assert_eq!(state.last_version, version_before);
        assert_eq!(state.last_success, success_before);
        assert!(!state.stale);
        state.refresh_stale_flag();
        assert!(
            !state.stale,
            "fresh last-known-good must not flip STALE on auth fail alone"
        );
        join.join().unwrap();
    }

    #[tokio::test]
    async fn fetch_empty_token_does_not_contact_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");
        let client = reqwest::Client::new();
        let err = fetch_policy_bundle(&client, &base, "")
            .await
            .expect_err("empty");
        assert!(err.to_string().contains("empty bearer"));
        assert!(listener.accept().is_err(), "must not open a connection");
    }

    #[tokio::test]
    async fn fetch_without_signature_header_yields_none() {
        let (base, join) = spawn_stub(
            Some("good-token"),
            "HTTP/1.1 200 OK",
            sample_bundle_v3(),
            None,
        );
        let client = reqwest::Client::new();
        let fetched = fetch_policy_bundle(&client, &base, "good-token")
            .await
            .expect("fetch");
        assert!(fetched.signature_b64.is_none());
        // sync_once → verify_bundle_signature still surfaces signature_missing;
        // fetch itself stays Ok so callers can dump response_header_names via the
        // tracing::error! diagnostic on the None path.
        join.join().unwrap();
    }
}
