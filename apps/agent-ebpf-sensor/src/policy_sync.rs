//! Periodic sync of the path-prefix deny list from zt-policy-engine.
//!
//! Fail-closed contract:
//! - Bootstrap (pre-attach) seeds the BPF maps with the historical hardcoded set.
//! - Sync failure leaves last-known-good map contents untouched.
//! - Staleness (> [`path_deny::POLICY_STALE_AFTER`]) is logged/metric'd but never
//!   disables enforcement.
//! - Auth failure (Issue #55) is a sync failure: no unauthenticated retry, maps
//!   unchanged (same STALE / last-known-good path as network errors).

use crate::path_deny::{
    self, apply_deny_entries, PathDenyMaps, PolicySyncState, POLICY_STALE_AFTER,
    POLICY_SYNC_INTERVAL,
};
use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

/// Environment variable for the policy-engine base URL (e.g. `http://127.0.0.1:8080`).
pub const POLICY_ENGINE_URL_ENV: &str = "NEUROMESH_ZT_POLICY_ENGINE_URL";

/// Shared bearer token for `GET /v1/policy-bundle` (Issue #55). Prefer the file form.
pub const POLICY_BUNDLE_TOKEN_ENV: &str = "NEUROMESH_POLICY_BUNDLE_TOKEN";

/// Absolute path to a file containing the shared bearer token (Secret mount).
pub const POLICY_BUNDLE_TOKEN_FILE_ENV: &str = "NEUROMESH_POLICY_BUNDLE_TOKEN_FILE";

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

/// Authenticated GET of the raw policy-bundle body.
///
/// Always sends `Authorization: Bearer …`. Never falls back to an unauthenticated GET.
pub async fn fetch_policy_bundle(
    client: &reqwest::Client,
    base_url: &str,
    bearer_token: &str,
) -> Result<String> {
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
            "GET {url} authentication rejected (HTTP {status}) — retaining last-known-good \
             (no unauthenticated retry)"
        );
    }
    if !status.is_success() {
        bail!("GET {url} returned HTTP {status}");
    }

    response
        .text()
        .await
        .context("failed to read policy-bundle body")
}

/// Fetch + apply one policy bundle. On any error, maps are left unchanged.
pub async fn sync_once(
    client: &reqwest::Client,
    base_url: &str,
    bearer_token: &str,
    maps: &mut PathDenyMaps,
    state: &mut PolicySyncState,
) -> Result<()> {
    let body = fetch_policy_bundle(client, base_url, bearer_token).await?;
    let (version, entries) = path_deny::entries_from_bundle_json(&body)?;

    if version == state.last_version {
        state.mark_success(version);
        tracing::debug!(
            target: "neuromesh::policy_sync",
            version = %state.last_version,
            "policy bundle unchanged"
        );
        return Ok(());
    }

    apply_deny_entries(maps, &entries).context("failed to apply policy bundle to BPF maps")?;
    state.mark_success(version);
    tracing::info!(
        target: "neuromesh::policy_sync",
        version = %state.last_version,
        prefixes = entries.len(),
        "applied path-prefix deny list from zt-policy-engine"
    );
    Ok(())
}

/// Spawn the background sync loop. Errors are logged; maps keep last-known-good.
pub fn spawn_policy_sync(
    maps: PathDenyMaps,
    mut state: PolicySyncState,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    let maps = Arc::new(Mutex::new(maps));
    tokio::spawn(async move {
        let base_url = match std::env::var(POLICY_ENGINE_URL_ENV) {
            Ok(url) if !url.is_empty() => url,
            _ => {
                tracing::info!(
                    target: "neuromesh::policy_sync",
                    "NEUROMESH_ZT_POLICY_ENGINE_URL unset — policy sync disabled; \
                     enforcing bootstrap deny list only"
                );
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
            "path-prefix deny-list sync armed (authenticated)"
        );

        let mut interval = tokio::time::interval(POLICY_SYNC_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = interval.tick() => {
                    let mut maps_guard = maps.lock().await;
                    match sync_once(
                        &client,
                        &base_url,
                        &bearer_token,
                        &mut maps_guard,
                        &mut state,
                    )
                    .await
                    {
                        Ok(()) => {}
                        Err(error) => {
                            // Retain last-known-good — do not clear maps.
                            // Auth rejection is handled identically to network failure.
                            state.refresh_stale_flag();
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
                        }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Mutex;
    use std::thread;

    /// Serialize env-mutating tests (process-global env).
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    fn spawn_stub(
        expect_bearer: Option<&'static str>,
        status_line: &'static str,
        body: &'static str,
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
            let resp = format!(
                "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
        });
        (format!("http://{addr}"), handle)
    }

    fn sample_bundle() -> &'static str {
        r#"{"schema_version":1,"version":"sha256:abad1dea","deny_path_prefixes":["/tmp/","/dev/shm/","/var/tmp/"]}"#
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

    #[tokio::test]
    async fn fetch_valid_token_returns_body() {
        let (base, join) = spawn_stub(Some("good-token"), "HTTP/1.1 200 OK", sample_bundle());
        let client = reqwest::Client::new();
        let body = fetch_policy_bundle(&client, &base, "good-token")
            .await
            .expect("fetch");
        assert!(body.contains("deny_path_prefixes"));
        let (version, entries) = path_deny::entries_from_bundle_json(&body).unwrap();
        assert_eq!(version, "sha256:abad1dea");
        assert_eq!(entries.len(), 3);
        join.join().unwrap();
    }

    #[tokio::test]
    async fn fetch_missing_token_rejected_no_unauthenticated_retry() {
        let (base, join) = spawn_stub(None, "HTTP/1.1 401 Unauthorized", "unauthorized");
        let client = reqwest::Client::new();
        // Send a token the stub ignores for body; server returns 401.
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
        let (base, join) = spawn_stub(Some("wrong"), "HTTP/1.1 401 Unauthorized", "unauthorized");
        let client = reqwest::Client::new();
        let err = fetch_policy_bundle(&client, &base, "wrong")
            .await
            .expect_err("401");
        assert!(err.to_string().contains("authentication rejected"));
        join.join().unwrap();
    }

    /// Auth rejection is a sync failure: last-known-good version/state must not advance
    /// (same contract as network errors — sync_once returns before apply/mark_success).
    #[tokio::test]
    async fn auth_rejection_retains_last_known_good_sync_state() {
        let (base, join) = spawn_stub(
            Some("expired-or-wrong"),
            "HTTP/1.1 401 Unauthorized",
            "unauthorized",
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
        // Mirror sync_once: on Err, do not call mark_success / apply_deny_entries.
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
}
