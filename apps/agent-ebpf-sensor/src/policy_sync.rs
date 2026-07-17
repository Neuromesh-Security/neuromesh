//! Periodic sync of the path-prefix deny list from zt-policy-engine.
//!
//! Fail-closed contract:
//! - Bootstrap (pre-attach) seeds the BPF maps with the historical hardcoded set.
//! - Sync failure leaves last-known-good map contents untouched.
//! - Staleness (> [`path_deny::POLICY_STALE_AFTER`]) is logged/metric'd but never
//!   disables enforcement.

use crate::path_deny::{
    self, apply_deny_entries, PathDenyMaps, PolicySyncState, POLICY_STALE_AFTER,
    POLICY_SYNC_INTERVAL,
};
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

/// Environment variable for the policy-engine base URL (e.g. `http://127.0.0.1:8080`).
pub const POLICY_ENGINE_URL_ENV: &str = "NEUROMESH_ZT_POLICY_ENGINE_URL";

/// Fetch + apply one policy bundle. On any error, maps are left unchanged.
pub async fn sync_once(
    client: &reqwest::Client,
    base_url: &str,
    maps: &mut PathDenyMaps,
    state: &mut PolicySyncState,
) -> Result<()> {
    let url = format!("{}/v1/policy-bundle", base_url.trim_end_matches('/'));
    let response = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .with_context(|| format!("GET {url} failed"))?;

    if !response.status().is_success() {
        anyhow::bail!("GET {url} returned HTTP {}", response.status());
    }

    let body = response
        .text()
        .await
        .context("failed to read policy-bundle body")?;
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
                // Still tick STALE? Bootstrap never goes stale if sync is intentionally off.
                // Keep last_success refreshed so we don't falsely alarm.
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
            "path-prefix deny-list sync armed"
        );

        let mut interval = tokio::time::interval(POLICY_SYNC_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = interval.tick() => {
                    let mut maps_guard = maps.lock().await;
                    match sync_once(&client, &base_url, &mut maps_guard, &mut state).await {
                        Ok(()) => {}
                        Err(error) => {
                            // Retain last-known-good — do not clear maps.
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
