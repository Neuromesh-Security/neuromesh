//! Periodic health sampling of kernel drop counters and user-space backpressure.

use crate::observability::metrics::AgentMetrics;
use anyhow::{Context, Result};
use aya::maps::{MapData, PerCpuArray};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::info;

const DEFAULT_HEALTH_INTERVAL_SECS: u64 = 5;

/// Sum per-CPU `RATE_LIMIT_DROPS` counters for global execve drop visibility.
pub fn sum_rate_limit_drops(map: &PerCpuArray<MapData, u64>) -> Result<u64> {
    const RATE_LIMIT_KEY: u32 = 0;
    let values = map
        .get(&RATE_LIMIT_KEY, 0)
        .context("failed to read RATE_LIMIT_DROPS per-CPU values")?;
    Ok(values.iter().copied().sum())
}

/// Spawn a Tokio task that samples kernel and user-space drop counters every 5 seconds.
pub fn spawn_health_monitor(
    rate_limit_drops: PerCpuArray<MapData, u64>,
    metrics: Arc<AgentMetrics>,
    cancel: CancellationToken,
) {
    let interval_secs = std::env::var("NEUROMESH_HEALTH_INTERVAL_SECS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_HEALTH_INTERVAL_SECS);

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
        ticker.tick().await;

        let mut last_kernel_drops = 0u64;
        let mut last_userspace_drops = 0u64;

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!(target: "neuromesh::health", "health monitor exiting");
                    break;
                }
                _ = ticker.tick() => {
                    match sum_rate_limit_drops(&rate_limit_drops) {
                        Ok(kernel_total) => {
                            let kernel_delta = kernel_total.saturating_sub(last_kernel_drops);
                            last_kernel_drops = kernel_total;
                            metrics.inc_dropped_by(kernel_delta);
                        }
                        Err(error) => {
                            tracing::warn!(
                                target: "neuromesh::health",
                                error = %error,
                                "failed to sample RATE_LIMIT_DROPS map"
                            );
                        }
                    }

                    metrics.reconcile_userspace_drops(&mut last_userspace_drops);
                    metrics.refresh_uptime();

                    info!(
                        target: "neuromesh::health",
                        interval_secs,
                        kernel_rate_limit_drops = last_kernel_drops,
                        userspace_channel_drops = metrics.userspace_drops(),
                        events_processed = metrics.processed_total(),
                        events_dropped = metrics.dropped_total(),
                        uptime_seconds = metrics.uptime_seconds.get(),
                        "agent health sample"
                    );
                }
            }
        }
    });
}
