//! Graceful shutdown signal handling for the orchestrator.

use anyhow::{Context, Result};

/// Wait for SIGINT (Ctrl+C) or SIGTERM before initiating agent shutdown.
pub async fn wait_for_shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm =
            signal(SignalKind::terminate()).context("failed to install SIGTERM handler")?;

        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.context("failed to await SIGINT")?;
                tracing::info!(target: "neuromesh::shutdown", "received SIGINT");
            }
            _ = sigterm.recv() => {
                tracing::info!(target: "neuromesh::shutdown", "received SIGTERM");
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("failed to await SIGINT")?;
        tracing::info!(target: "neuromesh::shutdown", "received shutdown signal");
    }

    Ok(())
}
