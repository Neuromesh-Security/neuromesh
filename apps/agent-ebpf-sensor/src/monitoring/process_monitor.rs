//! Async RingBuf consumer for C `sys_enter_execve` ExecEvent v1 records.
//!
//! Hot path: AsyncFd poll → zero-copy `ExecEvent` decode → bounded MPSC try_send.
//! Worker task: correlation registration, OTel attribute export, detection pipeline fan-out.

use crate::monitoring::correlation::CorrelationEngine;
use crate::monitoring::event::ProcessEventHandler;
use crate::monitoring::exec_mapper::{
    exec_event_otel_attributes, exec_event_to_security_telemetry,
};
use crate::observability::metrics::AgentMetrics;
use anyhow::{Context, Result};
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use aya::Ebpf;
use neuromesh_common::{ExecEvent, SecurityTelemetryEvent};
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::sync::mpsc::error::TrySendError;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

pub const PROCESS_EVENTS_MAP: &str = "PROCESS_EVENTS";
pub const SYS_EXEC_PROGRAM: &str = "neuromesh_process_events";

/// Bounded queue between kernel RingBuf drain and user-space processing.
pub const DEFAULT_PROCESS_CHANNEL_CAPACITY: usize = 8192;
pub const PROCESS_PRESSURE_DROP_THRESHOLD_PCT: usize = 90;
const DROP_WARN_INTERVAL: u64 = 10_000;

/// Attach the C tracepoint, spawn an async RingBuf poller with backpressure, and return
/// the shared correlation engine for downstream network enrichment.
pub async fn start_process_monitor(
    bpf: &mut Ebpf,
    cancel: CancellationToken,
    metrics: Arc<AgentMetrics>,
    detection_tx: Option<tokio::sync::mpsc::Sender<SecurityTelemetryEvent>>,
) -> Result<Arc<CorrelationEngine>> {
    let program: &mut TracePoint = bpf
        .program_mut(SYS_EXEC_PROGRAM)
        .with_context(|| format!("eBPF program `{SYS_EXEC_PROGRAM}` missing from object file"))?
        .try_into()
        .context("failed to cast eBPF program to TracePoint")?;
    program
        .load()
        .context("kernel verifier rejected neuromesh_process_events tracepoint")?;
    program
        .attach("syscalls", "sys_enter_execve")
        .context("failed to attach sys_enter_execve tracepoint")?;

    let ring_buf =
        RingBuf::try_from(bpf.take_map(PROCESS_EVENTS_MAP).with_context(|| {
            format!("BPF map `{PROCESS_EVENTS_MAP}` missing from object file")
        })?)?;

    let channel_capacity = std::env::var("NEUROMESH_PROCESS_CHANNEL_CAPACITY")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_PROCESS_CHANNEL_CAPACITY);

    let correlation = CorrelationEngine::new();
    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<ExecEvent>(channel_capacity);

    let worker_correlation = Arc::clone(&correlation);
    let worker_metrics = Arc::clone(&metrics);
    let worker_cancel = cancel.clone();
    let detection_fanout = detection_tx.is_some();
    tokio::spawn(async move {
        let mut handler = ProcessEventHandler::default();
        loop {
            tokio::select! {
                _ = worker_cancel.cancelled() => {
                    info!(target: "neuromesh::process_monitor", "process monitor worker exiting");
                    break;
                }
                event = event_rx.recv() => {
                    match event {
                        Some(event) => {
                            worker_correlation.register_process(event.pid, &event.filename);
                            handler.observe(&event);

                            let otel = exec_event_otel_attributes(&event);
                            let pid = event.pid;
                            tracing::trace!(
                                target: "neuromesh::otel",
                                pid,
                                ?otel,
                                "exec visibility OTel attributes"
                            );

                            if let Some(ref tx) = detection_tx {
                                let telemetry = exec_event_to_security_telemetry(&event);
                                if tx.try_send(telemetry).is_err() {
                                    tracing::debug!(
                                        target: "neuromesh::process_monitor",
                                        pid,
                                        "detection pipeline channel full — exec telemetry dropped"
                                    );
                                }
                            }

                            worker_metrics.record_event_processed();
                        }
                        None => break,
                    }
                }
            }
        }
    });

    let mut async_ring = AsyncFd::new(ring_buf)?;
    let poller_metrics = Arc::clone(&metrics);
    let poller_cancel = cancel.clone();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = poller_cancel.cancelled() => {
                    drop(event_tx);
                    info!(target: "neuromesh::process_monitor", "process monitor poller exiting");
                    break;
                }
                poll_result = async_ring.async_io_mut(Interest::READABLE, |ring| {
                    while let Some(item) = ring.next() {
                        let bytes = item.as_ref();
                        let Some(event) = crate::monitoring::ringbuf_decode::decode_exec_event(bytes)
                        else {
                            continue;
                        };

                        match event_tx.try_send(event) {
                            Ok(()) => {}
                            Err(TrySendError::Full(_)) => {
                                poller_metrics.record_userspace_drop();
                                let total = poller_metrics.userspace_drops();
                                if total == 1 || total.is_multiple_of(DROP_WARN_INTERVAL) {
                                    warn!(
                                        target: "neuromesh::process_monitor",
                                        dropped = total,
                                        channel_capacity,
                                        pressure_threshold_pct = PROCESS_PRESSURE_DROP_THRESHOLD_PCT,
                                        "PROCESS_EVENTS backpressure: dropping execve events (user-space channel full)"
                                    );
                                }
                            }
                            Err(TrySendError::Closed(_)) => return Ok(()),
                        }
                    }
                    Ok(())
                }) => {
                    if let Err(error) = poll_result {
                        warn!(
                            target: "neuromesh::process_monitor",
                            error = %error,
                            "PROCESS_EVENTS ring buffer poll failed"
                        );
                    }
                }
            }
        }
    });

    info!(
        target: "neuromesh::process_monitor",
        channel_capacity,
        pressure_threshold_pct = PROCESS_PRESSURE_DROP_THRESHOLD_PCT,
        detection_fanout,
        "Process monitor armed on sys_enter_execve → PROCESS_EVENTS RingBuf (ExecEvent v1)"
    );

    Ok(correlation)
}
