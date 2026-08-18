//! Runtime select loop: shutdown, health stats, enforcement ringbuf, visibility pipeline.
//!
//! Drain window for monitor tasks after cancellation before dropping BPF links.

use crate::visibility::AgentRuntime;
use agent_ebpf_sensor::monitoring::exec_event_to_security_telemetry;
use agent_ebpf_sensor::monitoring::ringbuf_decode::decode_exec_event;
use agent_ebpf_sensor::pipeline::TelemetryPipeline;
use agent_ebpf_sensor::rules::RuleEngine;
use agent_ebpf_sensor::telemetry_stream::TelemetryStreamHandle;
use agent_ebpf_sensor::wait_for_shutdown_signal;
use aya::maps::{Array, MapData};
use log::info;
use neuromesh_common::{SecurityTelemetryEvent, TelemetryHealthStats, TELEMETRY_STATS_INDEX};
use std::time::Duration;
use tokio::io::Interest;

const SHUTDOWN_DRAIN_MS: u64 = 500;

pub async fn run(runtime: AgentRuntime) -> Result<(), anyhow::Error> {
    let AgentRuntime {
        shutdown,
        mut async_ring,
        stats_map,
        mut pipeline,
        telemetry_stream,
        mut detection_rx,
        _wasm_policy,
        _process_bpf,
        _network_bpf,
        _enforcement_bpf,
        _integrity,
        _lsm_link_pin,
        _policy_sync,
        _correlator,
        bpf_pin_root: _,
    } = runtime;

    let mut stats_interval = tokio::time::interval(Duration::from_secs(5));
    stats_interval.tick().await;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                tracing::info!(target: "neuromesh::shutdown", "shutdown token cancelled");
                break;
            }
            result = wait_for_shutdown_signal() => {
                result?;
                tracing::info!(target: "neuromesh::shutdown", "initiating graceful shutdown");
                shutdown.cancel();
                break;
            }
            _ = stats_interval.tick() => {
                log_health_metrics(&stats_map)?;
            }
            // aya RingBuf + Tokio AsyncFd: empty drain MUST return WouldBlock so
            // readiness is cleared (Issue #103). See monitoring::ringbuf_async_io.
            result = async_ring.async_io_mut(Interest::READABLE, |ring| {
                let mut drained_any = false;
                while let Some(item) = ring.next() {
                    drained_any = true;
                    let bytes = item.as_ref();
                    let Some(exec) = decode_exec_event(bytes) else {
                        continue;
                    };
                    let event = exec_event_to_security_telemetry(&exec);
                    if let Err(error) =
                        emit_pipeline_output(&mut pipeline, &telemetry_stream, &event)
                    {
                        log::warn!("telemetry pipeline failed: {error}");
                    }
                }
                agent_ebpf_sensor::monitoring::ringbuf_drain_outcome(drained_any)
            }) => {
                result?;
            }
            Some(visibility) = detection_rx.recv() => {
                if let Err(error) =
                    emit_pipeline_output(&mut pipeline, &telemetry_stream, &visibility)
                {
                    log::warn!("visibility pipeline failed: {error}");
                }
            }
        }
    }

    tokio::time::sleep(Duration::from_millis(SHUTDOWN_DRAIN_MS)).await;
    tracing::info!(
        target: "neuromesh::shutdown",
        drain_ms = SHUTDOWN_DRAIN_MS,
        "graceful shutdown complete — BPF links released"
    );

    Ok(())
}

fn emit_pipeline_output(
    pipeline: &mut TelemetryPipeline,
    telemetry_stream: &TelemetryStreamHandle,
    event: &SecurityTelemetryEvent,
) -> Result<(), anyhow::Error> {
    let output = pipeline.process(event);

    for alert in output.behavior_alerts {
        println!("{}", serde_json::to_string(&alert)?);
        telemetry_stream.try_enqueue_behavior(alert);
    }

    for alert in output.siem_alerts {
        println!("{}", RuleEngine::format_json(&alert)?);
        telemetry_stream.try_enqueue_critical(alert);
    }

    Ok(())
}

fn log_health_metrics(
    stats_map: &Array<MapData, TelemetryHealthStats>,
) -> Result<(), anyhow::Error> {
    let stats = stats_map.get(&TELEMETRY_STATS_INDEX, 0)?;
    println!(
        "📊 Telemetry Health | events_processed={} lost_events_count={}",
        stats.events_processed, stats.lost_events_count
    );
    info!(
        "📊 Telemetry Health | events_processed={} lost_events_count={}",
        stats.events_processed, stats.lost_events_count
    );
    Ok(())
}
