mod rules;

use aya::maps::{Array, MapData, RingBuf};
use aya::programs::TracePoint;
use aya::Ebpf;
use log::info;
use neuromesh_common::{SecurityTelemetryEvent, TelemetryHealthStats, TELEMETRY_STATS_INDEX};
use rules::{RuleEngine, RuleVerdict};
use std::ptr;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    info!("🚀 [Neuromesh] Initializing Enterprise Agent...");

    #[cfg(debug_assertions)]
    let bpf_data = include_bytes!("../ebpf/target/bpfel-unknown-none/debug/agent-ebpf-sensor-ebpf");
    #[cfg(not(debug_assertions))]
    let bpf_data =
        include_bytes!("../ebpf/target/bpfel-unknown-none/release/agent-ebpf-sensor-ebpf");

    let mut ebpf = Ebpf::load(bpf_data)?;

    let program: &mut TracePoint = ebpf
        .program_mut("neuromesh_exec_hook")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

    let stats_map = Array::try_from(
        ebpf.take_map("TELEMETRY_STATS")
            .ok_or_else(|| anyhow::anyhow!("TELEMETRY_STATS map missing from eBPF object"))?,
    )?;
    let telemetry_map = RingBuf::try_from(
        ebpf.take_map("TELEMETRY_RINGBUF")
            .ok_or_else(|| anyhow::anyhow!("TELEMETRY_RINGBUF map missing from eBPF object"))?,
    )?;
    let mut async_ring = AsyncFd::new(telemetry_map)?;
    let rule_engine = RuleEngine::new();

    info!("⚡ Detection brain armed. RuleEngine active on RingBuf stream...");

    let mut stats_interval = tokio::time::interval(Duration::from_secs(5));
    stats_interval.tick().await;

    loop {
        tokio::select! {
            _ = stats_interval.tick() => {
                log_health_metrics(&stats_map)?;
            }
            result = async_ring.async_io_mut(Interest::READABLE, |ring| {
                while let Some(item) = ring.next() {
                    let event = unsafe {
                        ptr::read_unaligned(item.as_ptr() as *const SecurityTelemetryEvent)
                    };
                    if let Err(error) = process_telemetry_event(&rule_engine, &event) {
                        log::warn!("telemetry rule evaluation failed: {error}");
                    }
                }
                Ok(())
            }) => {
                result?;
            }
        }
    }
}

fn process_telemetry_event(
    rule_engine: &RuleEngine,
    event: &SecurityTelemetryEvent,
) -> Result<(), anyhow::Error> {
    match rule_engine.evaluate(event) {
        RuleVerdict::Suppressed => {}
        RuleVerdict::Alert(alert) => {
            let json = RuleEngine::format_json(&alert)?;
            println!("{json}");
        }
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
