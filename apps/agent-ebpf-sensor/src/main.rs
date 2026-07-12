use agent_ebpf_sensor::pipeline::TelemetryPipeline;
use agent_ebpf_sensor::rules::RuleEngine;
use agent_ebpf_sensor::wasm_policy::WasmPolicyEngine;
use aya::maps::{Array, MapData, RingBuf};
use aya::programs::{Lsm, TracePoint};
use aya::{Btf, Ebpf};
use log::info;
use neuromesh_common::{SecurityTelemetryEvent, TelemetryHealthStats, TELEMETRY_STATS_INDEX};
use std::ptr;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    info!("🚀 [Neuromesh] Initializing Enterprise Agent...");

    let bpf_data =
        include_bytes!("../ebpf/target/bpfel-unknown-none/release/agent-ebpf-sensor-ebpf");

    let mut ebpf = Ebpf::load(bpf_data)?;

    let program: &mut TracePoint = ebpf
        .program_mut("neuromesh_exec_hook")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

    let btf = Btf::from_sys_fs()?;
    let lsm_program: &mut Lsm = ebpf
        .program_mut("neuromesh_lsm_exec_guard")
        .unwrap()
        .try_into()?;
    lsm_program.load("bprm_check_security", &btf)?;
    lsm_program.attach()?;

    let stats_map = Array::try_from(
        ebpf.take_map("TELEMETRY_STATS")
            .ok_or_else(|| anyhow::anyhow!("TELEMETRY_STATS map missing from eBPF object"))?,
    )?;
    let telemetry_map = RingBuf::try_from(
        ebpf.take_map("TELEMETRY_RINGBUF")
            .ok_or_else(|| anyhow::anyhow!("TELEMETRY_RINGBUF map missing from eBPF object"))?,
    )?;
    let mut async_ring = AsyncFd::new(telemetry_map)?;
    let mut pipeline = TelemetryPipeline::new();
    let _wasm_policy = WasmPolicyEngine::new();

    info!("🛡️ XDR enforcement armed. LSM bprm_check_security active blocking enabled.");
    info!("⚡ Detection brain armed. RuleEngine + DataNormalizer active on RingBuf stream...");

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
                    if let Err(error) = emit_pipeline_output(&mut pipeline, &event) {
                        log::warn!("telemetry pipeline failed: {error}");
                    }
                }
                Ok(())
            }) => {
                result?;
            }
        }
    }
}

fn emit_pipeline_output(
    pipeline: &mut TelemetryPipeline,
    event: &SecurityTelemetryEvent,
) -> Result<(), anyhow::Error> {
    let output = pipeline.process(event);

    for alert in output.behavior_alerts {
        println!("{}", serde_json::to_string(&alert)?);
    }

    for alert in output.siem_alerts {
        println!("{}", RuleEngine::format_json(&alert)?);
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
