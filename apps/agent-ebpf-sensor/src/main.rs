use agent_ebpf_sensor::monitoring::{start_network_monitor, start_process_monitor};
use agent_ebpf_sensor::pipeline::TelemetryPipeline;
use agent_ebpf_sensor::rules::RuleEngine;
use agent_ebpf_sensor::telemetry_stream::{self, TelemetryStreamHandle};
use agent_ebpf_sensor::wasm_policy::WasmPolicyEngine;
use aya::maps::{Array, MapData, RingBuf};
use aya::programs::Lsm;
use aya::{Btf, Ebpf};
use log::info;
use neuromesh_common::{SecurityTelemetryEvent, TelemetryHealthStats, TELEMETRY_STATS_INDEX};
use std::ptr;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

const SYS_EXEC_BPF: &[u8] = include_bytes!("../target/bpf/sys_exec.bpf.o");
const NETWORK_FILTER_BPF: &[u8] = include_bytes!("../target/bpf/network_filter.bpf.o");

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    env_logger::init();

    info!("🚀 [Neuromesh] Initializing Enterprise Agent...");

    let enforcement_bpf_data =
        include_bytes!("../ebpf/target/bpfel-unknown-none/release/agent-ebpf-sensor-ebpf");

    let mut enforcement_bpf = Ebpf::load(enforcement_bpf_data)?;

    let btf = Btf::from_sys_fs()?;
    let lsm_program: &mut Lsm = enforcement_bpf
        .program_mut("neuromesh_lsm_exec_guard")
        .ok_or_else(|| anyhow::anyhow!("neuromesh_lsm_exec_guard program missing"))?
        .try_into()?;
    lsm_program.load("bprm_check_security", &btf)?;
    lsm_program.attach()?;

    let mut process_bpf = Ebpf::load(SYS_EXEC_BPF)?;
    start_process_monitor(&mut process_bpf).await?;

    let mut network_bpf = Ebpf::load(NETWORK_FILTER_BPF)?;
    start_network_monitor(&mut network_bpf).await?;

    let stats_map = Array::try_from(
        enforcement_bpf
            .take_map("TELEMETRY_STATS")
            .ok_or_else(|| anyhow::anyhow!("TELEMETRY_STATS map missing from eBPF object"))?,
    )?;
    let telemetry_map = RingBuf::try_from(
        enforcement_bpf
            .take_map("TELEMETRY_RINGBUF")
            .ok_or_else(|| anyhow::anyhow!("TELEMETRY_RINGBUF map missing from eBPF object"))?,
    )?;
    let mut async_ring = AsyncFd::new(telemetry_map)?;
    let mut pipeline = TelemetryPipeline::new();
    let telemetry_stream = telemetry_stream::spawn_from_env().await;
    let _wasm_policy = WasmPolicyEngine::new();

    info!("👁️ Process visibility armed via sys_enter_execve tracepoint.");
    info!("🌐 Network visibility armed via tcp_connect kprobe.");
    info!("🛡️ XDR enforcement armed. LSM bprm_check_security active blocking enabled.");
    info!("⚡ Detection brain armed. RuleEngine + DataNormalizer active on LSM RingBuf stream...");
    if std::env::var("NEUROMESH_KAFKA_BROKERS").is_ok() {
        info!("📡 Kafka Slow Path armed (topic: neuromesh.telemetry.v1)");
    } else {
        info!("📡 Kafka Slow Path disabled (set NEUROMESH_KAFKA_BROKERS to enable)");
    }

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
                    if let Err(error) =
                        emit_pipeline_output(&mut pipeline, &telemetry_stream, &event)
                    {
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
