use agent_ebpf_sensor::ingestion;
use agent_ebpf_sensor::monitoring::{start_network_monitor, start_process_monitor};
use agent_ebpf_sensor::observability::{
    spawn_health_monitor, spawn_metrics_server, AgentMetrics, RATE_LIMIT_DROPS_MAP,
};
use agent_ebpf_sensor::pipeline::TelemetryPipeline;
use agent_ebpf_sensor::rules::RuleEngine;
use agent_ebpf_sensor::telemetry_stream::{self, TelemetryStreamHandle};
use agent_ebpf_sensor::wasm_policy::WasmPolicyEngine;
use agent_ebpf_sensor::{load_with_map_pinning, pin_root, wait_for_shutdown_signal};
use anyhow::Context;
use aya::maps::{Array, MapData, PerCpuArray, RingBuf};
use aya::programs::Lsm;
use aya::{Btf, Ebpf};
use log::info;
use neuromesh_common::{SecurityTelemetryEvent, TelemetryHealthStats, TELEMETRY_STATS_INDEX};
use std::ptr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio_util::sync::CancellationToken;

const SYS_EXEC_BPF: &[u8] = include_bytes!("../target/bpf/sys_exec.bpf.o");
const NETWORK_FILTER_BPF: &[u8] = include_bytes!("../target/bpf/network_filter.bpf.o");

/// Drain window for monitor tasks after cancellation before dropping BPF links.
const SHUTDOWN_DRAIN_MS: u64 = 500;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    env_logger::init();

    info!("🚀 [Neuromesh] Initializing Enterprise Agent...");

    let shutdown = CancellationToken::new();

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

    let correlation_ingestion = ingestion::spawn_from_env().await;

    let bpf_pin_root = pin_root();
    let mut process_bpf = load_with_map_pinning(SYS_EXEC_BPF, &bpf_pin_root)?;

    let metrics = AgentMetrics::new()?;
    let rate_limit_drops = PerCpuArray::try_from(
        process_bpf
            .take_map(RATE_LIMIT_DROPS_MAP)
            .with_context(|| format!("BPF map `{RATE_LIMIT_DROPS_MAP}` missing from object file"))?,
    )?;

    let correlation = start_process_monitor(&mut process_bpf, shutdown.clone(), Arc::clone(&metrics)).await?;

    spawn_health_monitor(rate_limit_drops, Arc::clone(&metrics), shutdown.clone());
    spawn_metrics_server(Arc::clone(&metrics), shutdown.clone()).await?;

    let mut network_bpf = Ebpf::load(NETWORK_FILTER_BPF)?;
    start_network_monitor(
        &mut network_bpf,
        Arc::clone(&correlation),
        correlation_ingestion,
        shutdown.clone(),
    )
    .await?;

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
    info!("🔗 Lock-free correlation engine armed (DashMap PID → process name).");
    info!("📨 Correlation Kafka ingestion armed (bounded MPSC → idempotent rdkafka).");
    info!("🛡️ XDR enforcement armed. LSM bprm_check_security active blocking enabled.");
    info!("⚡ Detection brain armed. RuleEngine + DataNormalizer active on LSM RingBuf stream...");
    info!(
        "📌 eBPF map pinning active under {} (PROCESS_EVENTS, RATE_LIMIT_BUCKET)",
        bpf_pin_root.display()
    );
    info!("📈 Prometheus /metrics exporter armed (default port 9090, override via NEUROMESH_METRICS_PORT)");
    info!("🩺 Health monitor armed (kernel RATE_LIMIT_DROPS + user-space channel backpressure)");
    if std::env::var("NEUROMESH_KAFKA_BROKERS").is_ok() {
        info!("📡 Kafka Slow Path armed (topic: neuromesh.telemetry.v1)");
    } else {
        info!("📡 Kafka Slow Path disabled (set NEUROMESH_KAFKA_BROKERS to enable)");
    }

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
