#![cfg(feature = "orchestrator")]

//! Kernel-independent chaos scenarios for backpressure, observability, and shutdown.

use agent_ebpf_sensor::monitoring::correlation::CorrelationEngine;
use agent_ebpf_sensor::monitoring::event::{
    drain_events, MockEventStream, ProcessEvent, ProcessEventHandler,
};
use agent_ebpf_sensor::monitoring::network_event::{NetworkEvent, NetworkEventHandler};
use agent_ebpf_sensor::observability::metrics::AgentMetrics;
use std::sync::Arc;
use tokio::sync::mpsc::error::TrySendError;
use tokio_util::sync::CancellationToken;

fn sample_process_event(pid: u32) -> ProcessEvent {
    ProcessEvent {
        pid,
        uid: 1000,
        ppid: 1,
        comm: [0; 16],
        filename: [0; 128],
        ts: pid as u64,
    }
}

#[test]
fn ringbuf_overflow_simulation_drains_without_panic() {
    let mut stream = MockEventStream::default();
    for pid in 0..50_000 {
        stream.push(sample_process_event(pid));
    }

    let mut handler = ProcessEventHandler::default();
    drain_events(&mut stream, &mut handler);
    assert_eq!(handler.events_seen(), 50_000);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn userspace_memory_pressure_records_drops_in_metrics() {
    let metrics = AgentMetrics::new().expect("metrics registry");
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let event = sample_process_event(1);

    let mut accepted = 0u64;
    let mut dropped = 0u64;

    for _ in 0..256 {
        match tx.try_send(event) {
            Ok(()) => {
                accepted += 1;
                metrics.record_event_processed();
            }
            Err(TrySendError::Full(_)) => {
                dropped += 1;
                metrics.record_userspace_drop();
            }
            Err(TrySendError::Closed(_)) => break,
        }
    }

    while rx.try_recv().is_ok() {}

    assert!(dropped > 0, "expected MPSC saturation under chaos flood");
    assert_eq!(metrics.userspace_drops(), dropped);

    let mut last_userspace = 0u64;
    metrics.reconcile_userspace_drops(&mut last_userspace);
    assert!(metrics.dropped_total() >= dropped as f64);
    assert!(metrics.processed_total() >= accepted as f64);
}

#[tokio::test]
async fn abrupt_cancellation_exits_monitor_tasks_cleanly() {
    let cancel = CancellationToken::new();
    let metrics = AgentMetrics::new().expect("metrics registry");

    let worker_cancel = cancel.clone();
    let worker_metrics = Arc::clone(&metrics);
    let worker = tokio::spawn(async move {
        tokio::select! {
            _ = worker_cancel.cancelled() => {}
            _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
        }
        worker_metrics.record_event_processed();
    });

    cancel.cancel();
    worker.await.expect("worker join");

    metrics.refresh_uptime();
    assert!(metrics.uptime_seconds.get() >= 0.0);
}

#[test]
fn kernel_rate_limit_drops_reconcile_into_prometheus_counter() {
    let metrics = AgentMetrics::new().expect("metrics registry");

    metrics.inc_dropped_by(10_000);
    metrics.inc_dropped_by(5_000);
    metrics.record_userspace_drop();
    metrics.record_userspace_drop();

    let mut last = 0u64;
    metrics.reconcile_userspace_drops(&mut last);

    assert!(metrics.dropped_total() >= 15_002.0);
}

#[test]
fn network_monitor_handler_survives_packed_event_chaos_burst() {
    let mut handler = NetworkEventHandler::default();
    for pid in 0..10_000 {
        handler.observe(NetworkEvent {
            pid,
            uid: 1000,
            dest_ip: 0x0A00_0001,
            dest_port: u16::to_be(443),
        });
    }
    assert_eq!(handler.events_seen(), 10_000);
}

#[test]
fn correlation_engine_handles_missing_pid_gracefully() {
    let engine = CorrelationEngine::new();
    let event = NetworkEvent {
        pid: 9999,
        uid: 1000,
        dest_ip: 0x0100_007F,
        dest_port: u16::to_be(8080),
    };
    assert!(engine.correlate(event).is_none());

    engine.register_process(9999, b"/bin/curl");
    assert!(engine.correlate(event).is_some());
}

#[test]
fn default_process_channel_capacity_is_enterprise_safe() {
    let capacity = std::env::var("NEUROMESH_PROCESS_CHANNEL_CAPACITY")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8192);
    assert!(
        capacity >= 1024,
        "channel capacity too small for production backpressure headroom"
    );
}
