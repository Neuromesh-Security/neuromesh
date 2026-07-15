//! Kernel-independent chaos scenarios for backpressure, observability, and shutdown.

use agent_ebpf_sensor::monitoring::correlation::CorrelationEngine;
use agent_ebpf_sensor::monitoring::event::{
    drain_events, MockEventStream, ProcessEvent, ProcessEventHandler,
};
use agent_ebpf_sensor::monitoring::network_event::{NetworkEvent, NetworkEventHandler};
use agent_ebpf_sensor::observability::metrics::AgentMetrics;
use neuromesh_common::{
    ExecEvent, EXEC_EVENT_SCHEMA_VERSION, EXEC_EVENT_STRUCT_SIZE, EXEC_EVENT_TYPE_EXECVE,
    MAX_COMM_LEN, MAX_CONTAINER_ID_LEN, MAX_FILENAME_LEN,
};
use tokio::sync::mpsc::error::TrySendError;
use tokio_util::sync::CancellationToken;

fn sample_process_event(pid: u32) -> ProcessEvent {
    ExecEvent {
        schema_version: EXEC_EVENT_SCHEMA_VERSION,
        event_type: EXEC_EVENT_TYPE_EXECVE,
        flags: 0,
        struct_size: EXEC_EVENT_STRUCT_SIZE,
        header_reserved: 0,
        header_pad: [0; 8],
        pid,
        ppid: 1,
        tgid: pid,
        uid: 1000,
        euid: 1000,
        gid: 1000,
        comm: [0; MAX_COMM_LEN],
        filename: {
            let mut path = [0u8; MAX_FILENAME_LEN];
            path[..9].copy_from_slice(b"/bin/true");
            path
        },
        args_count: 1,
        container_id: [0; MAX_CONTAINER_ID_LEN],
        align_pad: [0; 4],
        namespace_id: 1,
        timestamp_ns: pid as u64,
        enforcement_action: 0,
        capture_status: 0,
        status_reserved: [0; 5],
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

    let mut last_seen = 0u64;
    metrics.reconcile_userspace_drops(&mut last_seen);
    assert!(accepted > 0);
    assert!(dropped > 0);
    assert_eq!(metrics.userspace_drops(), dropped);

    // Drop the sender so the drain loop below observes channel closure
    // instead of blocking forever waiting for more sends.
    drop(tx);
    while rx.recv().await.is_some() {}
}

#[test]
fn correlation_engine_survives_high_cardinality_exec_storm() {
    let engine = CorrelationEngine::new();
    // pid 0 is reserved (kernel scheduler) and intentionally ignored by
    // `register_process` — see `register_process_ignores_zero_pid`.
    for pid in 1..=10_000 {
        let event = sample_process_event(pid);
        engine.register_process(event.pid, &event.filename);
    }
    assert_eq!(engine.process_count(), 10_000);

    let network = NetworkEvent {
        pid: 9999,
        uid: 1000,
        dest_ip: u32::from_be_bytes([8, 8, 8, 8]),
        dest_port: 443u16.to_be(),
    };
    assert!(engine.correlate(network).is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_token_drains_inflight_events_without_panic() {
    let cancel = CancellationToken::new();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<ProcessEvent>(128);
    let worker_cancel = cancel.clone();

    let worker = tokio::spawn(async move {
        let mut handler = ProcessEventHandler::default();
        loop {
            tokio::select! {
                _ = worker_cancel.cancelled() => break,
                event = rx.recv() => {
                    if let Some(event) = event {
                        handler.observe(&event);
                    } else {
                        break;
                    }
                }
            }
        }
        handler.events_seen()
    });

    for pid in 0..1024 {
        let _ = tx.send(sample_process_event(pid)).await;
    }
    cancel.cancel();
    drop(tx);

    let seen = worker.await.expect("worker join");
    assert!(seen > 0);
}

#[test]
fn network_handler_survives_burst_without_panic() {
    let mut handler = NetworkEventHandler::default();
    for pid in 0..10_000 {
        handler.observe(NetworkEvent {
            pid,
            uid: 1000,
            dest_ip: 0,
            dest_port: 0,
        });
    }
    assert_eq!(handler.events_seen(), 10_000);
}
