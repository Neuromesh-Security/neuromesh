//! Lightweight pseudo-random fuzz harness for RingBuf decode paths (no `cargo-fuzz` required).

use agent_ebpf_sensor::monitoring::event::{ProcessEvent, ProcessEventHandler};
use agent_ebpf_sensor::monitoring::network_event::{NetworkEvent, NetworkEventHandler};
use agent_ebpf_sensor::monitoring::ringbuf_decode::{decode_exec_event, decode_network_event};
use core::mem::size_of;
use neuromesh_common::{
    EXEC_EVENT_SCHEMA_VERSION, EXEC_EVENT_STRUCT_SIZE, EXEC_EVENT_TYPE_EXECVE, ExecEvent,
    MAX_COMM_LEN, MAX_CONTAINER_ID_LEN, MAX_FILENAME_LEN,
};

const DEFAULT_ITERATIONS: usize = 50_000;

fn lcg_next(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

fn random_bytes(state: &mut u64, max_len: usize) -> Vec<u8> {
    let len = (lcg_next(state) as usize) % max_len;
    let mut buf = vec![0u8; len];
    for byte in &mut buf {
        *byte = lcg_next(state) as u8;
    }
    buf
}

fn sample_valid_event() -> ProcessEvent {
    ExecEvent {
        schema_version: EXEC_EVENT_SCHEMA_VERSION,
        event_type: EXEC_EVENT_TYPE_EXECVE,
        flags: 0,
        struct_size: EXEC_EVENT_STRUCT_SIZE,
        header_reserved: 0,
        header_pad: [0; 8],
        pid: 4242,
        ppid: 1,
        tgid: 4242,
        uid: 1000,
        euid: 1000,
        gid: 1000,
        comm: [0; MAX_COMM_LEN],
        filename: [0; MAX_FILENAME_LEN],
        args_count: 0,
        container_id: [0; MAX_CONTAINER_ID_LEN],
        align_pad: [0; 4],
        namespace_id: 0,
        timestamp_ns: 99,
        enforcement_action: 0,
        capture_status: 0,
        status_reserved: [0; 5],
    }
}

fn fuzz_decode_paths(seed: u64, iterations: usize) {
    let mut state = seed;
    let mut process_handler = ProcessEventHandler::default();
    let mut network_handler = NetworkEventHandler::default();

    for _ in 0..iterations {
        let bytes = random_bytes(&mut state, size_of::<ExecEvent>() * 2);

        if let Some(event) = decode_exec_event(&bytes) {
            process_handler.observe(&event);
        }

        if let Some(event) = decode_network_event(&bytes) {
            network_handler.observe(event);
        }
    }
}

#[test]
fn ringbuf_decoders_never_panic_on_random_bytes() {
    fuzz_decode_paths(0xDEAD_BEEF_CAFE, DEFAULT_ITERATIONS);
}

#[test]
fn ringbuf_decoders_never_panic_on_edge_length_buffers() {
    for len in 0..=size_of::<ExecEvent>() + 8 {
        let bytes = vec![0xFFu8; len];
        let _ = decode_exec_event(&bytes);
        let _ = decode_network_event(&bytes);
    }
}

#[test]
fn valid_process_event_bytes_roundtrip_through_handler() {
    let event = sample_valid_event();
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &event as *const ProcessEvent as *const u8,
            size_of::<ProcessEvent>(),
        )
    };

    let decoded = decode_exec_event(bytes).expect("valid layout");
    let mut handler = ProcessEventHandler::default();
    handler.observe(&decoded);
    assert_eq!(handler.events_seen(), 1);
}

#[test]
fn valid_network_event_bytes_roundtrip_through_handler() {
    let event = NetworkEvent {
        pid: 100,
        uid: 1000,
        dest_ip: 0x0808_0808,
        dest_port: 443,
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &event as *const NetworkEvent as *const u8,
            size_of::<NetworkEvent>(),
        )
    };

    let decoded = decode_network_event(bytes).expect("valid layout");
    let mut handler = NetworkEventHandler::default();
    handler.observe(decoded);
    assert_eq!(handler.events_seen(), 1);
}
