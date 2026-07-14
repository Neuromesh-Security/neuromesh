//! Lightweight pseudo-random fuzz harness for RingBuf decode paths (no `cargo-fuzz` required).

use agent_ebpf_sensor::monitoring::event::{ProcessEvent, ProcessEventHandler};
use agent_ebpf_sensor::monitoring::network_event::{NetworkEvent, NetworkEventHandler};
use agent_ebpf_sensor::monitoring::ringbuf_decode::{decode_network_event, decode_process_event};
use core::mem::size_of;

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

fn fuzz_decode_paths(seed: u64, iterations: usize) {
    let mut state = seed;
    let mut process_handler = ProcessEventHandler::default();
    let mut network_handler = NetworkEventHandler::default();

    for _ in 0..iterations {
        let bytes = random_bytes(&mut state, size_of::<ProcessEvent>() * 2);

        if let Some(event) = decode_process_event(&bytes) {
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
    for len in 0..=size_of::<ProcessEvent>() + 8 {
        let bytes = vec![0xFFu8; len];
        let _ = decode_process_event(&bytes);
        let _ = decode_network_event(&bytes);
    }
}

#[test]
fn valid_process_event_bytes_roundtrip_through_handler() {
    let event = ProcessEvent {
        pid: 4242,
        uid: 1000,
        ppid: 1,
        comm: [0; 16],
        filename: [0; 128],
        ts: 99,
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &event as *const ProcessEvent as *const u8,
            size_of::<ProcessEvent>(),
        )
    };

    let decoded = decode_process_event(bytes).expect("valid layout");
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
