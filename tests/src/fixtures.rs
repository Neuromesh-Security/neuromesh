use neuromesh_common::{SecurityTelemetryEvent, MAX_COMM_LEN, MAX_FILENAME_LEN};

/// Build a C-compatible telemetry record for offline pipeline tests.
pub fn telemetry_event(
    pid: u32,
    ppid: u32,
    path: &str,
    comm: &str,
    uid: u32,
) -> SecurityTelemetryEvent {
    let mut filename = [0u8; MAX_FILENAME_LEN];
    let path_bytes = path.as_bytes();
    filename[..path_bytes.len()].copy_from_slice(path_bytes);

    let mut comm_buf = [0u8; MAX_COMM_LEN];
    let comm_bytes = comm.as_bytes();
    comm_buf[..comm_bytes.len().min(MAX_COMM_LEN)]
        .copy_from_slice(&comm_bytes[..comm_bytes.len().min(MAX_COMM_LEN)]);

    SecurityTelemetryEvent {
        pid,
        ppid,
        uid,
        euid: uid,
        comm: comm_buf,
        filename,
    }
}

/// Benign execution vectors — whitelisted paths and low-frequency spawns.
pub fn benign_events() -> Vec<SecurityTelemetryEvent> {
    vec![
        telemetry_event(1001, 1, "/bin/ls", "ls", 1000),
        telemetry_event(1002, 1, "/bin/cat", "cat", 1000),
        telemetry_event(1003, 1, "/usr/bin/git", "git", 1000),
        telemetry_event(1004, 1, "/usr/bin/bash", "bash", 1000),
        telemetry_event(1005, 500, "/usr/bin/python3", "python3", 1000),
    ]
}

/// Malicious execution vectors — ephemeral staging paths and burst patterns.
pub fn malicious_blacklist_events() -> Vec<SecurityTelemetryEvent> {
    vec![
        telemetry_event(2001, 42, "/tmp/evil.bin", "bash", 1000),
        telemetry_event(2002, 42, "/dev/shm/.hidden", "sh", 0),
        telemetry_event(2003, 42, "/var/tmp/stage.sh", "stage", 1000),
    ]
}

/// Rapid spawn burst from a single parent (fork-bomb / LotL chaining pattern).
pub fn malicious_spawn_burst_events() -> Vec<SecurityTelemetryEvent> {
    (100..108)
        .map(|pid| telemetry_event(pid, 4242, "/usr/bin/bash", "bash", 1000))
        .collect()
}

/// Mixed stream simulating a mock RingBuf drain order.
pub fn mixed_ringbuf_drain() -> Vec<SecurityTelemetryEvent> {
    let mut events = benign_events();
    events.extend(malicious_blacklist_events());
    events.extend(malicious_spawn_burst_events());
    events
}
