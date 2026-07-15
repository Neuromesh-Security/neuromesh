//! ExecEvent v1 decode, SecurityTelemetryEvent mapping, and OTel attribute export.

use neuromesh_common::{
    ExecEvent, SecurityTelemetryEvent, CAPTURE_ARGS_COUNT, CAPTURE_COMM, CAPTURE_CONTAINER_ID,
    CAPTURE_EUID, CAPTURE_FILENAME, CAPTURE_GID, CAPTURE_NAMESPACE_ID, CAPTURE_PPID, CAPTURE_TGID,
    CAPTURE_TIMESTAMP, CAPTURE_UID, ENFORCEMENT_ALLOWED, ENFORCEMENT_BLOCKED, ENFORCEMENT_UNKNOWN,
    EXEC_EVENT_STRUCT_SIZE, UNKNOWN_SENTINEL,
};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::ptr;

/// OpenTelemetry-ready attribute bag for distributed tracing enrichment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtelExecAttributes {
    pub attributes: BTreeMap<String, String>,
}

/// Decode a ring-buffer record with schema validation (rejects torn/unknown versions).
#[inline]
pub fn decode_exec_event(bytes: &[u8]) -> Option<ExecEvent> {
    if bytes.len() < EXEC_EVENT_STRUCT_SIZE as usize {
        return None;
    }

    let event = unsafe { ptr::read_unaligned(bytes.as_ptr() as *const ExecEvent) };
    if !event.is_valid() {
        return None;
    }

    Some(event)
}

/// Map kernel `ExecEvent` into the canonical `SecurityTelemetryEvent` without silent data loss.
pub fn exec_event_to_security_telemetry(event: &ExecEvent) -> SecurityTelemetryEvent {
    SecurityTelemetryEvent {
        pid: scalar_or_zero(event.pid, event.field_unknown(CAPTURE_TGID)),
        ppid: scalar_or_zero(event.ppid, event.field_unknown(CAPTURE_PPID)),
        uid: scalar_or_zero(event.uid, event.field_unknown(CAPTURE_UID)),
        euid: scalar_or_zero(event.euid, event.field_unknown(CAPTURE_EUID)),
        comm: string_field(&event.comm, CAPTURE_COMM, event.capture_status),
        filename: string_field(&event.filename, CAPTURE_FILENAME, event.capture_status),
    }
}

/// Build OTel-compatible attributes including capture diagnostics for unknown fields.
pub fn exec_event_otel_attributes(event: &ExecEvent) -> OtelExecAttributes {
    let mut attributes = BTreeMap::new();

    attributes.insert("neuromesh.event.type".into(), "execve".into());
    let schema_version = event.schema_version;
    let pid = event.pid;
    let tgid = event.tgid;
    attributes.insert(
        "neuromesh.schema.version".into(),
        schema_version.to_string(),
    );
    attributes.insert("neuromesh.pid".into(), pid.to_string());
    attributes.insert("neuromesh.tgid".into(), tgid.to_string());
    attributes.insert(
        "neuromesh.ppid".into(),
        display_scalar(event.ppid, CAPTURE_PPID, event.capture_status),
    );
    attributes.insert(
        "neuromesh.uid".into(),
        display_scalar(event.uid, CAPTURE_UID, event.capture_status),
    );
    attributes.insert(
        "neuromesh.euid".into(),
        display_scalar(event.euid, CAPTURE_EUID, event.capture_status),
    );
    attributes.insert(
        "neuromesh.gid".into(),
        display_scalar(event.gid, CAPTURE_GID, event.capture_status),
    );
    attributes.insert(
        "neuromesh.comm".into(),
        display_string(&event.comm, CAPTURE_COMM, event.capture_status, "comm"),
    );
    attributes.insert(
        "neuromesh.filename".into(),
        display_string(
            &event.filename,
            CAPTURE_FILENAME,
            event.capture_status,
            "filename",
        ),
    );
    attributes.insert(
        "neuromesh.args_count".into(),
        display_scalar(event.args_count, CAPTURE_ARGS_COUNT, event.capture_status),
    );
    attributes.insert(
        "neuromesh.container_id".into(),
        display_string(
            &event.container_id,
            CAPTURE_CONTAINER_ID,
            event.capture_status,
            "container_id",
        ),
    );
    attributes.insert(
        "neuromesh.namespace_id".into(),
        display_scalar_u64(
            event.namespace_id,
            CAPTURE_NAMESPACE_ID,
            event.capture_status,
        ),
    );
    attributes.insert(
        "neuromesh.timestamp_ns".into(),
        display_scalar_u64(event.timestamp_ns, CAPTURE_TIMESTAMP, event.capture_status),
    );
    attributes.insert(
        "neuromesh.enforcement_action".into(),
        enforcement_label(event.enforcement_action).into(),
    );
    let capture_status = event.capture_status;
    attributes.insert(
        "neuromesh.capture_status".into(),
        format!("0x{capture_status:04x}"),
    );

    OtelExecAttributes { attributes }
}

#[inline]
fn scalar_or_zero(value: u32, unknown: bool) -> u32 {
    if unknown {
        0
    } else {
        value
    }
}

#[inline]
fn display_scalar(value: u32, bit: u16, status: u16) -> String {
    if status & bit != 0 {
        format!("UNKNOWN:{}", bit_name(bit))
    } else {
        value.to_string()
    }
}

#[inline]
fn display_scalar_u64(value: u64, bit: u16, status: u16) -> String {
    if status & bit != 0 {
        format!("UNKNOWN:{}", bit_name(bit))
    } else {
        value.to_string()
    }
}

#[inline]
fn display_string(bytes: &[u8], bit: u16, status: u16, field: &str) -> String {
    if status & bit != 0 {
        return format!("UNKNOWN:{field}_capture_fault");
    }
    cstr_lossy(bytes).into_owned()
}

#[inline]
fn string_field<const N: usize>(bytes: &[u8; N], bit: u16, status: u16) -> [u8; N] {
    let mut out = [0u8; N];
    if status & bit != 0 {
        write_unknown(&mut out);
        return out;
    }

    let src = cstr_bytes(bytes);
    let len = src.len().min(out.len());
    out[..len].copy_from_slice(&src[..len]);
    out
}

fn write_unknown(buf: &mut [u8]) {
    let len = UNKNOWN_SENTINEL.len().min(buf.len());
    buf[..len].copy_from_slice(&UNKNOWN_SENTINEL[..len]);
}

fn cstr_bytes(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    &bytes[..end]
}

fn cstr_lossy(bytes: &[u8]) -> Cow<'_, str> {
    let raw = cstr_bytes(bytes);
    if raw.starts_with(UNKNOWN_SENTINEL) {
        return Cow::Borrowed("UNKNOWN");
    }
    String::from_utf8_lossy(raw)
}

fn enforcement_label(action: u8) -> &'static str {
    match action {
        ENFORCEMENT_ALLOWED => "allowed",
        ENFORCEMENT_BLOCKED => "blocked",
        ENFORCEMENT_UNKNOWN => "unknown",
        _ => "unknown",
    }
}

fn bit_name(bit: u16) -> &'static str {
    match bit {
        CAPTURE_PPID => "ppid_probe_fault",
        CAPTURE_TGID => "tgid_probe_fault",
        CAPTURE_UID => "uid_probe_fault",
        CAPTURE_EUID => "euid_probe_fault",
        CAPTURE_GID => "gid_probe_fault",
        CAPTURE_COMM => "comm_probe_fault",
        CAPTURE_FILENAME => "filename_probe_fault",
        CAPTURE_ARGS_COUNT => "argv_probe_fault",
        CAPTURE_CONTAINER_ID => "cgroup_probe_fault",
        CAPTURE_NAMESPACE_ID => "namespace_probe_fault",
        CAPTURE_TIMESTAMP => "timestamp_probe_fault",
        _ => "field_capture_fault",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{offset_of, size_of};
    use neuromesh_common::{
        ExecEvent, EXEC_EVENT_SCHEMA_VERSION, EXEC_EVENT_STRUCT_SIZE, EXEC_EVENT_TYPE_EXECVE,
        MAX_COMM_LEN, MAX_CONTAINER_ID_LEN, MAX_FILENAME_LEN,
    };

    fn bytes_with_prefix<const N: usize>(prefix: &[u8]) -> [u8; N] {
        let mut buf = [0u8; N];
        let len = prefix.len().min(N);
        buf[..len].copy_from_slice(&prefix[..len]);
        buf
    }

    fn valid_event() -> ExecEvent {
        ExecEvent {
            schema_version: EXEC_EVENT_SCHEMA_VERSION,
            event_type: EXEC_EVENT_TYPE_EXECVE,
            flags: 0,
            struct_size: EXEC_EVENT_STRUCT_SIZE,
            header_reserved: 0,
            header_pad: [0; 8],
            pid: 100,
            ppid: 1,
            tgid: 100,
            uid: 1000,
            euid: 1000,
            gid: 1000,
            comm: bytes_with_prefix::<MAX_COMM_LEN>(b"curl"),
            filename: bytes_with_prefix::<MAX_FILENAME_LEN>(b"/usr/bin/curl"),
            args_count: 2,
            container_id: bytes_with_prefix::<MAX_CONTAINER_ID_LEN>(b"neuromesh-agent"),
            align_pad: [0; 4],
            namespace_id: 4026531836,
            timestamp_ns: 9_999,
            enforcement_action: ENFORCEMENT_ALLOWED,
            capture_status: 0,
            status_reserved: [0; 5],
        }
    }

    #[test]
    fn exec_event_layout_matches_bpf_header() {
        assert_eq!(size_of::<ExecEvent>(), EXEC_EVENT_STRUCT_SIZE as usize);
        assert_eq!(offset_of!(ExecEvent, pid), 16);
        assert_eq!(offset_of!(ExecEvent, comm), 40);
        assert_eq!(offset_of!(ExecEvent, filename), 56);
        assert_eq!(offset_of!(ExecEvent, namespace_id), 384);
    }

    #[test]
    fn decode_rejects_short_and_invalid_schema() {
        assert!(decode_exec_event(&[]).is_none());
        let mut event = valid_event();
        event.schema_version = 0;
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &event as *const ExecEvent as *const u8,
                size_of::<ExecEvent>(),
            )
        };
        assert!(decode_exec_event(bytes).is_none());
    }

    #[test]
    fn mapper_preserves_filename_and_marks_unknown_fields() {
        let mut event = valid_event();
        event.capture_status = CAPTURE_PPID;
        let mapped = exec_event_to_security_telemetry(&event);
        assert_eq!(mapped.pid, 100);
        assert_eq!(mapped.ppid, 0);

        let otel = exec_event_otel_attributes(&event);
        assert_eq!(
            otel.attributes.get("neuromesh.ppid").map(String::as_str),
            Some("UNKNOWN:ppid_probe_fault")
        );
    }

    #[test]
    fn unknown_sentinel_surfaces_in_otel_comm() {
        let mut event = valid_event();
        event.comm = bytes_with_prefix::<MAX_COMM_LEN>(b"UNKNOWN");
        event.capture_status = CAPTURE_COMM;
        let otel = exec_event_otel_attributes(&event);
        assert_eq!(
            otel.attributes.get("neuromesh.comm").map(String::as_str),
            Some("UNKNOWN:comm_capture_fault")
        );
    }
}
