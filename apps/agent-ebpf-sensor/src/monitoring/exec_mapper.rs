//! ExecEvent v1 decode, SecurityTelemetryEvent mapping, and OTel attribute export.

use neuromesh_common::{
    ExecEvent, SecurityTelemetryEvent, ARGV_FLAG_ARGC_TRUNCATED, ARGV_FLAG_PROBE_FAULT,
    CAPTURE_ARGS_COUNT, CAPTURE_ARGV, CAPTURE_COMM, CAPTURE_CONTAINER_ID, CAPTURE_EUID,
    CAPTURE_FILENAME, CAPTURE_GID, CAPTURE_NAMESPACE_ID, CAPTURE_PPID, CAPTURE_TGID,
    CAPTURE_TIMESTAMP, CAPTURE_UID, ENFORCEMENT_ALLOWED, ENFORCEMENT_BLOCKED, ENFORCEMENT_UNKNOWN,
    EXEC_EVENT_STRUCT_SIZE, MAX_ARGV_LEN, UNKNOWN_SENTINEL,
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

/// Join fixed argv slots (`MAX_ARGS_CAPTURE` × `MAX_ARG_STR_LEN`) into a
/// space-delimited command line for SIEM / OTel export. `argv_len` is the
/// number of filled slots (Issue #46).
pub fn format_argv_cmdline(argv: &[u8], argv_len: u16) -> String {
    use neuromesh_common::{MAX_ARGS_CAPTURE, MAX_ARGV_LEN, MAX_ARG_STR_LEN};

    let slots = (argv_len as usize).min(MAX_ARGS_CAPTURE);
    let buf = if argv.len() >= MAX_ARGV_LEN {
        &argv[..MAX_ARGV_LEN]
    } else {
        argv
    };
    let mut out = String::new();
    for i in 0..slots {
        let start = i * MAX_ARG_STR_LEN;
        let end = (start + MAX_ARG_STR_LEN).min(buf.len());
        if start >= end {
            break;
        }
        let slot = &buf[start..end];
        let nul = slot.iter().position(|&b| b == 0).unwrap_or(slot.len());
        if nul == 0 {
            continue;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&String::from_utf8_lossy(&slot[..nul]));
    }
    out
}

/// Map kernel `ExecEvent` into the canonical `SecurityTelemetryEvent` without silent data loss.
pub fn exec_event_to_security_telemetry(event: &ExecEvent) -> SecurityTelemetryEvent {
    let (argv_len, argv) = argv_field(event);
    SecurityTelemetryEvent {
        pid: scalar_or_zero(event.pid, event.field_unknown(CAPTURE_TGID)),
        ppid: scalar_or_zero(event.ppid, event.field_unknown(CAPTURE_PPID)),
        ppid_unresolved: event.field_unknown(CAPTURE_PPID),
        uid: scalar_or_zero(event.uid, event.field_unknown(CAPTURE_UID)),
        euid: scalar_or_zero(event.euid, event.field_unknown(CAPTURE_EUID)),
        comm: string_field(&event.comm, CAPTURE_COMM, event.capture_status),
        filename: string_field(&event.filename, CAPTURE_FILENAME, event.capture_status),
        argv_len,
        argv_truncated: event.argv_trunc_mask != 0
            || (event.argv_flags & (ARGV_FLAG_ARGC_TRUNCATED | ARGV_FLAG_PROBE_FAULT)) != 0
            || event.field_unknown(CAPTURE_ARGV),
        argv_trunc_mask: event.argv_trunc_mask,
        argv,
    }
}

/// Build OTel-compatible attributes including capture diagnostics for unknown fields.
pub fn exec_event_otel_attributes(event: &ExecEvent) -> OtelExecAttributes {
    let mut attributes = BTreeMap::new();

    attributes.insert("neuromesh.event.type".into(), "execve".into());
    // Which syscall produced this record (Issue #126). `event.type` stays "execve"
    // for schema compatibility; this is the analyst-facing discriminator.
    attributes.insert(
        "neuromesh.exec.syscall".into(),
        if event.is_execveat() {
            "execveat".into()
        } else {
            "execve".into()
        },
    );
    if event.path_from_fd() {
        // AT_EMPTY_PATH / fexecve: the target was named by a file descriptor, so
        // `filename` is the UNKNOWN sentinel rather than a resolvable path.
        attributes.insert("neuromesh.exec.path_from_fd".into(), "true".into());
    }
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
    if event.field_unknown(CAPTURE_PPID) {
        // Explicit flag so SIEM/OTel consumers do not treat neuromesh.ppid=UNKNOWN
        // as parent 0, and so burst fallback (`ppid_unresolved`) is queryable.
        attributes.insert("neuromesh.ppid_unresolved".into(), "true".into());
    }
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
    attributes.insert("neuromesh.argv".into(), display_argv(event));
    let argv_truncated = event.argv_trunc_mask != 0
        || (event.argv_flags & (ARGV_FLAG_ARGC_TRUNCATED | ARGV_FLAG_PROBE_FAULT)) != 0
        || event.field_unknown(CAPTURE_ARGV);
    attributes.insert(
        "neuromesh.argv_truncated".into(),
        argv_truncated.to_string(),
    );
    attributes.insert(
        "neuromesh.argv_trunc_mask".into(),
        format!("0x{:02x}", event.argv_trunc_mask),
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

fn argv_field(event: &ExecEvent) -> (u16, [u8; MAX_ARGV_LEN]) {
    use neuromesh_common::{MAX_ARGS_CAPTURE, MAX_ARG_STR_LEN};

    let mut out = [0u8; MAX_ARGV_LEN];
    let slots = (event.argv_len as usize).min(MAX_ARGS_CAPTURE);
    let bytes = (slots * MAX_ARG_STR_LEN).min(MAX_ARGV_LEN);
    out[..bytes].copy_from_slice(&event.argv[..bytes]);
    (slots as u16, out)
}

#[inline]
fn display_argv(event: &ExecEvent) -> String {
    let formatted = format_argv_cmdline(&event.argv, event.argv_len);
    if event.field_unknown(CAPTURE_ARGV) && formatted.is_empty() {
        return format!("UNKNOWN:{}", bit_name(CAPTURE_ARGV));
    }
    if event.field_unknown(CAPTURE_ARGV) && !formatted.is_empty() {
        return format!("{formatted} [truncated]");
    }
    formatted
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
        CAPTURE_ARGS_COUNT => "args_count_probe_fault",
        CAPTURE_ARGV => "argv_probe_fault",
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
        EXEC_FLAG_PATH_FROM_FD, EXEC_FLAG_SYSCALL_EXECVEAT, MAX_ARGV_LEN, MAX_COMM_LEN,
        MAX_CONTAINER_ID_LEN, MAX_FILENAME_LEN,
    };

    fn as_bytes(event: &ExecEvent) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                event as *const ExecEvent as *const u8,
                size_of::<ExecEvent>(),
            )
        }
    }

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
            argv_len: 0,
            argv_trunc_mask: 0,
            argv_flags: 0,
            argv: [0; MAX_ARGV_LEN],
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
        // `flags` carries the syscall-variant discriminator (Issue #126); the C
        // header writes it at this offset.
        assert_eq!(offset_of!(ExecEvent, flags), 3);
        assert_eq!(offset_of!(ExecEvent, pid), 16);
        assert_eq!(offset_of!(ExecEvent, comm), 40);
        assert_eq!(offset_of!(ExecEvent, filename), 56);
        assert_eq!(offset_of!(ExecEvent, argv), 320);
        assert_eq!(offset_of!(ExecEvent, namespace_id), 644);
    }

    /// Issue #126: `execveat` telemetry is only actually visible if the decoder
    /// accepts it. The variant lives in `flags` precisely because `is_valid()`
    /// hard-requires `event_type == EXEC_EVENT_TYPE_EXECVE`; encoding it as a new
    /// event_type would make these records fail decode and vanish silently.
    #[test]
    fn execveat_records_are_accepted_by_the_decoder() {
        let mut event = valid_event();
        event.flags = EXEC_FLAG_SYSCALL_EXECVEAT;

        assert!(
            event.is_valid(),
            "execveat flag must not invalidate the header"
        );

        let decoded =
            decode_exec_event(as_bytes(&event)).expect("execveat record must survive decode");
        assert!(decoded.is_execveat());
        assert!(!decoded.path_from_fd());
        assert_eq!(decoded.event_type, EXEC_EVENT_TYPE_EXECVE);
        // Copied out first: `ExecEvent` is packed, so a multi-byte field cannot be
        // borrowed by `assert_eq!`.
        let struct_size = decoded.struct_size;
        assert_eq!(struct_size, EXEC_EVENT_STRUCT_SIZE);

        // The variant must be visible to analysts, not just present in the struct.
        let otel = exec_event_otel_attributes(&decoded);
        assert_eq!(
            otel.attributes
                .get("neuromesh.exec.syscall")
                .map(String::as_str),
            Some("execveat")
        );
        assert!(!otel.attributes.contains_key("neuromesh.exec.path_from_fd"));
    }

    #[test]
    fn execve_records_are_not_flagged_as_execveat() {
        let event = valid_event();
        assert_eq!(event.flags, 0);
        let decoded = decode_exec_event(as_bytes(&event)).expect("valid execve record");
        assert!(!decoded.is_execveat());
        assert!(!decoded.path_from_fd());

        let otel = exec_event_otel_attributes(&decoded);
        assert_eq!(
            otel.attributes
                .get("neuromesh.exec.syscall")
                .map(String::as_str),
            Some("execve")
        );
    }

    /// `fexecve(3)` reaches the kernel as `execveat(fd, "", …, AT_EMPTY_PATH)`, so
    /// no path string exists. The event must still be visible, with the missing
    /// path reported explicitly rather than as an empty string.
    #[test]
    fn fexecve_shape_is_visible_and_marks_the_path_as_fd_named() {
        let mut event = valid_event();
        event.flags = EXEC_FLAG_SYSCALL_EXECVEAT | EXEC_FLAG_PATH_FROM_FD;
        event.filename = bytes_with_prefix::<MAX_FILENAME_LEN>(b"UNKNOWN");
        event.capture_status = CAPTURE_FILENAME;

        let decoded = decode_exec_event(as_bytes(&event)).expect("fexecve record must be visible");
        assert!(decoded.is_execveat());
        assert!(decoded.path_from_fd());
        assert!(decoded.field_unknown(CAPTURE_FILENAME));

        let otel = exec_event_otel_attributes(&decoded);
        assert_eq!(
            otel.attributes
                .get("neuromesh.filename")
                .map(String::as_str),
            Some("UNKNOWN:filename_capture_fault")
        );
        assert_eq!(
            otel.attributes
                .get("neuromesh.exec.syscall")
                .map(String::as_str),
            Some("execveat")
        );
        assert_eq!(
            otel.attributes
                .get("neuromesh.exec.path_from_fd")
                .map(String::as_str),
            Some("true"),
            "an fd-named exec must be distinguishable from a probe fault"
        );
    }

    /// The correlation/detection path consumes execveat records identically to
    /// execve records — the flag is metadata, not a separate pipeline.
    #[test]
    fn execveat_records_map_to_security_telemetry_like_execve() {
        let mut execveat = valid_event();
        execveat.flags = EXEC_FLAG_SYSCALL_EXECVEAT;

        let from_execve = exec_event_to_security_telemetry(&valid_event());
        let from_execveat = exec_event_to_security_telemetry(&execveat);

        assert_eq!(from_execve.pid, from_execveat.pid);
        assert_eq!(from_execve.ppid, from_execveat.ppid);
        assert_eq!(from_execve.filename, from_execveat.filename);
        assert_eq!(from_execve.comm, from_execveat.comm);
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
        assert!(
            mapped.ppid_unresolved,
            "CAPTURE_PPID must surface as ppid_unresolved for burst fallback"
        );

        let otel = exec_event_otel_attributes(&event);
        assert_eq!(
            otel.attributes.get("neuromesh.ppid").map(String::as_str),
            Some("UNKNOWN:ppid_probe_fault")
        );
        assert_eq!(
            otel.attributes
                .get("neuromesh.ppid_unresolved")
                .map(String::as_str),
            Some("true")
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
