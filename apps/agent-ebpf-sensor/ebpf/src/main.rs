#![allow(linker_messages)]
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
    },
    macros::{lsm, map},
    maps::{Array, RingBuf},
    programs::LsmContext,
};
use aya_ebpf_bindings::helpers::bpf_get_current_task;
use aya_log_ebpf::info;
use neuromesh_common::{
    CAPTURE_COMM, CAPTURE_CONTAINER_ID, CAPTURE_EUID, CAPTURE_FILENAME, CAPTURE_NAMESPACE_ID,
    CAPTURE_PPID, ENFORCEMENT_BLOCKED, EXEC_EVENT_SCHEMA_VERSION, EXEC_EVENT_STRUCT_SIZE,
    EXEC_EVENT_TYPE_EXECVE, ExecEvent, TelemetryHealthStats, MAX_COMM_LEN, MAX_CONTAINER_ID_LEN,
    MAX_FILENAME_LEN, TELEMETRY_STATS_INDEX, UNKNOWN_SENTINEL,
};

/// LSM denial code — maps to `-EPERM` in the kernel security hook contract.
const LSM_DENY: i32 = -1;

/// Prefix window used for blacklist matching without exhausting the 512-byte BPF stack.
const PATH_PREFIX_LEN: usize = 16;

/// `linux_binprm->filename` field offset on kernel 6.x (see `struct linux_binprm`).
const BPRM_FILENAME_OFFSET: usize = 72;

/// `task_struct->real_parent` offset (x86_64, kernel 6.x — best-effort).
const TASK_REAL_PARENT_OFFSET: usize = 1216;

/// `task_struct->tgid` offset (x86_64, kernel 6.x — best-effort).
const TASK_TGID_OFFSET: usize = 104;

#[map]
static TELEMETRY_RINGBUF: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

#[map]
static TELEMETRY_STATS: Array<TelemetryHealthStats> = Array::with_max_entries(1, 0);

#[lsm(hook = "bprm_check_security")]
pub fn neuromesh_lsm_exec_guard(ctx: LsmContext) -> i32 {
    match try_neuromesh_lsm_exec_guard(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_neuromesh_lsm_exec_guard(ctx: LsmContext) -> Result<i32, i64> {
    let prefix = read_bprm_path_prefix(&ctx)?;

    if !is_blacklisted_path(&prefix) {
        return Ok(0);
    }

    emit_blocked_exec_event(&ctx);
    info!(&ctx, "Neuromesh XDR: blocked execution from blacklisted path");

    Ok(LSM_DENY)
}

fn init_exec_event(event: &mut ExecEvent, enforcement_action: u8) {
    *event = ExecEvent {
        schema_version: 0,
        event_type: EXEC_EVENT_TYPE_EXECVE,
        flags: 0,
        struct_size: EXEC_EVENT_STRUCT_SIZE,
        header_reserved: 0,
        header_pad: [0; 8],
        pid: 0,
        ppid: 0,
        tgid: 0,
        uid: 0,
        euid: 0,
        gid: 0,
        comm: [0; MAX_COMM_LEN],
        filename: [0; MAX_FILENAME_LEN],
        args_count: 0,
        container_id: [0; MAX_CONTAINER_ID_LEN],
        align_pad: [0; 4],
        namespace_id: 0,
        timestamp_ns: 0,
        enforcement_action,
        capture_status: 0,
        status_reserved: [0; 5],
    };
}

/// Returns the updated `capture_status` bitmask; callers must write it back.
/// (`capture_status` lives in a `#[repr(C, packed)]` struct, so it cannot be
/// passed as `&mut u16` — taking a reference to an unaligned field is UB.)
fn mark_unknown(bytes: &mut [u8], status: u16, bit: u16) -> u16 {
    let len = UNKNOWN_SENTINEL.len().min(bytes.len());
    bytes[..len].copy_from_slice(&UNKNOWN_SENTINEL[..len]);
    status | bit
}

fn populate_lineage(event: &mut ExecEvent) {
    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = (pid_tgid >> 32) as u32;
    event.tgid = pid_tgid as u32;

    let uid_gid = bpf_get_current_uid_gid();
    event.uid = uid_gid as u32;
    event.gid = (uid_gid >> 32) as u32;
    event.euid = uid_gid as u32;
    event.capture_status |= CAPTURE_EUID;

    event.capture_status = mark_unknown(
        &mut event.container_id,
        event.capture_status,
        CAPTURE_CONTAINER_ID,
    );

    event.ppid = read_ppid_best_effort(event);

    if let Ok(comm) = bpf_get_current_comm() {
        let copy_len = comm.len().min(MAX_COMM_LEN);
        event.comm[..copy_len].copy_from_slice(&comm[..copy_len]);
    } else {
        event.capture_status = mark_unknown(&mut event.comm, event.capture_status, CAPTURE_COMM);
    }
}

fn read_ppid_best_effort(event: &mut ExecEvent) -> u32 {
    unsafe {
        let task = bpf_get_current_task() as *const u8;
        if task.is_null() {
            event.capture_status |= CAPTURE_PPID;
            return 0;
        }

        let parent_ptr: *const u8 = match bpf_probe_read_kernel(
            task.add(TASK_REAL_PARENT_OFFSET) as *const *const u8,
        ) {
            Ok(ptr) => ptr,
            Err(_) => {
                event.capture_status |= CAPTURE_PPID;
                return 0;
            }
        };

        if parent_ptr.is_null() {
            event.capture_status |= CAPTURE_PPID;
            return 0;
        }

        match bpf_probe_read_kernel(parent_ptr.add(TASK_TGID_OFFSET) as *const u32) {
            Ok(ppid) => ppid,
            Err(_) => {
                event.capture_status |= CAPTURE_PPID;
                0
            }
        }
    }
}

fn read_bprm_path_prefix(ctx: &LsmContext) -> Result<[u8; PATH_PREFIX_LEN], i64> {
    let filename_ptr = read_bprm_filename_ptr(ctx)?;
    let mut prefix = [0u8; PATH_PREFIX_LEN];
    unsafe {
        let _ = bpf_probe_read_kernel(filename_ptr as *const [u8; PATH_PREFIX_LEN]).map(|value| {
            prefix = value;
        });
    }
    Ok(prefix)
}

fn read_bprm_filename_ptr(ctx: &LsmContext) -> Result<*const u8, i64> {
    let bprm_ptr: *const u8 = unsafe { ctx.arg::<*const u8>(0) };
    unsafe {
        bpf_probe_read_kernel(bprm_ptr.add(BPRM_FILENAME_OFFSET) as *const *const u8)
            .map_err(|error| error as i64)
    }
}

fn emit_blocked_exec_event(ctx: &LsmContext) {
    if let Some(mut entry) = TELEMETRY_RINGBUF.reserve::<ExecEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        init_exec_event(event, ENFORCEMENT_BLOCKED);
        populate_lineage(event);
        event.filename = [0u8; MAX_FILENAME_LEN];
        if let Ok(filename_ptr) = read_bprm_filename_ptr(ctx) {
            if unsafe { bpf_probe_read_kernel_str_bytes(filename_ptr, &mut event.filename) }
                .is_err()
            {
                event.capture_status =
                    mark_unknown(&mut event.filename, event.capture_status, CAPTURE_FILENAME);
            }
        } else {
            event.capture_status =
                mark_unknown(&mut event.filename, event.capture_status, CAPTURE_FILENAME);
        }
        event.namespace_id = 0;
        event.capture_status |= CAPTURE_NAMESPACE_ID;
        event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
        event.schema_version = EXEC_EVENT_SCHEMA_VERSION;
        entry.submit(0);
        record_event_submitted();
    } else {
        record_event_lost();
    }
}

fn is_blacklisted_path(path: &[u8]) -> bool {
    starts_with(path, b"/tmp/")
        || starts_with(path, b"/dev/shm/")
        || starts_with(path, b"/var/tmp/")
}

fn starts_with(path: &[u8], prefix: &[u8]) -> bool {
    if path.len() < prefix.len() {
        return false;
    }

    path.iter()
        .zip(prefix.iter())
        .all(|(left, right)| left == right)
}

fn record_event_submitted() {
    if let Some(stats) = TELEMETRY_STATS.get_ptr_mut(TELEMETRY_STATS_INDEX) {
        unsafe {
            (*stats).events_processed = (*stats).events_processed.saturating_add(1);
        }
    }
}

fn record_event_lost() {
    if let Some(stats) = TELEMETRY_STATS.get_ptr_mut(TELEMETRY_STATS_INDEX) {
        unsafe {
            (*stats).lost_events_count = (*stats).lost_events_count.saturating_add(1);
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
