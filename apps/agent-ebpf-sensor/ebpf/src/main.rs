#![allow(linker_messages)]
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_user_str_bytes},
    macros::{map, tracepoint},
    maps::{Array, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::info;
use neuromesh_common::{
    SecurityTelemetryEvent, TelemetryHealthStats, MAX_FILENAME_LEN, TELEMETRY_STATS_INDEX,
};

#[map]
static TELEMETRY_RINGBUF: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static TELEMETRY_STATS: Array<TelemetryHealthStats> = Array::with_max_entries(1, 0);

#[tracepoint]
pub fn neuromesh_exec_hook(ctx: TracePointContext) -> u32 {
    match try_neuromesh_exec_hook(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_neuromesh_exec_hook(ctx: TracePointContext) -> Result<u32, i64> {
    const FILENAME_OFFSET: usize = 16;
    let filename_ptr: *const u8 = unsafe { ctx.read_at(FILENAME_OFFSET)? };

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;

    let mut event = SecurityTelemetryEvent {
        pid,
        uid,
        filename: [0u8; MAX_FILENAME_LEN],
    };

    let _ = unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename) };

    if let Some(mut entry) = TELEMETRY_RINGBUF.reserve::<SecurityTelemetryEvent>(0) {
        entry.write(event);
        entry.submit(0);
        record_event_submitted();
    } else {
        record_event_lost();
    }

    info!(&ctx, "Neuromesh Alert: Process intercepted!");
    Ok(0)
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
