#![allow(linker_messages)]
#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

#[map]
static TELEMETRY_RINGBUF: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[tracepoint]
pub fn neuromesh_exec_hook(ctx: TracePointContext) -> u32 {
    match try_neuromesh_exec_hook(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_neuromesh_exec_hook(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "Neuromesh Alert: Process intercepted!");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
