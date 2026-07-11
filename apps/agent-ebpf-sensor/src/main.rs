use aya::maps::RingBuf;
use aya::programs::TracePoint;
use aya::Ebpf;
use log::info;
use neuromesh_common::SecurityTelemetryEvent;
use std::ptr;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    info!("🚀 [Neuromesh] Initializing Enterprise Agent...");

    #[cfg(debug_assertions)]
    let bpf_data = include_bytes!("../ebpf/target/bpfel-unknown-none/debug/agent-ebpf-sensor-ebpf");
    #[cfg(not(debug_assertions))]
    let bpf_data =
        include_bytes!("../ebpf/target/bpfel-unknown-none/release/agent-ebpf-sensor-ebpf");

    let mut ebpf = Ebpf::load(bpf_data)?;

    let program: &mut TracePoint = ebpf
        .program_mut("neuromesh_exec_hook")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

    let telemetry_map = RingBuf::try_from(ebpf.map_mut("TELEMETRY_RINGBUF").unwrap())?;
    let mut async_ring = AsyncFd::new(telemetry_map)?;

    info!("⚡ Async telemetry pipeline armed. Polling RingBuf...");

    loop {
        async_ring
            .async_io_mut(Interest::READABLE, |ring| {
                while let Some(item) = ring.next() {
                    let event = unsafe {
                        ptr::read_unaligned(item.as_ptr() as *const SecurityTelemetryEvent)
                    };
                    let filename = format_filename(&event);

                    info!(
                        "🚨 Intercepted: pid={} uid={} target={}",
                        event.pid, event.uid, filename
                    );
                }
                Ok(())
            })
            .await?;
    }
}

fn format_filename(event: &SecurityTelemetryEvent) -> std::borrow::Cow<'_, str> {
    match std::ffi::CStr::from_bytes_until_nul(&event.filename) {
        Ok(cstr) => cstr.to_string_lossy(),
        Err(_) => std::borrow::Cow::Borrowed("[Invalid Path]"),
    }
}
