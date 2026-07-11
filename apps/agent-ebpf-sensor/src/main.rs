use aya::maps::RingBuf;
use aya::programs::TracePoint;
use aya::Ebpf;
use log::info;
use std::ptr;

pub const MAX_FILENAME_LEN: usize = 256;

#[repr(C)]
pub struct ExecveTelemetryEvent {
    pub pid: u32,
    pub uid: u32,
    pub filename: [u8; MAX_FILENAME_LEN],
}

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

    let mut telemetry_map = RingBuf::try_from(ebpf.map_mut("TELEMETRY_RINGBUF").unwrap())?;

    info!("⚡ Pipeline armed. Listening for kernel events...");

    loop {
        while let Some(item) = telemetry_map.next() {
            let event =
                unsafe { ptr::read_unaligned(item.as_ptr() as *const ExecveTelemetryEvent) };

            let filename = match std::ffi::CStr::from_bytes_until_nul(&event.filename) {
                Ok(cstr) => cstr.to_string_lossy(),
                Err(_) => std::borrow::Cow::Borrowed("[Invalid Path]"),
            };

            info!("🚨 Intercepted: PID {} | Target: {}", event.pid, filename);
        }

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}
