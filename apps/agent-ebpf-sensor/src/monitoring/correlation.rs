//! Lock-free in-memory correlation between process exec and network connect events.

use crate::monitoring::network_event::NetworkEvent;
use dashmap::DashMap;
use std::sync::Arc;

/// Network telemetry enriched with the originating process identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrichedNetworkEvent {
    pub pid: u32,
    pub uid: u32,
    pub dest_ip: u32,
    pub dest_port: u16,
    pub process_name: String,
}

/// Concurrent PID → process name cache (lock-free reads/writes via `DashMap`).
#[derive(Debug)]
pub struct CorrelationEngine {
    processes: Arc<DashMap<u32, String>>,
}

impl CorrelationEngine {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            processes: Arc::new(DashMap::new()),
        })
    }

    /// Register or refresh a process name observed from `sys_enter_execve`.
    #[inline]
    pub fn register_process(&self, pid: u32, argv0: &[u8]) {
        if pid == 0 {
            return;
        }
        let name = argv0_to_process_name(argv0);
        self.processes.insert(pid, name);
    }

    /// Resolve a raw network event against the process cache.
    #[inline]
    pub fn correlate(&self, event: NetworkEvent) -> Option<EnrichedNetworkEvent> {
        let (pid, uid, dest_ip, dest_port) = event.fields();
        let process_name = self.processes.get(&pid)?.clone();
        Some(EnrichedNetworkEvent {
            pid,
            uid,
            dest_ip,
            dest_port,
            process_name,
        })
    }

    pub fn process_count(&self) -> usize {
        self.processes.len()
    }
}

impl EnrichedNetworkEvent {
    /// Emit the canonical correlated visibility log line for the AI pipeline.
    #[inline]
    pub fn log_correlated(&self) {
        let ip = format_ipv4(self.dest_ip);
        let port = u16::from_be(self.dest_port);
        tracing::warn!(
            target: "neuromesh::correlation",
            process = %self.process_name,
            pid = self.pid,
            uid = self.uid,
            dest_ip = %ip,
            dest_port = port,
            "Process {} (PID {}) connected to {}:{}",
            self.process_name,
            self.pid,
            ip,
            port,
        );
    }
}

#[inline]
fn argv0_to_process_name(argv0: &[u8]) -> String {
    let end = argv0
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(argv0.len());
    String::from_utf8_lossy(&argv0[..end]).into_owned()
}

#[inline]
fn format_ipv4(addr: u32) -> String {
    let octets = addr.to_be_bytes();
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

#[cfg(test)]
mod tests {
    use super::{argv0_to_process_name, CorrelationEngine, EnrichedNetworkEvent};
    use crate::monitoring::network_event::NetworkEvent;

    #[test]
    fn registers_process_and_correlates_network_event() {
        let engine = CorrelationEngine::new();
        let mut argv0 = [0u8; 128];
        argv0[..9].copy_from_slice(b"/bin/curl");
        engine.register_process(4242, &argv0);

        let event = NetworkEvent {
            pid: 4242,
            uid: 1000,
            dest_ip: u32::from_be_bytes([8, 8, 8, 8]),
            dest_port: 443u16.to_be(),
        };

        let enriched = engine.correlate(event).expect("correlation");
        assert_eq!(enriched.process_name, "/bin/curl");
        assert_eq!(enriched.pid, 4242);
        assert_eq!(enriched.dest_port, 443u16.to_be());
    }

    #[test]
    fn correlate_misses_unknown_pid() {
        let engine = CorrelationEngine::new();
        let event = NetworkEvent {
            pid: 1,
            uid: 0,
            dest_ip: 0,
            dest_port: 0,
        };
        assert!(engine.correlate(event).is_none());
    }

    #[test]
    fn argv0_truncates_at_null_terminator() {
        let mut buf = *b"/usr/bin/wget\0garbage";
        assert_eq!(argv0_to_process_name(&buf), "/usr/bin/wget");
        buf[0] = 0;
        assert_eq!(argv0_to_process_name(&buf), "");
    }

    #[test]
    fn enriched_event_log_format_fields() {
        let enriched = EnrichedNetworkEvent {
            pid: 99,
            uid: 1000,
            dest_ip: u32::from_be_bytes([203, 0, 113, 1]),
            dest_port: 80u16.to_be(),
            process_name: "curl".to_string(),
        };
        assert_eq!(enriched.process_name, "curl");
        assert_eq!(enriched.pid, 99);
    }
}
