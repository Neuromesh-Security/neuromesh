use super::ringbuf::MockRingBuf;
use neuromesh_common::{SecurityTelemetryEvent, TelemetryHealthStats};

/// Abstraction over kernel telemetry producers for offline testing.
pub trait TelemetrySource {
    fn drain_events(&mut self) -> Vec<SecurityTelemetryEvent>;
    fn health_stats(&self) -> TelemetryHealthStats;
}

impl TelemetrySource for MockRingBuf {
    fn drain_events(&mut self) -> Vec<SecurityTelemetryEvent> {
        self.drain()
    }

    fn health_stats(&self) -> TelemetryHealthStats {
        MockRingBuf::health_stats(self)
    }
}

/// Static vector source mimicking repeated RingBuf polls.
#[derive(Debug, Clone)]
pub struct StaticTelemetrySource {
    chunks: Vec<Vec<SecurityTelemetryEvent>>,
    stats: TelemetryHealthStats,
}

impl StaticTelemetrySource {
    pub fn new(chunks: Vec<Vec<SecurityTelemetryEvent>>) -> Self {
        Self {
            chunks,
            stats: TelemetryHealthStats::default(),
        }
    }
}

impl TelemetrySource for StaticTelemetrySource {
    fn drain_events(&mut self) -> Vec<SecurityTelemetryEvent> {
        if self.chunks.is_empty() {
            return Vec::new();
        }
        let chunk = self.chunks.remove(0);
        self.stats.events_processed = self
            .stats
            .events_processed
            .saturating_add(chunk.len() as u64);
        chunk
    }

    fn health_stats(&self) -> TelemetryHealthStats {
        self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neuromesh_common::{SecurityTelemetryEvent, MAX_COMM_LEN, MAX_FILENAME_LEN};

    fn sample_event() -> SecurityTelemetryEvent {
        let mut filename = [0u8; MAX_FILENAME_LEN];
        filename[..9].copy_from_slice(b"/bin/bash");
        SecurityTelemetryEvent {
            pid: 7,
            ppid: 1,
            uid: 1000,
            euid: 1000,
            comm: [0u8; MAX_COMM_LEN],
            filename,
        }
    }

    #[test]
    fn static_source_drains_chunks_in_order() {
        let mut source = StaticTelemetrySource::new(vec![vec![sample_event()], vec![]]);
        assert_eq!(source.drain_events().len(), 1);
        assert_eq!(source.drain_events().len(), 0);
        assert_eq!(source.health_stats().events_processed, 1);
    }

    #[test]
    fn mock_ringbuf_implements_telemetry_source() {
        let mut ring = MockRingBuf::from_events(vec![sample_event()]);
        assert_eq!(TelemetrySource::drain_events(&mut ring).len(), 1);
        assert_eq!(TelemetrySource::health_stats(&ring).events_processed, 1);
    }
}
