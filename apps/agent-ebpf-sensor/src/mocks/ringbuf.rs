use neuromesh_common::{SecurityTelemetryEvent, TelemetryHealthStats};

/// In-memory RingBuf substitute backed by static event vectors.
#[derive(Debug, Clone)]
pub struct MockRingBuf {
    pending: Vec<SecurityTelemetryEvent>,
    stats: TelemetryHealthStats,
}

impl MockRingBuf {
    pub fn from_events(events: Vec<SecurityTelemetryEvent>) -> Self {
        Self {
            pending: events,
            stats: TelemetryHealthStats {
                events_processed: 0,
                lost_events_count: 0,
            },
        }
    }

    pub fn with_stats(mut self, stats: TelemetryHealthStats) -> Self {
        self.stats = stats;
        self
    }

    /// Drain all pending events as if polled from `TELEMETRY_RINGBUF`.
    pub fn drain(&mut self) -> Vec<SecurityTelemetryEvent> {
        let drained = std::mem::take(&mut self.pending);
        self.stats.events_processed = self
            .stats
            .events_processed
            .saturating_add(drained.len() as u64);
        drained
    }

    pub fn health_stats(&self) -> TelemetryHealthStats {
        self.stats
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neuromesh_common::{SecurityTelemetryEvent, MAX_COMM_LEN, MAX_FILENAME_LEN};

    fn sample_event() -> SecurityTelemetryEvent {
        let mut filename = [0u8; MAX_FILENAME_LEN];
        filename[..7].copy_from_slice(b"/bin/ls");
        SecurityTelemetryEvent {
            pid: 1,
            ppid: 1,
            uid: 1000,
            euid: 1000,
            comm: [0u8; MAX_COMM_LEN],
            filename,
        }
    }

    #[test]
    fn drain_updates_health_counters() {
        let mut ring = MockRingBuf::from_events(vec![sample_event(), sample_event()]);
        let drained = ring.drain();
        assert_eq!(drained.len(), 2);
        assert_eq!(ring.health_stats().events_processed, 2);
        assert_eq!(ring.pending_count(), 0);
    }
}
