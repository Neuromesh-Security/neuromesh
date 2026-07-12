use crate::normalizer::{BehaviorAlert, DataNormalizer};
use crate::rules::{RuleEngine, RuleVerdict, SiemAlert};
use neuromesh_common::SecurityTelemetryEvent;

/// Aggregated output from a single telemetry event through the detection pipeline.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct PipelineOutput {
    pub behavior_alerts: Vec<BehaviorAlert>,
    pub siem_alerts: Vec<SiemAlert>,
}

/// Kernel-agnostic orchestration of RuleEngine and DataNormalizer.
#[derive(Debug)]
pub struct TelemetryPipeline {
    rule_engine: RuleEngine,
    data_normalizer: DataNormalizer,
}

impl TelemetryPipeline {
    pub fn new() -> Self {
        Self {
            rule_engine: RuleEngine::new(),
            data_normalizer: DataNormalizer::new(),
        }
    }

    /// Process one telemetry event without requiring eBPF maps or RingBuf I/O.
    pub fn process(&mut self, event: &SecurityTelemetryEvent) -> PipelineOutput {
        let mut output = PipelineOutput::default();

        if let Some(alert) = self.data_normalizer.ingest(event) {
            output.behavior_alerts.push(alert);
        }

        if let RuleVerdict::Alert(alert) = self.rule_engine.evaluate(event) {
            output.siem_alerts.push(alert);
        }

        output
    }

    /// Drain a static or mocked event vector through the full pipeline.
    pub fn process_batch(&mut self, events: &[SecurityTelemetryEvent]) -> PipelineOutput {
        let mut combined = PipelineOutput::default();
        for event in events {
            let partial = self.process(event);
            combined
                .behavior_alerts
                .extend(partial.behavior_alerts.into_iter());
            combined.siem_alerts.extend(partial.siem_alerts.into_iter());
        }
        combined
    }
}

impl Default for TelemetryPipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neuromesh_common::{MAX_COMM_LEN, MAX_FILENAME_LEN};

    fn event(path: &str) -> SecurityTelemetryEvent {
        let mut filename = [0u8; MAX_FILENAME_LEN];
        filename[..path.len()].copy_from_slice(path.as_bytes());
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
    fn pipeline_flags_blacklisted_path() {
        let mut pipeline = TelemetryPipeline::new();
        let output = pipeline.process(&event("/tmp/payload"));

        assert_eq!(output.siem_alerts.len(), 1);
        assert!(output.behavior_alerts.is_empty());
    }

    #[test]
    fn pipeline_process_batch_aggregates_alerts() {
        let mut pipeline = TelemetryPipeline::new();
        let events = vec![event("/bin/ls"), event("/tmp/a"), event("/tmp/b")];
        let output = pipeline.process_batch(&events);

        assert_eq!(output.siem_alerts.len(), 2);
    }
}
