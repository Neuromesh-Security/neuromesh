"""Slow Path inference orchestration for behavioral telemetry."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from src.inference.gnn_evaluator import AnomalyScore, GNNEvaluator
from src.streaming.kafka_consumer import (
    BEHAVIOR_ALERT,
    CRITICAL_ALERT,
    TelemetryEnvelope,
)

logger = logging.getLogger(__name__)


@dataclass
class PipelineStats:
    """Runtime counters for observability."""

    behavior_alerts: int = 0
    critical_alerts: int = 0
    anomalies_detected: int = 0
    dropped: int = 0


@dataclass
class AnomalyPipeline:
    """Routes Kafka telemetry to the GNN evaluator and records detections."""

    evaluator: GNNEvaluator = field(default_factory=GNNEvaluator)
    stats: PipelineStats = field(default_factory=PipelineStats)

    async def handle(self, envelope: TelemetryEnvelope) -> AnomalyScore | None:
        """Dispatch a telemetry envelope to the appropriate inference path."""
        if envelope.alert_type == BEHAVIOR_ALERT:
            return await self._handle_behavior(envelope)

        if envelope.alert_type == CRITICAL_ALERT:
            await self._handle_critical(envelope)
            return None

        self.stats.dropped += 1
        logger.warning("dropping unsupported alert_type=%s", envelope.alert_type)
        return None

    async def _handle_behavior(self, envelope: TelemetryEnvelope) -> AnomalyScore | None:
        self.stats.behavior_alerts += 1
        logger.info(
            "behavior alert | event_id=%s node=%s rule_id=%s spawn_count=%s",
            envelope.event_id,
            envelope.node_name,
            envelope.payload.get("rule_id"),
            envelope.payload.get("spawn_count"),
        )

        score = self.evaluator.ingest_behavior_alert(envelope)
        if score is not None:
            self.stats.anomalies_detected += 1
            logger.info(
                "anomaly detected | node=%s score=%.2f reason=%s graph_nodes=%d graph_edges=%d",
                score.node_id,
                score.score,
                score.reason,
                self.evaluator.node_count,
                self.evaluator.edge_count,
            )
        return score

    async def _handle_critical(self, envelope: TelemetryEnvelope) -> None:
        self.stats.critical_alerts += 1
        logger.info(
            "critical alert (Fast Path deterministic) | event_id=%s node=%s rule_id=%s binary=%s",
            envelope.event_id,
            envelope.node_name,
            envelope.payload.get("rule_id"),
            envelope.payload.get("binary_path"),
        )
