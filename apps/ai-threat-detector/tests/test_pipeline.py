"""Unit tests for the Slow Path pipeline (no Kafka broker required)."""

from __future__ import annotations

import json
import unittest

from src.inference.anomaly_pipeline import AnomalyPipeline
from src.inference.gnn_evaluator import GNNEvaluator
from src.streaming.kafka_consumer import (
    BEHAVIOR_ALERT,
    SCHEMA_VERSION,
    TelemetryEnvelope,
    parse_telemetry_message,
)


class ParseTelemetryMessageTests(unittest.TestCase):
    def test_parses_valid_behavior_envelope(self) -> None:
        raw = json.dumps(
            {
                "event_id": "evt-1",
                "timestamp_ns": 1710000000000000000,
                "node_name": "worker-01",
                "schema_version": SCHEMA_VERSION,
                "alert_type": BEHAVIOR_ALERT,
                "payload": {"ppid": 1, "last_pid": 2, "spawn_count": 8},
            }
        ).encode()

        envelope = parse_telemetry_message(raw)
        self.assertEqual(envelope.event_id, "evt-1")
        self.assertEqual(envelope.alert_type, BEHAVIOR_ALERT)
        self.assertEqual(envelope.payload["spawn_count"], 8)


class GNNEvaluatorTests(unittest.TestCase):
    def test_flags_rapid_edge_growth(self) -> None:
        evaluator = GNNEvaluator(edge_growth_threshold=3, growth_window_secs=60.0)

        score = None
        for child_pid in range(101, 105):
            envelope = TelemetryEnvelope(
                event_id=f"evt-{child_pid}",
                timestamp_ns=child_pid,
                node_name="host-a",
                schema_version=SCHEMA_VERSION,
                alert_type=BEHAVIOR_ALERT,
                payload={
                    "ppid": 100,
                    "last_pid": child_pid,
                    "last_comm": "bash",
                    "last_binary_path": "/usr/bin/bash",
                    "spawn_count": 4,
                },
            )
            score = evaluator.ingest_behavior_alert(envelope)

        self.assertIsNotNone(score)
        self.assertGreater(score.score, 0.0)
        self.assertGreaterEqual(evaluator.edge_count, 4)


class AnomalyPipelineTests(unittest.IsolatedAsyncioTestCase):
    async def test_routes_behavior_alert_to_evaluator(self) -> None:
        pipeline = AnomalyPipeline(
            evaluator=GNNEvaluator(edge_growth_threshold=1, growth_window_secs=60.0)
        )
        envelope = TelemetryEnvelope(
            event_id="evt-2",
            timestamp_ns=2,
            node_name="host-b",
            schema_version=SCHEMA_VERSION,
            alert_type=BEHAVIOR_ALERT,
            payload={"ppid": 10, "last_pid": 11, "spawn_count": 9},
        )

        await pipeline.handle(envelope)
        self.assertEqual(pipeline.stats.behavior_alerts, 1)


if __name__ == "__main__":
    unittest.main()
