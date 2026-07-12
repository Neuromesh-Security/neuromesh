"""AI Threat Detector — Slow Path ingestion and GNN inference service."""

from .inference import AnomalyPipeline, AnomalyScore, GNNEvaluator, PipelineStats
from .streaming.kafka_consumer import (
    AsyncTelemetryConsumer,
    TelemetryEnvelope,
    parse_telemetry_message,
)

__all__ = [
    "AnomalyPipeline",
    "AnomalyScore",
    "AsyncTelemetryConsumer",
    "GNNEvaluator",
    "PipelineStats",
    "TelemetryEnvelope",
    "parse_telemetry_message",
]
