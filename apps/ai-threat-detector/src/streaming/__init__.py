"""Streaming adapters for the Slow Path (Kafka → GNN)."""

from .kafka_consumer import (
    BEHAVIOR_ALERT,
    CRITICAL_ALERT,
    DEFAULT_TOPIC,
    SCHEMA_VERSION,
    AsyncTelemetryConsumer,
    TelemetryEnvelope,
    parse_telemetry_message,
)

__all__ = [
    "BEHAVIOR_ALERT",
    "CRITICAL_ALERT",
    "DEFAULT_TOPIC",
    "SCHEMA_VERSION",
    "AsyncTelemetryConsumer",
    "TelemetryEnvelope",
    "parse_telemetry_message",
]
