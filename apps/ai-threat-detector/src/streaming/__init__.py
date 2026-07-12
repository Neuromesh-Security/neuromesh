"""Streaming adapters for the Slow Path (Kafka → GNN)."""

from .kafka_consumer import (
    DEFAULT_TOPIC,
    SCHEMA_VERSION,
    build_consumer,
    consume_loop,
    parse_telemetry_message,
    route_to_gnn,
)

__all__ = [
    "DEFAULT_TOPIC",
    "SCHEMA_VERSION",
    "build_consumer",
    "consume_loop",
    "parse_telemetry_message",
    "route_to_gnn",
]
