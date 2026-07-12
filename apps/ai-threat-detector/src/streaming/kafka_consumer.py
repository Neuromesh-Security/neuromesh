"""Kafka Slow Path consumer for Neuromesh AI threat detection.

Consumes JSON telemetry envelopes published by `agent-ebpf-sensor` on topic
`neuromesh.telemetry.v1` and routes CRITICAL_ALERT / BEHAVIOR_ALERT events to
the GNN inference pipeline.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Callable, Final

logger = logging.getLogger(__name__)

SCHEMA_VERSION: Final[str] = "neuromesh.telemetry.v1"
DEFAULT_TOPIC: Final[str] = "neuromesh.telemetry.v1"
SUPPORTED_ALERT_TYPES: Final[set[str]] = {"CRITICAL_ALERT", "BEHAVIOR_ALERT"}


def parse_telemetry_message(raw: bytes) -> dict[str, Any]:
    """Validate and parse a Kafka payload from the Fast Path exporter."""
    event = json.loads(raw)

    if event.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            f"unsupported schema_version: {event.get('schema_version')!r}"
        )

    alert_type = event.get("alert_type")
    if alert_type not in SUPPORTED_ALERT_TYPES:
        raise ValueError(f"unsupported alert_type: {alert_type!r}")

    if "payload" not in event:
        raise ValueError("missing payload field")

    return event


def route_to_gnn(event: dict[str, Any]) -> None:
    """Placeholder for the GNN Slow Path inference pipeline."""
    logger.info(
        "routing to GNN | alert_type=%s rule_id=%s node=%s",
        event.get("alert_type"),
        event.get("payload", {}).get("rule_id"),
        event.get("node_name"),
    )


def consume_loop(
    consumer: Any,
    handler: Callable[[dict[str, Any]], None] = route_to_gnn,
) -> None:
    """Blocking consumer loop — intended to run in the ai-threat-detector service."""
    for message in consumer:
        try:
            event = parse_telemetry_message(message.value)
            handler(event)
        except (json.JSONDecodeError, ValueError) as error:
            logger.warning("dropping malformed telemetry message: %s", error)


def build_consumer() -> Any:
    """Construct a KafkaConsumer from environment variables."""
    try:
        from kafka import KafkaConsumer
    except ImportError as error:  # pragma: no cover - optional dev dependency
        raise RuntimeError(
            "kafka-python is required for the Slow Path consumer"
        ) from error

    brokers = os.getenv("NEUROMESH_KAFKA_BROKERS", "localhost:9092")
    topic = os.getenv("NEUROMESH_KAFKA_TOPIC", DEFAULT_TOPIC)
    group_id = os.getenv("NEUROMESH_KAFKA_GROUP_ID", "ai-threat-detector")

    return KafkaConsumer(
        topic,
        bootstrap_servers=[broker.strip() for broker in brokers.split(",") if broker.strip()],
        group_id=group_id,
        auto_offset_reset="earliest",
        enable_auto_commit=True,
        value_deserializer=lambda value: value,
    )


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    consumer = build_consumer()
    logger.info("ai-threat-detector consuming topic=%s", DEFAULT_TOPIC)
    consume_loop(consumer)


if __name__ == "__main__":
    main()
