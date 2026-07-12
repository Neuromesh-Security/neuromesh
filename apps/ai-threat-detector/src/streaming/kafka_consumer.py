"""Kafka Slow Path consumer for Neuromesh AI threat detection.

Consumes JSON telemetry envelopes published by `agent-ebpf-sensor` on topic
`neuromesh.telemetry.v1` using confluent-kafka with manual offset commits.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Final

logger = logging.getLogger(__name__)

SCHEMA_VERSION: Final[str] = "neuromesh.telemetry.v1"
DEFAULT_TOPIC: Final[str] = "neuromesh.telemetry.v1"
BEHAVIOR_ALERT: Final[str] = "BEHAVIOR_ALERT"
CRITICAL_ALERT: Final[str] = "CRITICAL_ALERT"
SUPPORTED_ALERT_TYPES: Final[set[str]] = {CRITICAL_ALERT, BEHAVIOR_ALERT}

EventHandler = Callable[["TelemetryEnvelope"], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class TelemetryEnvelope:
    """Deserialized Fast Path telemetry message."""

    event_id: str
    timestamp_ns: int
    node_name: str
    schema_version: str
    alert_type: str
    payload: dict[str, Any]

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> TelemetryEnvelope:
        return cls(
            event_id=str(raw["event_id"]),
            timestamp_ns=int(raw["timestamp_ns"]),
            node_name=str(raw.get("node_name", "unknown-node")),
            schema_version=str(raw["schema_version"]),
            alert_type=str(raw["alert_type"]),
            payload=dict(raw["payload"]),
        )


def parse_telemetry_message(raw: bytes) -> TelemetryEnvelope:
    """Validate and parse a Kafka payload from the Fast Path exporter."""
    event = json.loads(raw)

    if event.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            f"unsupported schema_version: {event.get('schema_version')!r}"
        )

    alert_type = event.get("alert_type")
    if alert_type not in SUPPORTED_ALERT_TYPES:
        raise ValueError(f"unsupported alert_type: {alert_type!r}")

    for field in ("event_id", "timestamp_ns", "payload"):
        if field not in event:
            raise ValueError(f"missing required field: {field}")

    return TelemetryEnvelope.from_dict(event)


class AsyncTelemetryConsumer:
    """Async Kafka consumer with graceful broker disconnect handling."""

    def __init__(
        self,
        *,
        brokers: str,
        topic: str,
        group_id: str,
        poll_timeout_sec: float = 1.0,
        reconnect_backoff_sec: float = 5.0,
    ) -> None:
        self._topic = topic
        self._poll_timeout_sec = poll_timeout_sec
        self._reconnect_backoff_sec = reconnect_backoff_sec
        self._running = False
        self._consumer = self._build_consumer(brokers, group_id, topic)

    @staticmethod
    def _build_consumer(brokers: str, group_id: str, topic: str) -> Any:
        try:
            from confluent_kafka import Consumer
        except ImportError as error:  # pragma: no cover - optional dev dependency
            raise RuntimeError(
                "confluent-kafka is required for the Slow Path consumer"
            ) from error

        consumer = Consumer(
            {
                "bootstrap.servers": brokers,
                "group.id": group_id,
                "auto.offset.reset": "earliest",
                "enable.auto.commit": False,
                "session.timeout.ms": 45000,
                "max.poll.interval.ms": 300000,
            }
        )
        consumer.subscribe([topic])
        return consumer

    @classmethod
    def from_env(cls) -> AsyncTelemetryConsumer:
        brokers = os.getenv("NEUROMESH_KAFKA_BROKERS", "localhost:9092")
        topic = os.getenv("NEUROMESH_KAFKA_TOPIC", DEFAULT_TOPIC)
        group_id = os.getenv("NEUROMESH_KAFKA_GROUP_ID", "ai-threat-detector")
        return cls(brokers=brokers, topic=topic, group_id=group_id)

    async def run(self, handler: EventHandler) -> None:
        """Consume messages until cancelled, committing offsets after each success."""
        from confluent_kafka import KafkaError, KafkaException

        self._running = True
        logger.info(
            "ai-threat-detector consuming topic=%s (manual commit enabled)",
            self._topic,
        )

        while self._running:
            try:
                message = await asyncio.to_thread(
                    self._consumer.poll, self._poll_timeout_sec
                )
            except KafkaException as error:
                logger.warning("broker disconnect (poll): %s", error)
                await asyncio.sleep(self._reconnect_backoff_sec)
                continue

            if message is None:
                continue

            if message.error():
                error = message.error()
                if error.code() == KafkaError._PARTITION_EOF:
                    continue
                if error.code() == KafkaError._TRANSPORT:
                    logger.warning("broker transport error: %s", error)
                    await asyncio.sleep(self._reconnect_backoff_sec)
                    continue
                logger.error("kafka consumer error: %s", error)
                await asyncio.sleep(self._reconnect_backoff_sec)
                continue

            try:
                envelope = parse_telemetry_message(message.value())
                await handler(envelope)
                await asyncio.to_thread(
                    self._consumer.commit, message=message, asynchronous=False
                )
            except (json.JSONDecodeError, ValueError, TypeError) as error:
                logger.warning(
                    "dropping malformed telemetry message (offset=%s): %s",
                    message.offset(),
                    error,
                )
                await asyncio.to_thread(
                    self._consumer.commit, message=message, asynchronous=False
                )
            except Exception:
                logger.exception(
                    "handler failed — offset not committed (offset=%s)",
                    message.offset(),
                )

    def stop(self) -> None:
        self._running = False
        self._consumer.close()
