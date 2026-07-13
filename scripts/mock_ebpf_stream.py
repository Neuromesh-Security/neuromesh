#!/usr/bin/env python3
"""Synthetic Ring 0 telemetry injector for Neuromesh Slow Path validation.

Publishes JSON envelopes compatible with `agent-ebpf-sensor` → Kafka →
`ai-threat-detector` (schema: neuromesh.telemetry.v1).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Final

SCHEMA_VERSION: Final[str] = "neuromesh.telemetry.v1"
DEFAULT_TOPIC: Final[str] = "neuromesh.telemetry.v1"
BEHAVIOR_ALERT: Final[str] = "BEHAVIOR_ALERT"
CRITICAL_ALERT: Final[str] = "CRITICAL_ALERT"
NODE_NAME: Final[str] = "neuromesh-dev"
SPIFFE_ID: Final[str] = "spiffe://neuromesh/agent"


def utc_rfc3339() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def timestamp_ns() -> int:
    return time.time_ns()


def envelope(
    *,
    alert_type: str,
    payload: dict[str, Any],
    event_id: str | None = None,
) -> dict[str, Any]:
    return {
        "event_id": event_id or str(uuid.uuid4()),
        "timestamp_ns": timestamp_ns(),
        "node_name": NODE_NAME,
        "schema_version": SCHEMA_VERSION,
        "alert_type": alert_type,
        "payload": payload,
    }


def benign_behavior(pid: int, ppid: int = 1) -> dict[str, Any]:
    return envelope(
        alert_type=BEHAVIOR_ALERT,
        payload={
            "timestamp": utc_rfc3339(),
            "severity": BEHAVIOR_ALERT,
            "rule_id": "NEUROMESH-EXEC-BASELINE",
            "rule_name": "Benign process execution",
            "ppid": ppid,
            "spawn_count": 1,
            "window_secs": 2,
            "last_pid": pid,
            "last_comm": "ls",
            "last_binary_path": "/bin/ls",
            "spiffe_id": SPIFFE_ID,
            "syscall": "execve",
        },
    )


def lateral_critical_bash() -> dict[str, Any]:
    return envelope(
        alert_type=CRITICAL_ALERT,
        event_id="sim-t1204-bash-exec",
        payload={
            "timestamp": utc_rfc3339(),
            "severity": CRITICAL_ALERT,
            "rule_id": "NEUROMESH-EXEC-BLACKLIST-PATH",
            "rule_name": "Execution from ephemeral malware staging directory",
            "pid": 4401,
            "ppid": 4400,
            "uid": 1000,
            "euid": 1000,
            "comm": "bash",
            "binary_path": "/tmp/neuromesh-lateral-payload.sh",
            "matched_pattern": "/tmp/",
            "spiffe_id": SPIFFE_ID,
            "syscall": "execve",
            "identity": SPIFFE_ID,
        },
    )


def lateral_critical_curl() -> dict[str, Any]:
    return envelope(
        alert_type=CRITICAL_ALERT,
        event_id="sim-t1071-curl-exfil",
        payload={
            "timestamp": utc_rfc3339(),
            "severity": CRITICAL_ALERT,
            "rule_id": "NEUROMESH-NET-UNKNOWN-EGRESS",
            "rule_name": "Outbound curl to unknown external endpoint",
            "pid": 4402,
            "ppid": 4401,
            "uid": 1000,
            "euid": 1000,
            "comm": "curl",
            "binary_path": "/usr/bin/curl",
            "matched_pattern": "203.0.113.50",
            "spiffe_id": SPIFFE_ID,
            "syscall": "connect",
            "source_ip": "10.42.0.12",
            "destination_ip": "203.0.113.50",
            "destination_port": 443,
        },
    )


def lateral_behavior_burst(ppid: int, child_pid: int, spawn_count: int) -> dict[str, Any]:
    return envelope(
        alert_type=BEHAVIOR_ALERT,
        event_id=f"sim-t1059-burst-{ppid}-{child_pid}",
        payload={
            "timestamp": utc_rfc3339(),
            "severity": BEHAVIOR_ALERT,
            "rule_id": "NEUROMESH-EXEC-SPAWN-BURST",
            "rule_name": "Abnormal process execution burst from single parent",
            "ppid": ppid,
            "spawn_count": spawn_count,
            "window_secs": 2,
            "last_pid": child_pid,
            "last_comm": "bash",
            "last_binary_path": "/bin/bash",
            "spiffe_id": SPIFFE_ID,
            "syscall": "execve",
            "identity": SPIFFE_ID,
        },
    )


def build_event_stream() -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []

    # Payload 1 — benign baseline
    events.append(benign_behavior(pid=1001))
    events.append(benign_behavior(pid=1002))
    events.append(
        envelope(
            alert_type=BEHAVIOR_ALERT,
            payload={
                "timestamp": utc_rfc3339(),
                "severity": BEHAVIOR_ALERT,
                "rule_id": "NEUROMESH-EXEC-BASELINE",
                "rule_name": "Benign network syscall",
                "ppid": 1,
                "spawn_count": 1,
                "window_secs": 2,
                "last_pid": 1003,
                "last_comm": "sshd",
                "last_binary_path": "/usr/sbin/sshd",
                "spiffe_id": SPIFFE_ID,
                "syscall": "accept",
                "source_ip": "10.42.0.1",
            },
        )
    )

    # Payload 2 — MITRE T1204 / T1059 lateral movement chain
    events.append(lateral_critical_bash())
    events.append(lateral_critical_curl())

    attack_ppid = 4400
    for index, child_pid in enumerate(range(4501, 4510), start=1):
        events.append(
            lateral_behavior_burst(
                ppid=attack_ppid,
                child_pid=child_pid,
                spawn_count=index + 4,
            )
        )
        time.sleep(0.05)

    return events


def publish_stream(brokers: str, topic: str) -> int:
    try:
        from confluent_kafka import Producer
    except ImportError as error:
        raise SystemExit(
            "confluent-kafka is required. Install with: pip install confluent-kafka"
        ) from error

    events = build_event_stream()
    producer = Producer({"bootstrap.servers": brokers, "client.id": "mock-ebpf-stream"})

    def delivery_callback(err: object, msg: object) -> None:
        if err is not None:
            print(f"[mock-ebpf] delivery failed: {err}", file=sys.stderr)

    for index, event in enumerate(events, start=1):
        payload = json.dumps(event).encode("utf-8")
        producer.produce(
            topic,
            key=event["event_id"].encode("utf-8"),
            value=payload,
            callback=delivery_callback,
        )
        print(
            f"[mock-ebpf] queued {index}/{len(events)} "
            f"type={event['alert_type']} id={event['event_id']}"
        )
        producer.poll(0)

    producer.flush(10)
    print(f"[mock-ebpf] published {len(events)} telemetry events to {topic} @ {brokers}")
    return len(events)


def main() -> None:
    parser = argparse.ArgumentParser(description="Inject synthetic eBPF telemetry into Kafka")
    parser.add_argument("--brokers", default="localhost:9092", help="Kafka bootstrap servers")
    parser.add_argument("--topic", default=DEFAULT_TOPIC, help="Telemetry topic name")
    args = parser.parse_args()

    count = publish_stream(args.brokers, args.topic)
    print(f"Threat Simulation Active. {count} events flowing to Kafka.")


if __name__ == "__main__":
    main()
