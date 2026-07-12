# AI Threat Detector (Slow Path)

Python service consuming Kafka telemetry from `agent-ebpf-sensor` and routing
`BEHAVIOR_ALERT` events through a NetworkX-based GNN anomaly scaffold.

## Architecture

```
neuromesh.telemetry.v1 (Kafka)
        │
        ▼
AsyncTelemetryConsumer  (confluent-kafka, manual offset commit)
        │
        ▼
AnomalyPipeline
        ├─► BEHAVIOR_ALERT → GNNEvaluator (process graph + mock scoring)
        └─► CRITICAL_ALERT → logged (Fast Path deterministic)
```

## Requirements

- Python 3.11+
- `asyncio` (stdlib)
- `confluent-kafka` (librdkafka-backed high-throughput consumer)
- `networkx` (graph state for GNN scaffold)

## Quickstart

```bash
cd apps/ai-threat-detector
pip install -r requirements.txt

export NEUROMESH_KAFKA_BROKERS=localhost:9092
export NEUROMESH_KAFKA_TOPIC=neuromesh.telemetry.v1
export NEUROMESH_KAFKA_GROUP_ID=ai-threat-detector

python main.py
```

## Expected Message Envelope

```json
{
  "event_id": "NEUROMESH-EXEC-SPAWN-BURST-4242-110",
  "timestamp_ns": 1710000000000000000,
  "node_name": "worker-01",
  "schema_version": "neuromesh.telemetry.v1",
  "alert_type": "BEHAVIOR_ALERT",
  "payload": {
    "rule_id": "NEUROMESH-EXEC-SPAWN-BURST",
    "ppid": 4242,
    "last_pid": 110,
    "spawn_count": 8
  }
}
```

## GNN Scaffold (Sprint)

- **Nodes:** `proc:{host}:{pid}:{comm}` process identities
- **Edges:** parent → child execution relationships from burst alerts
- **Scoring:** mock lateral-movement detector flags nodes with rapid out-edge
  growth within a sliding time window

## Reliability

- Manual offset commits after successful handler execution (no data loss on crash)
- Malformed messages are committed and skipped to avoid poison-pill loops
- Broker transport errors trigger backoff and automatic poll retry

## Environment

| Variable | Default | Purpose |
|----------|---------|---------|
| `NEUROMESH_KAFKA_BROKERS` | `localhost:9092` | Bootstrap brokers |
| `NEUROMESH_KAFKA_TOPIC` | `neuromesh.telemetry.v1` | Consumed topic |
| `NEUROMESH_KAFKA_GROUP_ID` | `ai-threat-detector` | Consumer group |
