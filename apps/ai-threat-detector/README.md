# AI Threat Detector (Slow Path)

Python service consuming Kafka telemetry from `agent-ebpf-sensor` and routing
alerts to the GNN anomaly engine.

## Kafka Consumer

```bash
pip install -r requirements.txt
export NEUROMESH_KAFKA_BROKERS=localhost:9092
export NEUROMESH_KAFKA_TOPIC=neuromesh.telemetry.v1
python -m src.streaming.kafka_consumer
```

## Expected Message Envelope

```json
{
  "event_id": "NEUROMESH-EXEC-BLACKLIST-PATH-42-1",
  "timestamp_ns": 1710000000000000000,
  "node_name": "worker-01",
  "schema_version": "neuromesh.telemetry.v1",
  "alert_type": "CRITICAL_ALERT",
  "payload": { }
}
```

Supported `alert_type` values: `CRITICAL_ALERT`, `BEHAVIOR_ALERT`.
