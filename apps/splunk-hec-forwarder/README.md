# splunk-hec-forwarder

Kafka slow-path consumer that forwards Neuromesh `BEHAVIOR_ALERT` / `CRITICAL_ALERT`
envelopes to Splunk HEC. Fully decoupled from the agent LSM enforcement hot path.

## Default-off

Forwarding is **inactive** unless all of the following are set:

- `NEUROMESH_SPLUNK_HEC_URL`
- `NEUROMESH_SPLUNK_HEC_TOKEN_FILE` (absolute path to mounted Secret — same `_FILE`
  discipline as `NEUROMESH_POLICY_BUNDLE_TOKEN_FILE`)
- `NEUROMESH_KAFKA_BROKERS`

When inactive, the process exits 0 after a single info log.

## Optional

| Variable | Default |
|----------|---------|
| `NEUROMESH_KAFKA_TOPIC` | `neuromesh.telemetry.v1` |
| `NEUROMESH_KAFKA_GROUP_ID` | `splunk-hec-forwarder` |
| `NEUROMESH_SPLUNK_HEC_SOURCETYPE` | `neuromesh:alert:v1` |
| `NEUROMESH_SPLUNK_HEC_SOURCE` | `neuromesh/agent-ebpf-sensor` |
| `NEUROMESH_SPLUNK_HEC_INDEX` | (omit) |
| `NEUROMESH_SPLUNK_HEC_QUEUE_CAPACITY` | `8192` |
| `NEUROMESH_SPLUNK_HEC_METRICS_PORT` | `9091` |

## Metrics

Prometheus `/metrics`:

- `hec_forwarded_total`
- `hec_forward_failed_total{reason=retryable|non_retryable|network}`
- `hec_forward_dropped_total{reason=queue_full|malformed}`
- `hec_forward_queue_depth`

## Build & test

```bash
cargo test -p splunk-hec-forwarder
cargo run -p splunk-hec-forwarder
```

Live verification is **not required** for merge: this service only consumes Kafka and
POSTs to HEC. Unit tests cover payload mapping, token file loading, backpressure drops,
and manifest isolation from agent/eBPF crates. Optional local mock HEC tests use an
in-process axum receiver (no real Splunk account).
