# datadog-forwarder

Kafka slow-path consumer that forwards Neuromesh `BEHAVIOR_ALERT` / `CRITICAL_ALERT`
envelopes to Datadog Logs API v2. Fully decoupled from the agent LSM enforcement
hot path. Mirrors `splunk-hec-forwarder` as a **separate crate** (no shared sink
process).

## Default-off

Forwarding is **inactive** unless all of the following are set:

- `NEUROMESH_DATADOG_SITE` **or** `NEUROMESH_DATADOG_LOGS_URL`
- `NEUROMESH_DATADOG_API_KEY_FILE` (absolute path to mounted Secret — same `_FILE`
  discipline as HEC token and policy-bundle token)
- `NEUROMESH_KAFKA_BROKERS`

When inactive, the process exits 0 after a single info log. Site is never defaulted
to US1.

## Kafka identity (must stay distinct)

This crate reads **`NEUROMESH_DATADOG_KAFKA_GROUP_ID`** (default `datadog-forwarder`).
It does **not** read `NEUROMESH_KAFKA_GROUP_ID` (that env belongs to
`ai-threat-detector`). Default is also distinct from `splunk-hec-forwarder`.

Consumption is an independent partition fetch (same as Splunk): both forwarders
see every message. A slow Datadog consumer cannot stall Splunk or the agent.

## Optional

| Variable | Default |
|----------|---------|
| `NEUROMESH_DATADOG_SITE` | (none — required unless URL override) |
| `NEUROMESH_DATADOG_LOGS_URL` | derived from site, e.g. `https://http-intake.logs.datadoghq.eu/api/v2/logs` |
| `NEUROMESH_DATADOG_KAFKA_TOPIC` | `neuromesh.telemetry.v1` |
| `NEUROMESH_DATADOG_KAFKA_GROUP_ID` | `datadog-forwarder` |
| `NEUROMESH_DATADOG_SERVICE` | `neuromesh-agent-ebpf-sensor` |
| `NEUROMESH_DATADOG_SOURCE` | `neuromesh` |
| `NEUROMESH_DATADOG_QUEUE_CAPACITY` | `8192` |
| `NEUROMESH_DATADOG_METRICS_PORT` | `9092` |

Supported sites: `datadoghq.com` (us1), `us3.datadoghq.com`, `us5.datadoghq.com`,
`datadoghq.eu` (eu1), `ap1.datadoghq.com`, `ap2.datadoghq.com`, `uk1.datadoghq.com`,
`ddog-gov.com`, `us2.ddog-gov.com`.

## Metrics

Prometheus `/metrics`:

- `dd_forwarded_total`
- `dd_forward_failed_total{reason=retryable|non_retryable|network}`
- `dd_forward_dropped_total{reason=queue_full|malformed}`
- `dd_forward_queue_depth`

## Build & test

```bash
cargo test -p datadog-forwarder
cargo run -p datadog-forwarder
```

Live Datadog verification is **not required** for merge. This service only consumes
Kafka and POSTs to Logs intake. Unit tests cover payload mapping, API-key file
loading, backpressure drops against an in-process mock intake (HTTP 202 / 503),
and manifest isolation from agent/eBPF crates. No Datadog account or droplet is
needed.
