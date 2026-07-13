# 🛡️ Neuromesh Security

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)
![Version](https://img.shields.io/badge/Version-v0.1.0--alpha-orange.svg)
![Architecture](https://img.shields.io/badge/Architecture-eBPF%20%7C%20Wasm%20%7C%20GNN-success.svg)

> **Next-Generation Zero Trust & eBPF Runtime Security.**
> Bridging deep kernel visibility with asynchronous artificial intelligence for Kubernetes.

## 🚀 The Dual-Path Architecture

Neuromesh operates strictly on a philosophy where performance is non-negotiable. We separate security into two distinct layers:
*   **The Fast Path (Synchronous):** Rust/C-based eBPF sensors and Wasm execution environments that block deterministic threats (e.g., unauthorized syscalls) instantly, directly in the kernel, with sub-millisecond latency.
*   **The Slow Path (Asynchronous):** Out-of-band telemetry flows via Kafka to our Python/Mojo AI engine. Here, Graph Neural Networks (GNN) analyze complex lateral movement and generate mitigation signals without ever throttling your production traffic.

## 🏢 Open Core Model

Neuromesh follows an **Open Core** commercial strategy: the runtime sensor and deterministic detection logic are open source under Apache 2.0, while AI-driven anomaly detection, enterprise integrations, and fleet operations are offered as a commercial subscription.

### Community Edition (Open Source)

Free forever. Ideal for security engineers, homelabs, and teams validating eBPF runtime protection.

| Capability | Included |
|------------|----------|
| eBPF Dual-Path sensor (LSM blocking + tracepoint telemetry) | ✅ |
| User-space `RuleEngine` (whitelist + blacklist path rules) | ✅ |
| `DataNormalizer` behavioral burst detection | ✅ |
| Local JSON alert logging (stdout / container logs) | ✅ |
| Integration test farm + Criterion performance baseline | ✅ |
| Kubernetes DaemonSet manifest (`deploy/kubernetes/`) | ✅ |
| MITRE ATT&CK threat model + attack simulation scripts | ✅ |

**License:** Apache 2.0 · **Support:** Community (GitHub Issues)

### Enterprise Edition (Commercial)

For regulated industries, SOC teams, and multi-cluster Kubernetes estates requiring AI-assisted detection and centralized operations.

| Capability | Included |
|------------|----------|
| AI / GNN Anomaly Engine (Kafka Slow Path, lateral movement) | ✅ |
| SIEM integrations (Splunk HEC, Datadog, Elastic, Sentinel) | ✅ |
| Post-Quantum Cryptography (PQC) signed telemetry envelopes | ✅ |
| Fleet Management (multi-cluster policy sync, RBAC console) | ✅ |
| OIDC / SAML SSO, audited admin dashboards | ✅ |
| 24×7 SLA, dedicated TAM, custom MITRE detection packs | ✅ |

**Pricing:** Contact [sales@neuromesh.security](mailto:sales@neuromesh.security) · **Deployment:** Helm + SaaS control plane

### Why Open Core?

| Stakeholder | Value |
|-------------|-------|
| **Security community** | Inspect Ring 0 code, reproduce detections, contribute rules |
| **Procurement** | Prove nanosecond overhead (`docs/performance-baseline.md`) before license commitment |
| **Enterprise buyers** | Upgrade path from proven open-source sensor to AI + SIEM without rip-and-replace |

> The Community Edition is production-capable for single-cluster deployments with JSON logging. The Enterprise Edition adds the Slow Path AI pipeline and operational scale required for global SOCs.

## 📂 Repository Structure

* `/apps` — Autonomous deployable units (eBPF Sensor, AI Detector, ZT Engine).
  * `agent-ebpf-sensor` — Dual-path eBPF sensor and user-space orchestrator (Fast Path).
  * `ai-threat-detector` — Kafka consumer and GNN Slow Path inference service.
  * `zt-policy-engine` — Go control plane: OPA policy evaluation + SPIFFE identity.
  * `k8s-admission-webhook` — Validating/mutating admission webhook (TLS enforcement).
  * `security-dashboard` — Next.js 16 Enterprise command center (OIDC/SAML RBAC, dual-path telemetry).
* `/deploy` — Production deployment manifests.
  * `kubernetes/neuromesh-agent.yaml` — Privileged DaemonSet for per-node eBPF enforcement.
* `/packages` — Shared internal libraries.
  * `neuromesh-common` — Kernel/user-space shared types and BPF map contracts.
  * `telemetry` — Standard `MetricEvent` contract for Kafka and observability pipelines.
  * `proto-definitions` — Protobuf schemas for cross-service telemetry.
  * `shared-ui-kit` — Enterprise UI primitives (`VirtualizedLogGrid`, `ThreatMap`).
* `/docs` — Architecture decision records and design documentation.
  * `threat-model.md` — MITRE ATT&CK mapping and integration test traceability.
  * `performance-baseline.md` — Criterion micro-benchmark results and complexity analysis.
* `/scripts` — Red team simulations and operational tooling.
  * `simulate_attack.sh` — MITRE T1059/T1204 proof-of-value attack simulation.
* `/tests` — Kernel-independent integration test farm (`neuromesh-integration-tests`).

## ☸️ Kubernetes Deployment

```bash
kubectl apply -f deploy/kubernetes/neuromesh-agent.yaml
kubectl logs -n neuromesh-system -l app.kubernetes.io/name=neuromesh-agent -f
```

The DaemonSet mounts `/sys/fs/bpf`, `/sys/kernel/debug`, and host `/` (read-only) with `CAP_BPF`, `CAP_SYS_ADMIN`, and `CAP_PERFMON` for eBPF program attachment.

## 🛠️ Prerequisites & Quickstart

Neuromesh operates at Ring 0 and requires a modern environment for eBPF bytecode compilation and kernel injection.

### System Requirements
* **OS:** Linux Kernel `5.8` or higher (for complete BPF Memory Map and Ring Buffer support).
* **Toolchain:** Rust Nightly (required for `core` and `compiler_builtins`).
* **Dependencies:** `bpf-linker`

### Setup & Compilation
```bash
# 0. Run logic tests locally (no eBPF kernel required)
cargo test -p neuromesh-integration-tests
cargo test -p agent-ebpf-sensor --lib

# 1. Install the eBPF linker
cargo install bpf-linker

# 2. Compile the kernel-space eBPF program
cargo xtask build-ebpf --release

# 3. Run the user-space orchestrator (Root privileges required for bpf() syscall)
RUST_LOG=info sudo -E cargo run -p agent-ebpf-sensor --features orchestrator --release

# 3b. Enable Kafka Slow Path export (optional — non-blocking; Fast Path unaffected if broker is down)
export NEUROMESH_KAFKA_BROKERS=localhost:9092
export NEUROMESH_KAFKA_TOPIC=neuromesh.telemetry.v1
export NEUROMESH_NODE_NAME=$(hostname)

# 4. Trigger proof-of-value alerts (separate terminal)
chmod +x scripts/simulate_attack.sh
./scripts/simulate_attack.sh
```

## 🐳 E2E Local Stack (Docker Compose)

Spin up the full Dual-Path architecture on a **Linux host** with Docker Engine:

```bash
docker compose up --build
```

| Service | Port | Role |
|---------|------|------|
| `kafka` | 9092 | KRaft-mode broker (no Zookeeper) |
| `zt-policy-engine` | 8080 | OPA Zero Trust API (`GET /healthz`, `POST /v1/evaluate`) |
| `ai-threat-detector` | — | Kafka → GNN Slow Path consumer |
| `agent-ebpf-sensor` | — | Privileged eBPF Fast Path + Kafka producer |

```bash
# Verify control plane
curl -s http://localhost:8080/healthz | jq .

# Tail Slow Path inference
docker compose logs -f ai-threat-detector

# Trigger Fast Path alerts (host terminal)
./scripts/simulate_attack.sh
```

> **Note:** `agent-ebpf-sensor` requires `privileged: true`, `pid: host`, and
> `/sys/kernel/debug` mounts — it will not attach eBPF programs on macOS/Windows
> Docker Desktop. Use native Linux or a Linux VM for full E2E validation.

---
*Built for environments where milliseconds matter.*
