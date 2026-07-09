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

## 🏢 Open Core Strategy

Neuromesh embraces the open-source community to ensure trust, transparency, and frictionless adoption. 
*   **Open Source (Apache 2.0):** The core eBPF sensor, fundamental telemetry hubs, and raw mutating webhooks.
*   **Enterprise Edition:** Advanced GNN models, Post-Quantum Cryptography (PQC) implementations, OIDC/SAML integrations, and strictly audited RBAC dashboards.

## 📂 Repository Structure
* `/apps` - Autonomous deployable units (eBPF Sensor, AI Detector, ZT Engine).
* `/packages` - Shared internal libraries (Crypto, Telemetry, UI UI Kit).

---
*Built for environments where milliseconds matter.*