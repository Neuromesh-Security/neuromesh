# Neuromesh Security Verification Summary

**Audience:** technical evaluators / security auditors  
**Document type:** consolidated evidence package (citations required)  
**Release scope:** [`v0.1.0-core`](RELEASE_v0.1.0-core.md) (tag date **2026-07-14**)  
**Generated from:** in-repo docs, manifests, live-verify scripts, and merged PR history  
**Last evidence refresh:** 2026-08-29 (includes merged [#180](https://github.com/Neuromesh-Security/neuromesh/pull/180) / [#177](https://github.com/Neuromesh-Security/neuromesh/pull/177))

Every substantive claim below cites a **PR**, **issue**, or **file path**. Where a figure or live-run scenario cannot be traced to those sources, the text says **TBD — verify** rather than inventing detail.

---

## 1. Executive summary

Neuromesh is an eBPF-based runtime protection platform: a Linux agent attaches a BPF LSM program (`bprm_check_security`) to **deny** execution from ephemeral staging prefixes (`/tmp/`, `/dev/shm/`, `/var/tmp/`) synchronously in-kernel, while separate visibility programs feed process/network telemetry into user-space detection and optional SIEM forwarding ([`docs/RELEASE_v0.1.0-core.md`](RELEASE_v0.1.0-core.md), [`docs/architecture-decision-records/adr-001-lsm-vs-tracepoint.md`](architecture-decision-records/adr-001-lsm-vs-tracepoint.md)).

Architecture is **dual-path**: a **synchronous Fast Path** (kernel LSM enforcement + agent policy sync from the zt-policy-engine) and an **asynchronous Slow Path** (Kafka consumers → SIEM forwarders and a scaffold GNN evaluator that must never block the syscall hot path) ([`README.md`](../README.md) Slow Path table; [`apps/ai-threat-detector`](../apps/ai-threat-detector)).

Licensing is **Apache License 2.0** ([`LICENSE`](../LICENSE)) under an **Open Core** model: runtime sensor and deterministic detection are open; commercial layers (enterprise integrations, fleet ops, fuller AI) are described separately ([`README.md`](../README.md) § Open Core Model).

Current engineering-grade milestone is **`v0.1.0-core`**. The project is **solo-maintained** ([`README.md`](../README.md) support row: “solo-maintained project”).

---

## 2. Security controls — live-verified

### 2.1 LSM enforcement survives agent `kill -9`

| | |
|--|--|
| **PR / issue** | [#72](https://github.com/Neuromesh-Security/neuromesh/pull/72) (merged 2026-07-23) — *pin LSM link + PATH_DENY maps so deny survives agent exit*; tracking [#44](https://github.com/Neuromesh-Security/neuromesh/issues/44) |
| **Mechanism** | LSM link + deny maps pinned under bpffs; pin failure aborts startup (fail-closed) ([`docs/threat-model.md`](threat-model.md) residual table; [`docs/performance-baseline.md`](performance-baseline.md) capability row) |
| **Live method** | [`scripts/manual_verify_lsm_pin.sh`](../scripts/manual_verify_lsm_pin.sh) — start agent, confirm deny on `/tmp/` probe, `kill -9` agent, re-probe deny still enforced |

### 2.2 Bytecode attestation (Cosign) — fail-closed on mismatch

| | |
|--|--|
| **PR / issue** | [#62](https://github.com/Neuromesh-Security/neuromesh/pull/62) (merged 2026-07-18) — Phase 1 signed bytecode attestation (Issue [#44](https://github.com/Neuromesh-Security/neuromesh/issues/44)) |
| **Mechanism** | Cosign-static-key signed bytecode manifest verified **before** any BPF load for `sys_exec.bpf.o`, `network_filter.bpf.o`, and LSM enforcement ELF ([`docs/threat-model.md`](threat-model.md) §7 Agent tampering; [`apps/agent-ebpf-sensor/src/startup.rs`](../apps/agent-ebpf-sensor/src/startup.rs) `bytecode_attestation::verify_startup`) |
| **Live method** | Wrong Cosign pubkey (e.g. lab key vs `deploy/kubernetes/ci-cosign.pub`) correctly fail-closes at agent start — documented in [`scripts/manual_verify_k8s_policy_engine.sh`](../scripts/manual_verify_k8s_policy_engine.sh) header and [`deploy/kubernetes/README.md`](../deploy/kubernetes/README.md) |

### 2.3 Runtime tamper detection (pin / binary watchdog)

| | |
|--|--|
| **PR / issue** | [#74](https://github.com/Neuromesh-Security/neuromesh/pull/74) (2026-07-23) periodic integrity monitor; [#76](https://github.com/Neuromesh-Security/neuromesh/pull/76) (2026-07-25) on-disk install-path digest (Issue [#75](https://github.com/Neuromesh-Security/neuromesh/issues/75)) |
| **Measured window** | Detection within **≤60s** (default interval **45s**) for pin removal / binary replacement ([`docs/threat-model.md`](threat-model.md) E-07 / BPF hook disable row) |
| **Live method** | [`scripts/manual_verify_runtime_integrity.sh`](../scripts/manual_verify_runtime_integrity.sh) — (1) remove `PATH_DENY_LIST` pin → `reason=pinned_map`; (2) unlink+replace on-disk install path → `reason=on_disk_binary` |
| **Honest residual** | Detection-only vs determined root/`CAP_BPF` who also controls alert path or re-signs with a stolen key — **E-07**, not elimination ([`docs/RELEASE_v0.1.0-core.md`](RELEASE_v0.1.0-core.md); [`docs/threat-model.md`](threat-model.md)) |

### 2.4 Identity exceptions — dual-plane (bundle + Rego), drift-proof

| | |
|--|--|
| **PR / issue** | DesiredPolicy Rego coupling [#139](https://github.com/Neuromesh-Security/neuromesh/pull/139) (2026-08-17, Issue [#137](https://github.com/Neuromesh-Security/neuromesh/issues/137) PR-2); Slice 2b live identity docs [#99](https://github.com/Neuromesh-Security/neuromesh/pull/99) (2026-08-05) |
| **Unit proof (single mutation → both planes)** | `TestDesiredPolicyMutationMovesBundleAndRegoPlanes` in [`apps/zt-policy-engine/cmd/server/main_test.go`](../apps/zt-policy-engine/cmd/server/main_test.go) — one `ApplyValidated` must move **both** `GET /v1/policy-bundle` content and `POST /v1/evaluate` outcomes |
| **Live method** | Identity exception / correlator scripts under `scripts/manual_verify_identity_*.sh` (see [#99](https://github.com/Neuromesh-Security/neuromesh/pull/99)); dynamic dual-plane live gate in §2.6 |

### 2.5 Policy-bundle — Cosign signature + anti-replay (schema 3)

| | |
|--|--|
| **Signature** | [#109](https://github.com/Neuromesh-Security/neuromesh/pull/109) (2026-08-12) — Cosign-compatible detached signature (Issue [#108](https://github.com/Neuromesh-Security/neuromesh/issues/108)) |
| **Temporal / anti-replay** | [#111](https://github.com/Neuromesh-Security/neuromesh/pull/111) (2026-08-12) — T-PB-04; schema_version **3** with `not_before` / `not_after` inside signed JSON; default window **300s** (10 × 30s sync) |
| **Live method** | [`scripts/manual_verify_policy_bundle_signature.sh`](../scripts/manual_verify_policy_bundle_signature.sh) — sign/verify path plus **capture → wait → replay** of exact body bytes ([`docs/threat-model.md`](threat-model.md) T-PB-02 / T-PB-04 rows) |

### 2.6 Dynamic DesiredPolicy — ConfigMap → both planes → kernel

| | |
|--|--|
| **PR / issue** | Live script [#171](https://github.com/Neuromesh-Security/neuromesh/pull/171) (merged 2026-08-28); foundation [#138](https://github.com/Neuromesh-Security/neuromesh/pull/138) / Rego [#139](https://github.com/Neuromesh-Security/neuromesh/pull/139); RBAC audit [#175](https://github.com/Neuromesh-Security/neuromesh/pull/175) |
| **Script** | [`scripts/manual_verify_desired_policy_dynamic.sh`](../scripts/manual_verify_desired_policy_dynamic.sh) |
| **Scenario contract (in-repo, 7 scenarios)** | (1) ENABLE gate + initial reconcile; (2) VALID CHANGE — prefix + SPIFFE on **both** planes; (3) DOWNSTREAM — agent sync + **LSM deny** on dynamic prefix; (4) REJECTION — invalid CM retains LKG; (5) SAFETY RAIL — floor removal override vs regression; (6) RESTART SELF-HEAL — PE restart re-reads live ConfigMap; (7) cleanup / restore |
| **Citable claim level** | **Scenario contract verified in-repo (7 scenarios).** Live execution transcript (exact `PASS:` lines / wall-clock paste-back from a droplet run) is **not** recoverable from [#171](https://github.com/Neuromesh-Security/neuromesh/pull/171) PR body/comments or saved chat logs at document refresh time — **TBD — verify**. Do not read this section as “droplet paste-back attached here.” |

### 2.7 TLS rotation — zero-downtime class

| | |
|--|--|
| **PR / issue** | [#169](https://github.com/Neuromesh-Security/neuromesh/pull/169) (merged 2026-08-25) — Phase B part 2 cert-manager leaf renewal (Issue [#168](https://github.com/Neuromesh-Security/neuromesh/issues/168)); runbook in [`deploy/kubernetes/admission/README.md`](../deploy/kubernetes/admission/README.md) |
| **Live method** | [`scripts/manual_verify_admission_tls_rotation.sh`](../scripts/manual_verify_admission_tls_rotation.sh) — leaf renew **in place** (Secret never deleted); rolling restart with continuous `/healthz` sampling under **replicas ≥ 2** + PDB; require majority OK samples (`healthz_ok_samples` > `healthz_miss_samples`) |
| **“15-pod creation during rotation”** | **TBD — verify** — no in-repo script currently names a fixed **15-pod** admission churn metric; the checked-in live gate is the healthz-majority / rollout-status proof above. Do not treat “15 pods” as cited evidence until located in a PR paste-back. |

### 2.8 Rate limiting — PE yes; webhook deliberately no

| | |
|--|--|
| **Design** | [#176](https://github.com/Neuromesh-Security/neuromesh/issues/176) — webhook rate limiting **rejected** (only caller is kube-apiserver; dangerous under eventual `failurePolicy: Fail`); PE `GET /v1/policy-bundle` gets **coarse aggregate** limiting only (shared bearer → no per-client identity) |
| **Implementation** | [#177](https://github.com/Neuromesh-Security/neuromesh/pull/177) (merged 2026-08-29) — default **1000 RPS**; exceed → HTTP **429** + `Retry-After`; agent distinct 429 path (`policy sync throttled`, `policy_sync_throttled_total`) isolated from signature/temporal rejection |
| **Live method (PE)** | Lab curl burst under `NEUROMESH_POLICY_BUNDLE_RATE_LIMIT_RPS=1` against PE (documented in PE README env table [`apps/zt-policy-engine/README.md`](../apps/zt-policy-engine/README.md)) |
| **Agent 429 live** | Unit-test verified in [#177](https://github.com/Neuromesh-Security/neuromesh/pull/177); **full agent-loop live gate deferred** to [#178](https://github.com/Neuromesh-Security/neuromesh/issues/178) (Cosign CI private key not distributable to lab for feature-branch agent images) |

### 2.9 Token rotation — dual-trust N → N+1 → retire

| | |
|--|--|
| **Design** | [#179](https://github.com/Neuromesh-Security/neuromesh/issues/179) — N∥N+1, no automatic retire of N |
| **Implementation** | [#180](https://github.com/Neuromesh-Security/neuromesh/pull/180) (merged 2026-08-29) — PE accepted-set + `policy_bundle_auth_accept_total{fp=…}` (truncated SHA-256 hex only) |
| **Live method** | [`scripts/manual_verify_policy_bundle_token_rotation.sh`](../scripts/manual_verify_policy_bundle_token_rotation.sh) — dual-accept → agent roll to N+1 → soak `W=max(3×POLICY_SYNC_INTERVAL, 90s)` with **zero increase on fp_N** and **positive increase on fp_N+1** → human gate `RETIRE` → N returns **401**, N+1 **200** |
| **Operator paste-back timestamps** | **TBD — verify** against droplet transcript if auditors need wall-clock proof beyond script contract |

### 2.10 NetworkPolicy — PE + webhook, ALLOW / DENY live

| | |
|--|--|
| **PR / issue** | [#167](https://github.com/Neuromesh-Security/neuromesh/pull/167) (merged 2026-08-25) — Phase B part 1 (Issue [#166](https://github.com/Neuromesh-Security/neuromesh/issues/166)); Phase A webhook hardening [#164](https://github.com/Neuromesh-Security/neuromesh/pull/164) |
| **Manifests** | e.g. [`deploy/kubernetes/neuromesh-zt-policy-engine-networkpolicy.yaml`](../deploy/kubernetes/neuromesh-zt-policy-engine-networkpolicy.yaml) |
| **Live method** | [`scripts/manual_verify_network_policies.sh`](../scripts/manual_verify_network_policies.sh) — agent → PE `:8080` **ALLOW**; foreign pod (default ns) → PE `:8080` **DENY**; webhook path checks documented in script header |

### 2.11 SIEM forwarding — Splunk + Datadog, delivery + fault isolation

| | |
|--|--|
| **Implementation** | Splunk HEC [#146](https://github.com/Neuromesh-Security/neuromesh/pull/146) (2026-08-18); Datadog Logs [#149](https://github.com/Neuromesh-Security/neuromesh/pull/149) (2026-08-18) |
| **Live E2E** | [#173](https://github.com/Neuromesh-Security/neuromesh/pull/173) (merged 2026-08-28) — Issue [#172](https://github.com/Neuromesh-Security/neuromesh/issues/172) |
| **Script / scenarios** | [`scripts/manual_verify_siem_forwarders.sh`](../scripts/manual_verify_siem_forwarders.sh): mock HEC + Datadog v2 receivers; **real** agent spawn-burst `BEHAVIOR_ALERT` → both intakes; crate isolation regression; **fault isolation** — Splunk aimed at dead endpoint (`hec_forward_failed_total{reason=network}` rises) while Datadog still delivers burst #2 |

### 2.12 Supply chain — digest-pinned, Cosign-signed images

| Image | Digest pin (manifests / chart values) |
|-------|----------------------------------------|
| Agent | `ghcr.io/neuromesh-security/neuromesh-agent-ebpf-sensor@sha256:413424ce5ec990e97b58014daa05ae8addab27de5afcac74904eb28fdcd5de2d` |
| PE | `ghcr.io/neuromesh-security/neuromesh-zt-policy-engine@sha256:eceb694cc12409a935ca3d83a9ac856b0f3e4461131c63b193142aa828572255` |
| Admission webhook | `ghcr.io/neuromesh-security/neuromesh-k8s-admission-webhook@sha256:e3997b4c42763c2a2b488b3b0246e8bddaa071ba5d1328d6abd5ea118370e273` |

Sources: [`deploy/kubernetes/README.md`](../deploy/kubernetes/README.md), [`deploy/kubernetes/charts/neuromesh-security/values.yaml`](../deploy/kubernetes/charts/neuromesh-security/values.yaml), admission README Cosign pin note.  
**Publish / Cosign sign:** Production CI `Build Docker (*)` pushes and Cosign-signs **only** on `push` to `main` (`should_publish=true` in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)); PR builds are build+load only. Trust root for GHCR agent bytecode: [`deploy/kubernetes/ci-cosign.pub`](../deploy/kubernetes/ci-cosign.pub) (Issue [#114](https://github.com/Neuromesh-Security/neuromesh/issues/114) class).

### 2.13 Performance & reliability evidence

**Source of record:** [`docs/performance-baseline.md`](performance-baseline.md) (not marketing copy). Figures below are copied from that document’s measured claims.

| Claim | Exact figure | Citation |
|-------|--------------|----------|
| Idle agent CPU **pre** RingBuf/AsyncFd fix | ~**93–97%** of one core (busy-spin) | Issue [#103](https://github.com/Neuromesh-Security/neuromesh/issues/103); [`performance-baseline.md`](performance-baseline.md) §2.4 / §2.5; code comment in [`apps/agent-ebpf-sensor/src/monitoring/ringbuf_async_io.rs`](../apps/agent-ebpf-sensor/src/monitoring/ringbuf_async_io.rs) |
| Idle agent CPU **post** fix | **`0.400%`** of 1 core (correlator-off baseline) | PR [#104](https://github.com/Neuromesh-Security/neuromesh/pull/104) (fix); Issue [#100](https://github.com/Neuromesh-Security/neuromesh/issues/100) / [`performance-baseline.md`](performance-baseline.md) §2.5 table (`0.400`); also [`README.md`](../README.md) idle CPU row. **Do not use `0.3833%`** — that figure is not in the source of record. |
| Historical execve stress (pre-[#160](https://github.com/Neuromesh-Security/neuromesh/pull/160)) | Band **880–962 EPS**; best **`average_eps=962`**; **three** independent 30 s runs; **zero** RingBuf/MPSC drops | [`performance-baseline.md`](performance-baseline.md) §2.3 / historical table; example `spawned=28868`, `failed=0`, `elapsed=30.00s`, `average_eps=962` |
| Post-[#160](https://github.com/Neuromesh-Security/neuromesh/pull/160) apples-to-apples re-measure | **`average_eps=816`** (`spawned=24860`, `failed=0`, `elapsed=30.48s`, `workers=128`, `worker_model=std::thread`, `host_parallelism=1`) | [`performance-baseline.md`](performance-baseline.md) §2.3 / §2.3.2; docs PRs [#161](https://github.com/Neuromesh-Security/neuromesh/pull/161) / [#162](https://github.com/Neuromesh-Security/neuromesh/pull/162) |

**Honest finding (do not smooth):** **`816 < 962`.** The OS-thread generator fix ([#160](https://github.com/Neuromesh-Security/neuromesh/pull/160)) was **architecturally correct** (workers no longer serialize on one Tokio runtime thread) but did **not** raise the measured ceiling on this specific **1-vCPU** box; both post-#160 and historical runs are still **generator-bound**, not agent-bound ([`performance-baseline.md`](performance-baseline.md) §2.3.2: “OS threads did **not** raise the 1-vCPU generator above historical 962; 816 < 962 is expected when 128 threads fight one core”). Related (do not collapse into 816): sweep-best **`average_eps=738`** at 8 workers / 15 s is a different protocol.

---

## 3. CI/CD security pipeline

Workflows in-repo: [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) (**Production CI**), [`.github/workflows/security-scan-pipeline.yml`](../.github/workflows/security-scan-pipeline.yml) (**Security Scan Pipeline**). Both trigger on `pull_request` and `push` to `main` (see workflow `on:` blocks).

### 3.1 Production CI — representative jobs

| Job name (as in workflow) | Notes |
|---------------------------|--------|
| `Detect core path changes` | Paths filter / core flag |
| `Lint (work)` / gate `Lint` | fmt, clippy, BPF name length, sensor test enumeration |
| `Test` | Workspace libs, integration, neuromesh-common, sensor, telemetry, **splunk-hec-forwarder**, **datadog-forwarder**, **k8s-admission-webhook**, coverage gate ≥70% |
| `Build eBPF (work: ubuntu-22.04 / ~6.8-azure)` / `…24.04 / ~6.17-azure` | Honest kernel labels ([#158](https://github.com/Neuromesh-Security/neuromesh/pull/158)) |
| `eBPF Verifier (work: …)` | Live BTF + verify-ebpf |
| `Performance Regression` | events/sec gate |
| `E2E Detection Test` | Attack simulation / GNN insight probe |
| `Build Docker (neuromesh-{zt-policy-engine,agent-ebpf-sensor,k8s-admission-webhook})` | **PR:** build+load; **main push only:** push to GHCR + Cosign (`should_publish`) |

### 3.2 Security Scan Pipeline — representative jobs

| Job name | Role |
|----------|------|
| `Trivy — Filesystem` | FS CVE report + CRITICAL gate |
| `Semgrep — Static Analysis` | SAST |
| `SAST — Go (gosec) (work: apps/zt-policy-engine \| apps/k8s-admission-webhook)` | gosec v2.22.4 SARIF |
| Gate names `SAST — Go (gosec) (apps/…)` / aggregate `gosec` | Required-check mirrors of matrix result |
| `SAST — Rust (cargo-audit)` | rustsec |
| `SAST — Rust (cargo-deny)` | License/deny policies |
| `SBOM & Container Scan (neuromesh-zt-policy-engine \| neuromesh-agent-ebpf-sensor)` | SPDX SBOM + Trivy image CRITICAL gate (when matrix applicable) |

### 3.3 CodeQL — real finding (not TBD)

**CodeQL runs in this repo for Code Quality (maintainability/reliability), NOT the security query suite — all security-relevant static analysis coverage comes from gosec, Semgrep, cargo-audit/cargo-deny, and Trivy. Adding CodeQL's security suite was evaluated and deemed low marginal value given existing coverage.**

Supporting evidence:

| Observation | Accurate interpretation |
|-------------|-------------------------|
| Code scanning default setup | GitHub API `GET …/code-scanning/default-setup` → `state: not-configured`. |
| Security tab / code-scanning analyses & alerts | Only tools present: **gosec** and **Trivy** — **zero** analyses with tool name CodeQL. |
| In-repo workflows use `github/codeql-action/upload-sarif@v3` | SARIF **upload helper only** for gosec + Trivy ([`security-scan-pipeline.yml`](../.github/workflows/security-scan-pipeline.yml), [`experimental-ci.yml`](../.github/workflows/experimental-ci.yml)). No `github/codeql-action/init` / `analyze` in any of the four in-repo workflow files. |
| PR checks `Analyze (go)`, `Analyze (javascript-typescript)`, `Analyze (python)` under workflow name **CodeQL** | Genuine CodeQL **engine** runs via **GitHub Code Quality** (`dynamic/github-code-quality/codeql`, run titles like `Code Quality: PR #…`) — maintainability/reliability only. |

Security SAST that *does* run: gosec (Go), Semgrep `p/ci`, cargo-audit + cargo-deny (Rust), Trivy (FS/image), plus clippy on the lint path. CodeQL security default/advanced setup was considered as a Go dataflow/taint complement and rejected as low marginal value for this stack — not a coverage emergency.

### 3.4 Every PR vs main-only

| Class | On every PR (typical) | Main push only |
|-------|----------------------|----------------|
| Lint / Test / eBPF build+verify / Performance / E2E / Docker **build** | Yes (subject to path/core filters) | Yes |
| GHCR **publish** + Cosign **sign** image / bytecode | No (`should_publish=false`) | Yes ([`ci.yml`](../.github/workflows/ci.yml) publish step) |
| Security Scan SAST / Trivy FS / cargo-audit|deny | Yes when core paths change | Yes |

Pre-commit (local): [#156](https://github.com/Neuromesh-Security/neuromesh/pull/156) — fmt, clippy, shellcheck fail-closed.

---

## 4. Honest limitations (do not omit)

| Limitation | Citation |
|------------|----------|
| **ARM64 unsupported / unverified** | No current infrastructure access — DigitalOcean droplets x86_64-only ([`docs/threat-model.md`](threat-model.md) §1; [#157](https://github.com/Neuromesh-Security/neuromesh/issues/157); docs [#158](https://github.com/Neuromesh-Security/neuromesh/pull/158)) |
| **Kernel 5.15 / 6.1 LTS unverified** | No honest stock cloud image path (Debian 12 / 6.1 deprecated by provider; Ubuntu 22.04 cloud → HWE **6.8**, not GA 5.15). Verified envelope: x86_64 **~6.8 / ~6.17** only ([`docs/threat-model.md`](threat-model.md) §1; [#157](https://github.com/Neuromesh-Security/neuromesh/issues/157)). Issue [#52](https://github.com/Neuromesh-Security/neuromesh/issues/52) fixed **labels**, not real LTS coverage. |
| **Root / `CAP_BPF` — detection, not elimination** | Threat-model **E-07** / Agent tampering residual; integrity monitor is tamper-**evidence** ([#74](https://github.com/Neuromesh-Security/neuromesh/pull/74)/[#76](https://github.com/Neuromesh-Security/neuromesh/pull/76); [`docs/RELEASE_v0.1.0-core.md`](RELEASE_v0.1.0-core.md)) |
| **No external third-party security audit** | Not claimed anywhere in release notes; state as **absent to date** (this document). |
| **No SOC 2 / ISO 27001 certification** | Not claimed in [`README.md`](../README.md) / release notes; **absent to date**. |
| **AI / GNN Slow Path — scaffold only** | [`README.md`](../README.md) roadmap: rule-based edge-growth heuristic on `networkx`; no ML/GNN model/training/inference framework; [`docs/threat-model.md`](threat-model.md) out-of-scope Slow Path GNN |
| **Wasm policy hot-path — deferred scaffold** | [`wasm_policy.rs`](../apps/agent-ebpf-sensor/src/) scaffold; labeled intentional deferred work ([#153](https://github.com/Neuromesh-Security/neuromesh/pull/153); threat-model out-of-scope) |
| **LotL detection — partial** | Allowlisted exec **env-hijack** signals only (`LD_PRELOAD`, `LD_LIBRARY_PATH`, …) via [#140](https://github.com/Neuromesh-Security/neuromesh/issues/140) / [#141](https://github.com/Neuromesh-Security/neuromesh/pull/141); **not** comprehensive LotL / T1218 coverage ([`docs/threat-model.md`](threat-model.md) LotL residual `#TBD`) |
| **CodeQL security suite not configured (evaluated, deferred)** | CodeQL here = Code Quality only; security SAST = gosec + Semgrep + cargo-audit/deny + Trivy. Security suite deemed **low marginal value** — see §3.3. |

---

## 5. Governance note

Neuromesh is **solo-maintained** ([`README.md`](../README.md)). Development is **AI-augmented** (Cursor as implementation agent) with **human architectural review** and a standing practice that security-relevant changes require **live droplet verification** (paste-back of `scripts/manual_verify_*.sh` output) before merge — encoded in script headers (e.g. DesiredPolicy, SIEM, token rotation, NetworkPolicy) and issue/PR discipline (e.g. [#171](https://github.com/Neuromesh-Security/neuromesh/pull/171), [#173](https://github.com/Neuromesh-Security/neuromesh/pull/173), [#180](https://github.com/Neuromesh-Security/neuromesh/pull/180)).

This is **context for evaluators**, not an apology: it explains how evidence is produced (live gates + CI) and why some residuals (ARM64, 5.15/6.1, external audit) remain explicitly open.

---

## Appendix A — Quick index of live-verify scripts

| Script | Primary control |
|--------|-----------------|
| `scripts/manual_verify_lsm_pin.sh` | LSM survives `kill -9` |
| `scripts/manual_verify_runtime_integrity.sh` | Pin / binary tamper evidence |
| `scripts/manual_verify_policy_bundle_signature.sh` | Bundle Cosign + temporal replay |
| `scripts/manual_verify_desired_policy_dynamic.sh` | DesiredPolicy E2E scenario contract (7); live transcript TBD |
| `scripts/manual_verify_admission_tls_rotation.sh` | Webhook TLS renew + rollout health |
| `scripts/manual_verify_policy_bundle_token_rotation.sh` | Bearer N∥N+1 rotation |
| `scripts/manual_verify_network_policies.sh` | NetworkPolicy ALLOW/DENY |
| `scripts/manual_verify_siem_forwarders.sh` | Splunk + Datadog E2E + fault isolation |
| `scripts/manual_verify_k8s_policy_engine.sh` | PE/agent K8s productization bootstrap |

## Appendix B — Citation hygiene

- Prefer PR merge dates from GitHub (`mergedAt`) over memory.
- Digests above are those **pinned in-tree as of this document’s branch tip**; re-verify against `main` before procurement language that asserts “current production digests.”
- Items marked **TBD — verify** are intentional gaps for human cross-check, not soft claims.
