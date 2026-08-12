# Security Policy

Neuromesh Security is an eBPF-based runtime protection platform. We treat the
security of our codebase, CI/CD pipeline, and downstream operators with the
same rigor we apply to customer workloads.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |

## Zero Trust Commitment

Neuromesh is designed around **Zero Trust** principles:

- **Never trust, always verify.** Kernel sensors, orchestrators, and AI inference
  pipelines authenticate and authorize every action — no implicit trust by network
  location or binary path alone.
- **Least privilege by default.** eBPF programs operate with minimal map scopes;
  user-space components run with the narrowest capabilities required for telemetry
  and enforcement.
- **Assume breach.** Telemetry lineage (pid, ppid, comm, euid) and behavioral
  analysis are first-class signals so lateral movement is detectable even when
  attackers use living-off-the-land binaries.
- **Continuous validation.** Production CI enforces formatting, static analysis,
  unit tests, and multi-architecture eBPF cross-compilation on every change to
  `main`.

## Reporting a Vulnerability

We welcome responsible disclosure from researchers, operators, and community
members.

### How to Report

1. **Do not** open a public GitHub issue for security vulnerabilities.
2. Email **draganflaviusfx@gmail.com** with:
   - A clear description of the vulnerability and affected component
   - Steps to reproduce (proof-of-concept, logs, or minimal test case)
   - Impact assessment (confidentiality, integrity, availability)
   - Your preferred contact and disclosure timeline
3. Encrypt sensitive reports with our PGP key when available at
   `https://neuromesh.security/.well-known/pgp-key.txt` (placeholder — rotate
   before production launch).

### What to Expect

| Milestone | Target |
| --------- | ------ |
| Initial acknowledgement | 2 business days |
| Triage and severity rating | 5 business days |
| Remediation plan shared | 10 business days |
| Coordinated disclosure | Agreed with reporter |

We follow a good-faith disclosure model. We will not pursue legal action against
researchers who:

- Avoid privacy violations, data destruction, and service disruption
- Do not exploit vulnerabilities beyond what is necessary to demonstrate impact
- Report findings promptly and allow reasonable time for remediation

### Severity Handling

| Severity | Examples | Response |
| -------- | -------- | -------- |
| Critical | Unauthenticated RCE in orchestrator, BPF verifier bypass enabling arbitrary kernel write | Hotfix release + advisory within 72 hours |
| High | LSM bypass, privilege escalation via sensor | Patch release within 14 days |
| Medium | Information disclosure via telemetry channel | Scheduled release |
| Low | Hardening gaps with no direct exploit path | Backlog / defense-in-depth |

## Safe Harbor

If you conduct security research in accordance with this policy, Neuromesh
considers your activities authorized. We will work with you to understand and
resolve the issue quickly.

## Control-plane advisory vs kernel enforcement

`POST /v1/evaluate` on the zero-trust policy engine is a **control-plane advisory**
endpoint (OPA/Rego + SPIFFE identity checks for operators, dashboards, and
integration tests). It is **not** the source of truth for execve enforcement.

Real-time blocking of ephemeral staging paths (`/tmp/`, `/dev/shm/`, `/var/tmp/`)
is performed in-kernel by the eBPF LSM (`neuromesh_lsm_exec_guard`) against the
agent-synced `PATH_DENY_LIST` / policy-bundle deny prefixes. Do **not** treat
`/v1/evaluate` `allowed: true|false` as a substitute for LSM decisions when
building real-time security controls.

Identity exceptions (when enabled) are scoped to `/tmp/` only — `/dev/shm/` and
`/var/tmp/` remain hard-denied for every SPIFFE identity, in both the LSM and
the Rego policy.

## Policy-bundle signing (mandatory — fail-closed)

`GET /v1/policy-bundle` is protected by **two independent controls**:

| Control | Mechanism | Failure mode |
|---------|-----------|--------------|
| Transport auth | Bearer token (`NEUROMESH_POLICY_BUNDLE_TOKEN` / `_FILE`) — Issue #55 | PE fatal if unset; agent never syncs unauthenticated |
| Content integrity | Cosign-compatible detached signature over **exact** response body bytes (`X-Neuromesh-Policy-Bundle-Signature`) — Issue #108 / external review P0 (T-PB-02-class) | PE **refuses to boot** without a valid `NEUROMESH_POLICY_BUNDLE_SIGNING_KEY_PATH`; agent rejects missing/invalid signatures (`signature_missing` / `signature_invalid`) and retains last-known-good deny maps — **never** applies unsigned or tampered bundles |

Bearer auth alone is **not** content integrity. An operator who deploys PE without
the signing key will see an immediate fatal startup error
(`policy-bundle signing misconfigured`) — this is intentional, not a soft warning.
Do not weaken fail-closed startup to “make local demos easier”; generate a
dev PKCS#8 key (see `apps/zt-policy-engine/README.md` Quickstart) or use
[`scripts/manual_verify_policy_bundle_signature.sh`](scripts/manual_verify_policy_bundle_signature.sh)
for the signed-vs-tampered live proof.

Same documentation loudness bar as lab-only manual identity seeding
(`NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS`): mandatory controls are explicit, fail-closed,
and called out here — not buried in an env table alone. Full threat reasoning:
`docs/threat-model.md` §4.5 and the residual-risk table (T-PB-02-class row).

## Security Contacts

- **Vulnerability reports:** draganflaviusfx@gmail.com
- **General security inquiries:** draganflaviusfx@gmail.com

---

*Last updated: 2026-08-12*
