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
2. Email **security@neuromesh.security** with:
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

## Security Contacts

- **Vulnerability reports:** security@neuromesh.security
- **General security inquiries:** security@neuromesh.security

---

*Last updated: 2026-07-12*
