# Kubernetes Admission Webhook

Validating and mutating admission webhook for Neuromesh Kubernetes enforcement.

## Endpoints (HTTPS)

| Path | Type | Behavior |
|------|------|----------|
| `POST /validate` | Validating | Fail-closed Cosign static-key verification of **every** Pod image (`initContainers`, `containers`, `ephemeralContainers`). Deny on missing/wrong signature or unreachable registry. |
| `POST /mutate` | Mutating | Injects `neuromesh-security-sidecar` when absent (scaffold; **MutatingWebhookConfiguration is not shipped** under `deploy/` today). |
| `GET /healthz` | Health | Liveness / readiness probe |

The deprecated annotation `neuromesh.security/signed` is **not** consulted for admission. Cryptographic verification in `src/validation/` is authoritative.

## TLS

Kubernetes requires webhooks over TLS. Mount certificates and configure:

| Variable | Default | Purpose |
|----------|---------|---------|
| `WEBHOOK_LISTEN_ADDR` | `:8443` | HTTPS listen address |
| `WEBHOOK_TLS_CERT_FILE` | `/etc/webhook/certs/tls.crt` | Server certificate |
| `WEBHOOK_TLS_KEY_FILE` | `/etc/webhook/certs/tls.key` | Server private key |
| `NEUROMESH_COSIGN_PUBLIC_KEY_PATH` | `/etc/webhook/cosign/cosign.pub` | Static Cosign public key PEM |
| `NEUROMESH_COSIGN_VERIFY_MODE` | `key` | Trust-root mode (`key` or `keyless`; keyless is scaffolded fail-closed) |
| `NEUROMESH_COSIGN_REGISTRY_INSECURE` | unset / false | Exact value `true` enables plain-HTTP registry access (lab/kind only; loud `SECURITY WARNING` at startup; **never** set in `deploy/kubernetes/`) |

Generate Phase A certs with `openssl` (see admission deploy README). cert-manager is a later Phase B item.

## Build & Test

```bash
cd apps/k8s-admission-webhook
go test ./...
go build -o bin/k8s-admission-webhook ./src
```

## Production deploy (Phase A + Phase B part 1)

Shipped manifests, TLS/openssl runbook, install order, Ignore→Fail graduation
checklist, NetworkPolicy, and caBundle inject live under
[`deploy/kubernetes/admission/`](../../deploy/kubernetes/admission/README.md).

Do not treat the snippet below as the sole deploy source — use that directory.

Hardening already on `main` (Phase A / PR #164): `replicas: 2`, preferred hostname
anti-affinity, PDB `minAvailable: 1`, `matchPolicy: Equivalent`, VWC matches
`pods` + `pods/ephemeralcontainers`. Phase B part 1 adds ingress NetworkPolicy
on container port **8443** (Service is `443→8443`) from k3s API-server source
CIDRs.

## Example ValidatingWebhookConfiguration (snippet only)

```yaml
webhooks:
  - name: neuromesh.security.validate-pods
    clientConfig:
      service:
        name: neuromesh-admission-webhook
        namespace: neuromesh-system
        path: /validate
      caBundle: <base64-webhook-ca>
    rules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods", "pods/ephemeralcontainers"]
    admissionReviewVersions: ["v1"]
    sideEffects: None
    matchPolicy: Equivalent
    failurePolicy: Ignore   # Phase A; graduate to Fail per admission README
```
