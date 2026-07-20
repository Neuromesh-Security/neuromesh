# Kubernetes Admission Webhook

Validating and mutating admission webhook for Neuromesh Kubernetes enforcement.

## Endpoints (HTTPS)

| Path | Type | Behavior |
|------|------|----------|
| `POST /validate` | Validating | Rejects Pods missing `neuromesh.security/signed: "true"` |
| `POST /mutate` | Mutating | Injects `neuromesh-security-sidecar` container |
| `GET /healthz` | Health | Liveness probe |

## TLS

Kubernetes requires webhooks over TLS. Mount certificates and configure:

| Variable | Default | Purpose |
|----------|---------|---------|
| `WEBHOOK_LISTEN_ADDR` | `:8443` | HTTPS listen address |
| `WEBHOOK_TLS_CERT_FILE` | `/etc/webhook/certs/tls.crt` | Server certificate |
| `WEBHOOK_TLS_KEY_FILE` | `/etc/webhook/certs/tls.key` | Server private key |
| `NEUROMESH_COSIGN_PUBLIC_KEY_PATH` | `/etc/webhook/cosign/cosign.pub` | Static Cosign public key PEM |
| `NEUROMESH_COSIGN_VERIFY_MODE` | `key` | Trust-root mode (`key` or `keyless`) |
| `NEUROMESH_COSIGN_REGISTRY_INSECURE` | unset / false | Exact value `true` enables plain-HTTP registry access (lab/kind only; loud `SECURITY WARNING` at startup; **never** set in `deploy/kubernetes/`) |

Generate dev certs with cert-manager, `openssl`, or your cluster CSR flow.

## Build & Test

```bash
cd apps/k8s-admission-webhook
go test ./...
go build -o bin/k8s-admission-webhook ./src
```

## Sprint Mock Semantics

- **Validation:** Cosign/Notary integration is mocked via required annotation
  `neuromesh.security/signed=true`.
- **Mutation:** Injects mock sidecar image
  `ghcr.io/neuromesh-security/neuromesh-sidecar:0.1.0`.

## Example ValidatingWebhookConfiguration (snippet)

```yaml
webhooks:
  - name: neuromesh.security.validate-pods
    clientConfig:
      service:
        name: neuromesh-admission-webhook
        namespace: neuromesh-system
        path: /validate
      caBundle: <base64-cluster-ca-or-webhook-ca>
    rules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
    admissionReviewVersions: ["v1"]
    sideEffects: None
```

## Production deploy (Phase A — Issue #63)

Shipped manifests, TLS/openssl runbook, install order, and Ignore→Fail graduation
checklist live under [`deploy/kubernetes/admission/`](../../deploy/kubernetes/admission/README.md).
Do not use the snippet above as the sole deploy source — use that directory.
