# Neuromesh admission webhook — Phase A deploy (Issue #63)

Ships a **Validating** admission webhook that invokes the existing fail-closed
Cosign Pod image verification in `apps/k8s-admission-webhook`.

| Phase A (this directory) | Not in this phase |
|--------------------------|-------------------|
| `failurePolicy: Ignore` | `failurePolicy: Fail` |
| Manual TLS Secret + `caBundle` | cert-manager |
| Pods CREATE/UPDATE only | MutatingWebhookConfiguration / sidecar |
| Static Cosign key verify | Keyless Cosign |

## Install order (mandatory)

Do **not** apply the ValidatingWebhookConfiguration before the Deployment is Ready.

1. Ensure namespace `neuromesh-system` exists (created by `../neuromesh-agent.yaml` or `kubectl create namespace neuromesh-system`).
2. Create Secrets (Cosign pubkey + webhook TLS) — commands below.
3. Apply Deployment + Service:
   ```bash
   kubectl apply -f neuromesh-admission-webhook-deployment.yaml
   kubectl apply -f neuromesh-admission-webhook-service.yaml
   ```
4. Wait until Ready:
   ```bash
   kubectl -n neuromesh-system rollout status deployment/neuromesh-admission-webhook
   kubectl -n neuromesh-system get endpoints neuromesh-admission-webhook
   ```
5. Fill `caBundle` in `neuromesh-admission-validating-webhook.yaml`, then apply:
   ```bash
   kubectl apply -f neuromesh-admission-validating-webhook.yaml
   ```

After step 5, Pod CREATE/UPDATE outside excluded namespaces (including
`neuromesh-agent` in `neuromesh-system`) are sent to `/validate` when the webhook
is reachable. Under Phase A `Ignore`, an unreachable webhook does **not** block
admission — graduate to Fail only after the checklist below.

## TLS: openssl SAN + Secrets + caBundle

The API server dials `neuromesh-admission-webhook.neuromesh-system.svc` (and the
cluster DNS variants). The server certificate **must** include those names.

### 1. Generate a self-signed CA and server cert (operator laptop)

```bash
# Working directory for generated material (do not commit private keys).
mkdir -p /tmp/neuromesh-webhook-certs && cd /tmp/neuromesh-webhook-certs

# CA
openssl req -x509 -newkey rsa:4096 -nodes -days 3650 \
  -keyout ca.key -out ca.crt \
  -subj "/CN=neuromesh-admission-ca"

# Server key + CSR
openssl req -newkey rsa:4096 -nodes \
  -keyout tls.key -out tls.csr \
  -subj "/CN=neuromesh-admission-webhook.neuromesh-system.svc"

# SAN extension (required)
cat >server-ext.cnf <<'EOF'
subjectAltName = DNS:neuromesh-admission-webhook,DNS:neuromesh-admission-webhook.neuromesh-system,DNS:neuromesh-admission-webhook.neuromesh-system.svc,DNS:neuromesh-admission-webhook.neuromesh-system.svc.cluster.local
EOF

openssl x509 -req -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out tls.crt -days 825 -extfile server-ext.cnf
```

### 2. Create Kubernetes Secrets

```bash
# Webhook serving cert (keys: tls.crt, tls.key — standard kubernetes.io/tls)
kubectl -n neuromesh-system create secret tls neuromesh-admission-webhook-tls \
  --cert=tls.crt --key=tls.key

# Cosign static public key (same Secret class as the agent DaemonSet)
kubectl -n neuromesh-system create secret generic neuromesh-cosign-pubkey \
  --from-file=cosign.pub=./cosign.pub
```

Use the **same** Cosign public key that verifies GHCR image signatures for
`agent-ebpf-sensor` / webhook images (CI Cosign static key).

For **kind / air-gapped lab registries that speak plain HTTP**, set
`NEUROMESH_COSIGN_REGISTRY_INSECURE=true` on the Deployment (see
`neuromesh-admission-webhook-deployment.yaml`). Leave `false` for production
HTTPS registries. This does **not** change `failurePolicy`, selectors, or
timeouts.

### 3. Inject `caBundle` into the ValidatingWebhookConfiguration

`caBundle` must be the **base64-encoded PEM of the CA** that signed `tls.crt`
(here: `ca.crt`), not the server cert alone.

```bash
# Linux / macOS / Git Bash:
CA_BUNDLE="$(openssl base64 -A -in ca.crt)"
# Or: CA_BUNDLE="$(base64 -w0 ca.crt)"

# Patch the placeholder in the manifest before apply, e.g.:
sed "s/REPLACE_WITH_BASE64_CA_BUNDLE/${CA_BUNDLE}/" \
  neuromesh-admission-validating-webhook.yaml | kubectl apply -f -
```

PowerShell:

```powershell
$caBundle = [Convert]::ToBase64String([IO.File]::ReadAllBytes("ca.crt"))
(Get-Content neuromesh-admission-validating-webhook.yaml -Raw) `
  -replace 'REPLACE_WITH_BASE64_CA_BUNDLE', $caBundle |
  kubectl apply -f -
```

## Selectors (do not change without a design revision)

- **namespaceSelector:** exclude `kube-system`, `kube-public`, `kube-node-lease`.
- **objectSelector:** exclude pods with `app.kubernetes.io/name=neuromesh-admission-webhook`.
- **`neuromesh-system` is not excluded** — `neuromesh-agent` DaemonSet pods are gated.

## Phase A → Fail graduation checklist (operator)

Graduate `failurePolicy` from `Ignore` to `Fail` **only** when all of the following
are true in the target cluster. Treat this as a gate, not aspirational guidance.

- [ ] `deployment/neuromesh-admission-webhook` has been Ready continuously for a soak
      period you accept (recommended: ≥ 7 days in the target environment, or an
      equivalent load test with zero prolonged `/validate` timeouts).
- [ ] Webhook logs show successful ALLOW for a known Cosign-signed image (e.g. a
      rolling update of `neuromesh-agent` with a signed `agent-ebpf-sensor` image).
- [ ] Webhook logs show DENY for an intentionally **unsigned** test Pod while the
      webhook is healthy (create a Pod with an unsigned image in a non-excluded
      namespace; confirm DENY in webhook logs). Under `Ignore`, confirm the API
      server still received a deny response when the webhook was up.
- [ ] TLS/DNS/`caBundle` are correct: no sustained client TLS errors from the API
      server to `neuromesh-admission-webhook.neuromesh-system.svc`.
- [ ] An operator explicitly changes `failurePolicy` to `Fail` (edit/overlay) and
      re-applies the ValidatingWebhookConfiguration — do not flip this casually.

Until Fail is applied, an outage of the webhook **silently allows** matched Pod
CREATE/UPDATE (`Ignore`) — Phase A is not the final security posture.

## Post-install smoke checks

```bash
# Webhook healthy
kubectl -n neuromesh-system get deploy,svc,pods -l app.kubernetes.io/name=neuromesh-admission-webhook

# VWC present
kubectl get validatingwebhookconfiguration neuromesh-validate-pods -o yaml

# Unsigned Pod (expect DENY in webhook logs when healthy; under Ignore the create
# may still succeed if you only look at kubectl — always check webhook logs)
kubectl -n default run unsigned-smoke --image=busybox:1.36 --restart=Never --command -- sleep 30
kubectl -n neuromesh-system logs -l app.kubernetes.io/name=neuromesh-admission-webhook --tail=50
```

## Manifests in this directory

| File | Role |
|------|------|
| `neuromesh-admission-webhook-deployment.yaml` | Deployment + ServiceAccount |
| `neuromesh-admission-webhook-service.yaml` | ClusterIP 443→8443 |
| `neuromesh-admission-validating-webhook.yaml` | ValidatingWebhookConfiguration (Phase A) |
