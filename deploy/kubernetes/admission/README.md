# Neuromesh admission webhook — Phase A deploy (Issue #63)

Ships a **Validating** admission webhook that invokes the existing fail-closed
Cosign Pod image verification in `apps/k8s-admission-webhook`.

| Phase A (this directory) | Not in this phase |
|--------------------------|-------------------|
| `failurePolicy: Ignore` | `failurePolicy: Fail` (gated — see checklist) |
| Manual openssl TLS Secret + `caBundle` **or** Phase B part 2 cert-manager | Blind CA auto-replace (forbidden) |
| Pods CREATE/UPDATE (`pods` + `pods/ephemeralcontainers`) | MutatingWebhookConfiguration / sidecar |
| Static Cosign key verify | Keyless Cosign |

## Install order (mandatory)

Do **not** apply the ValidatingWebhookConfiguration before the Deployment is Ready.

1. Ensure namespace `neuromesh-system` exists (created by `../neuromesh-agent.yaml` or `kubectl create namespace neuromesh-system`).
2. Create Secrets (Cosign pubkey + webhook TLS) — commands below.
3. Apply Deployment + Service + PDB + NetworkPolicy:
   ```bash
   kubectl apply -f neuromesh-admission-webhook-deployment.yaml
   kubectl apply -f neuromesh-admission-webhook-service.yaml
   kubectl apply -f neuromesh-admission-webhook-pdb.yaml
   kubectl apply -f neuromesh-admission-webhook-networkpolicy.yaml
   ```
4. Wait until Ready:
   ```bash
   kubectl -n neuromesh-system rollout status deployment/neuromesh-admission-webhook
   kubectl -n neuromesh-system get endpoints neuromesh-admission-webhook
   kubectl -n neuromesh-system get pdb neuromesh-admission-webhook
   ```
5. Fill `caBundle` then apply the ValidatingWebhookConfiguration.
   **Do not** hand-edit a one-off sed unless you must. From the **repository root**,
   use the repo script:
   ```bash
   bash scripts/inject_admission_cabundle.sh /tmp/neuromesh-webhook-certs/ca.crt - \
     | kubectl apply -f -
   ```
   Helm: `--set validatingWebhook.caBundle="$(openssl base64 -A -in ca.crt)"`.
   **Lab / `failurePolicy: Ignore` default:** keep this openssl path.
   **Production leaf renewal:** Phase B part 2 cert-manager path below (Issue #168).

After step 5, Pod CREATE/UPDATE (including `pods/ephemeralcontainers` / `kubectl debug`)
outside excluded namespaces (including `neuromesh-agent` in `neuromesh-system`) are
sent to `/validate` when the webhook is reachable. Under Phase A `Ignore`, an
unreachable webhook does **not** block admission — graduate to Fail only after the
checklist below.

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
  --from-file=cosign.pub=../ci-cosign.pub
```

Use **`deploy/kubernetes/ci-cosign.pub`** — the CI static key (`secrets.COSIGN_PUBLIC_KEY`)
that verifies GHCR image signatures and baked `bytecode-manifest.sig`. Do **not** use
`~/neuromesh-attest-lab/cosign/cosign.pub` (lab-only, locally-built binaries).

### Local/lab-only HTTP registry bypass (insecure)

`NEUROMESH_COSIGN_REGISTRY_INSECURE=true` allows Cosign verification against
**plain-HTTP** registries (`name.Insecure`). It emits a loud `SECURITY WARNING`
at webhook startup. Use only for kind / air-gapped lab plumbing — **never** in
shared or production environments. Production registries must use HTTPS.

This variable is **intentionally absent** from every file under
`deploy/kubernetes/` (including `neuromesh-admission-webhook-deployment.yaml`).
Do not add it to those manifests. For a local kind E2E only, patch the running
Deployment (or set the env on a throwaway override), e.g.:

```bash
# LAB ONLY — never commit this into deploy/kubernetes/
kubectl -n neuromesh-system set env deployment/neuromesh-admission-webhook \
  NEUROMESH_COSIGN_REGISTRY_INSECURE=true
```

This does **not** change `failurePolicy`, selectors, or `timeoutSeconds`.

### 3. Inject `caBundle` into the ValidatingWebhookConfiguration

`caBundle` must be the **base64-encoded PEM of the CA** that signed `tls.crt`
(here: `ca.crt`), not the server cert alone.

The in-repo YAML **keeps** the placeholder `REPLACE_WITH_BASE64_CA_BUNDLE`.
That is correct for Phase A: the CA is operator-generated and must not be
committed. **cert-manager leaf renewal is Phase B part 2** (opt-in) — see below.
Do not remove this openssl path; it remains the lab / Ignore bootstrap.

Supported inject path (repo script, not improvised sed):

```bash
# From repo root. Writes patched YAML to stdout:
bash scripts/inject_admission_cabundle.sh /tmp/neuromesh-webhook-certs/ca.crt - \
  | kubectl apply -f -
```

Helm:

```bash
helm upgrade neuromesh-security deploy/kubernetes/charts/neuromesh-security \
  -n neuromesh-system \
  --set validatingWebhook.caBundle="$(openssl base64 -A -in /tmp/neuromesh-webhook-certs/ca.crt)"
```

Emergency one-liner (same substitution the script performs):

```bash
CA_BUNDLE="$(openssl base64 -A -in ca.crt)"
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
- **`matchPolicy: Equivalent`** — explicit (this is also the API default).
- **resources:** `pods` **and** `pods/ephemeralcontainers`. `/validate` already
  walks `initContainers` + `containers` + `ephemeralContainers` in code; without
  the subresource rule, `kubectl debug` would bypass Cosign for debug images.

## HA (Phase A pre-Fail)

- **replicas: 2** with **preferred** `podAntiAffinity` on `kubernetes.io/hostname`.
  Preferred (not required) so a single-node lab still schedules both replicas.
- **PodDisruptionBudget** `minAvailable: 1` — a drain/upgrade must not remove
  both pods. Do not set `replicas: 1` while this PDB is applied.

## NetworkPolicy (Phase B part 1)

File: `neuromesh-admission-webhook-networkpolicy.yaml`.

- Matches **container port 8443** (not Service port 443). Service remains `443→https`.
- k3s apiserver is **host-networked** — there is no apiserver Pod selector. Ingress
  uses `ipBlock`. Default in-repo CIDR is `10.42.0.0/32` (Flannel server PodCIDR
  network address as a `/32` host prefix). Discover the correct value on the
  droplet with `scripts/manual_verify_network_policies.sh` before tightening or
  widening. Do **not** default to `10.42.0.0/16` (that admits every Flannel pod).
- On single-node k3s, Kubernetes always allows host→local-pod (kubelet / same-node
  apiserver path). Multi-node: set a `/32` (or `/128`) per control-plane node’s
  PodCIDR network address (same rule Longhorn documents for k3s webhooks).
- PE has a sibling policy: `../neuromesh-zt-policy-engine-networkpolicy.yaml`
  (agent pods only on `:8080`).

## TLS rotation — Phase B part 2 (Issue #168)

**Gate:** do **not** graduate `failurePolicy` to `Fail` without a live rotation
path (cert-manager below, or a platform-equivalent CA injector with the same
dual-trust / fail-safe properties).

### Two supported install modes

| Mode | When | How |
|------|------|-----|
| **openssl / manual** | Lab, kind, `failurePolicy: Ignore` | README openssl section + `inject_admission_cabundle.sh` + openssl VWC |
| **cert-manager** (opt-in) | Production leaf renewal / Fail prep | `neuromesh-admission-webhook-cert-manager.yaml` + `neuromesh-admission-validating-webhook-cert-manager.yaml` |

Do **not** apply both VWC variants. Do **not** Helm-create the TLS Secret when
`certManager.enabled=true` (the leaf `Certificate` owns
`neuromesh-admission-webhook-tls`).

### cert-manager path (leaf renew automated)

**Requires cert-manager ≥ 1.19** (cainjector `CAInjectorMerging` default — merge
new CA material into `caBundle` instead of replace-only).

```bash
# 1) cert-manager Issuers + CA Certificate + leaf Certificate
kubectl apply -f neuromesh-admission-webhook-cert-manager.yaml
kubectl -n neuromesh-system wait --for=condition=Ready certificate/neuromesh-admission-webhook-ca --timeout=120s
kubectl -n neuromesh-system wait --for=condition=Ready certificate/neuromesh-admission-webhook-tls --timeout=120s

# 2) Deployment/Service/PDB/NetworkPolicy (Secret is created by cert-manager)
kubectl apply -f neuromesh-admission-webhook-deployment.yaml
kubectl apply -f neuromesh-admission-webhook-service.yaml
kubectl apply -f neuromesh-admission-webhook-pdb.yaml
kubectl apply -f neuromesh-admission-webhook-networkpolicy.yaml
kubectl -n neuromesh-system rollout status deployment/neuromesh-admission-webhook

# 3) VWC with inject-ca-from (cainjector fills caBundle)
kubectl apply -f neuromesh-admission-validating-webhook-cert-manager.yaml
# Wait until caBundle is non-empty:
kubectl get validatingwebhookconfiguration neuromesh-validate-pods \
  -o jsonpath='{.webhooks[0].clientConfig.caBundle}' | wc -c
```

Helm:

```bash
helm upgrade --install neuromesh-security deploy/kubernetes/charts/neuromesh-security \
  -n neuromesh-system \
  --set certManager.enabled=true \
  --set validatingWebhook.enabled=true
# Do not set validatingWebhook.caBundle when certManager.enabled=true.
```

**Automated behavior:** short-lived leaf (90d, renewBefore 15d) signed by a
long-lived CA. cert-manager updates the TLS Secret **in place** on successful
renew. The webhook process loads TLS at start (`ListenAndServeTLS`) — after
renew, run a **rolling restart** so pods pick up the new leaf (replicas ≥ 2 +
PDB keep admission up). Same CA → `caBundle` unchanged.

**Failure-mode locks (enforced by design / manifests / verify script):**

- Never `kubectl delete secret neuromesh-admission-webhook-tls` as part of renew.
- Never ship automation that blanks `caBundle` or writes `REPLACE_WITH_BASE64_CA_BUNDLE` over a live inject.
- On renew error, the last successfully issued Secret contents remain — fix forward.
- Helm `secrets.create` **skips** the TLS Secret when `certManager.enabled=true`
  so values cannot overwrite/fight the Certificate-owned Secret.

Live verify:

```bash
KUBECONFIG=/etc/rancher/k3s/k3s.yaml \
  bash scripts/manual_verify_admission_tls_rotation.sh
```

### CA rotation runbook (manual — not blind automation)

Use only for planned CA replace or compromise. **Sequence matters** (Fail-era).

Preconditions: cert-manager ≥ 1.19 with cainjector merge behavior; webhook
`replicas ≥ 2` + PDB; take a backup of current CA Secret + VWC `caBundle`.

| Step | Action | Must NOT |
|------|--------|----------|
| 1 | Create **CA₁** (new CA Certificate / Issuer material). Leave **CA₀** and the current TLS Secret serving. | Delete CA₀ or wipe TLS Secret |
| 2 | Patch VWC `caBundle` to **CA₀ ∥ CA₁** (both PEM). With `inject-ca-from` + `CAInjectorMerging`, cainjector **merges** new CA into the bundle rather than replace-only. Confirm **both** CA fingerprints appear in the decoded `caBundle` before continuing. | Set `caBundle` to **CA₁-only** while any Ready pod still serves a CA₀ leaf |
| 3 | Issue leaf signed by **CA₁** into `neuromesh-admission-webhook-tls` (update in place after the new PEM exists). | Delete Secret before the new leaf is written |
| 4 | `kubectl -n neuromesh-system rollout restart deployment/neuromesh-admission-webhook` and wait until **all** Ready replicas serve the CA₁ leaf (check mounted cert fingerprint / openssl against pod). | Skip soak / proceed with mixed trust assumptions undocumented |
| 5 | Remove **CA₀** from `caBundle`; destroy CA₀ / old leaf key material. | Drop CA₀ before every Ready replica serves CA₁ |

Break-glass: if step 2–4 fails, **stop**. Leave prior Secret + prior `caBundle` serving until hard expiry; fix forward. Do not “clean up” by deleting a still-valid cert.

## Image pin

The Deployment still references `…/neuromesh-k8s-admission-webhook:0.1.0`.
That tag is **not** published by CI (Production CI historically built only PE +
agent). This hardening adds the webhook to the docker matrix. After the first
`main` publish, pin `@sha256:…` the same way PE/agent are pinned. Do **not**
invent a digest.

## Phase A → Fail graduation checklist (operator)

Graduate `failurePolicy` from `Ignore` to `Fail` **only** when all of the following
are true in the target cluster. Treat this as a gate, not aspirational guidance.

- [ ] `deployment/neuromesh-admission-webhook` has `replicas: 2` Ready continuously for a soak
      period you accept (recommended: ≥ 7 days in the target environment, or an
      equivalent load test with zero prolonged `/validate` timeouts).
- [ ] PDB `neuromesh-admission-webhook` is present with `minAvailable: 1`.
- [ ] Image is digest-pinned (`@sha256:…`), Cosign-signed, matching PE/agent convention.
- [ ] Webhook logs show successful ALLOW for a known Cosign-signed image (e.g. a
      rolling update of `neuromesh-agent` with a signed `agent-ebpf-sensor` image).
- [ ] Webhook logs show DENY for an intentionally **unsigned** test Pod while the
      webhook is healthy (create a Pod with an unsigned image in a non-excluded
      namespace; confirm DENY in webhook logs). Under `Ignore`, confirm the API
      server still received a deny response when the webhook was up.
- [ ] Unsigned **initContainer** and unsigned **ephemeralContainer** (`kubectl debug`)
      are denied while the webhook is healthy.
- [ ] TLS/DNS/`caBundle` are correct: no sustained client TLS errors from the API
      server to `neuromesh-admission-webhook.neuromesh-system.svc`.
- [ ] **TLS rotation path live:** cert-manager ≥ 1.19 path applied **or** an
      equivalent platform CA injector with dual-trust CA-rotate semantics.
      `scripts/manual_verify_admission_tls_rotation.sh` PASSes (leaf renew in
      place + rollout healthz). openssl-only with no renew plan is **not**
      sufficient for Fail.
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
| `neuromesh-admission-webhook-deployment.yaml` | Deployment + ServiceAccount (`replicas: 2`, preferred anti-affinity) |
| `neuromesh-admission-webhook-service.yaml` | ClusterIP 443→8443 |
| `neuromesh-admission-webhook-pdb.yaml` | PodDisruptionBudget `minAvailable: 1` |
| `neuromesh-admission-webhook-networkpolicy.yaml` | Ingress NetworkPolicy (TCP/8443 from API-server CIDRs) |
| `neuromesh-admission-validating-webhook.yaml` | ValidatingWebhookConfiguration (openssl / Phase A caBundle inject) |
| `neuromesh-admission-webhook-cert-manager.yaml` | Phase B part 2: Issuers + CA/leaf Certificates (Issue #168) |
| `neuromesh-admission-validating-webhook-cert-manager.yaml` | VWC with `cert-manager.io/inject-ca-from` |
