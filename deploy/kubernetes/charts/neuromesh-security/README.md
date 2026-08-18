# neuromesh-security Helm chart

Production Helm packaging of the existing manifests in `deploy/kubernetes/` and `deploy/kubernetes/admission/`, with security posture preserved.

## Inventory mapped into templates

- `neuromesh-agent.yaml` -> `templates/agent.yaml` (DaemonSet + ServiceAccount)
- `neuromesh-agent-correlator-rbac.yaml` -> `templates/agent-correlator-rbac.yaml`
- `neuromesh-zt-policy-engine-deployment.yaml` -> `templates/policy-engine.yaml` (Deployment + ServiceAccount)
- `neuromesh-zt-policy-engine-service.yaml` -> `templates/policy-engine-service.yaml`
- `neuromesh-desired-policy.yaml` -> `templates/desired-policy.yaml` (ConfigMap + Role + RoleBinding)
- `admission/neuromesh-admission-webhook-deployment.yaml` -> `templates/admission-webhook-deployment.yaml` (Deployment + ServiceAccount)
- `admission/neuromesh-admission-webhook-service.yaml` -> `templates/admission-webhook-service.yaml`
- `admission/neuromesh-admission-validating-webhook.yaml` -> `templates/admission-validating-webhook.yaml`

Associated Secrets are represented in `templates/secrets.yaml` (disabled by default to preserve current operational workflow).

## Install order (required)

Helm hooks are intentionally **not** used for Deployment ordering because they reduce lifecycle visibility and make upgrades harder to reason about. Instead, use explicit, deterministic phased Helm installs/upgrades that preserve the current documented order:

1) Secrets
2) Policy Engine
3) Wait Ready
4) Agent
5) Admission webhook Deployment+Service
6) Wait Ready
7) ValidatingWebhookConfiguration

### 0) Namespace

```bash
kubectl create namespace neuromesh-system --dry-run=client -o yaml | kubectl apply -f -
```

### 1) Secrets (same inputs as raw-manifest workflow)

Either:
- create Secrets manually with the same `kubectl create secret` commands from `deploy/kubernetes/README.md` and `deploy/kubernetes/admission/README.md`, or
- enable `secrets.create=true` and provide values.

### 2) Install policy-engine first

```bash
helm upgrade --install neuromesh-security deploy/kubernetes/charts/neuromesh-security \
  -n neuromesh-system \
  --set agent.enabled=false \
  --set admissionWebhook.enabled=false \
  --set validatingWebhook.enabled=false
```

### 3) Wait policy engine ready

```bash
kubectl -n neuromesh-system rollout status deploy/neuromesh-zt-policy-engine --timeout=180s
```

### 4) Enable agent

```bash
helm upgrade neuromesh-security deploy/kubernetes/charts/neuromesh-security \
  -n neuromesh-system \
  --set admissionWebhook.enabled=false \
  --set validatingWebhook.enabled=false
```

### 5) Enable admission webhook Deployment + Service only

```bash
helm upgrade neuromesh-security deploy/kubernetes/charts/neuromesh-security \
  -n neuromesh-system \
  --set validatingWebhook.enabled=false
```

### 6) Wait admission deployment ready

```bash
kubectl -n neuromesh-system rollout status deploy/neuromesh-admission-webhook --timeout=180s
kubectl -n neuromesh-system get endpoints neuromesh-admission-webhook
```

### 7) Apply VWC (after setting caBundle)

```bash
helm upgrade neuromesh-security deploy/kubernetes/charts/neuromesh-security \
  -n neuromesh-system
```

## Validation

```bash
helm lint deploy/kubernetes/charts/neuromesh-security
helm template neuromesh-security deploy/kubernetes/charts/neuromesh-security -n neuromesh-system
```

For live verification, run the existing acceptance path with Helm-managed resources:

```bash
sudo -E bash scripts/manual_verify_k8s_policy_engine.sh
```

Use script environment overrides (for example image refs) if needed; acceptance remains:
- PE healthy (`/healthz`)
- signed `/v1/policy-bundle` available
- agent policy sync evidence
- webhook validating path operational
