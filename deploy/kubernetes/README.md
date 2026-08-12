# Neuromesh — Kubernetes deploy

## Manifests

| File | Purpose |
|------|---------|
| `neuromesh-agent.yaml` | Namespace, DaemonSet, ServiceAccount |
| `neuromesh-agent-correlator-rbac.yaml` | Slice **2b-i** ClusterRole/Binding: pods `get/list/watch` only |
| `neuromesh-zt-policy-engine-deployment.yaml` | zt-policy-engine Deployment + ServiceAccount (port 8080) |
| `neuromesh-zt-policy-engine-service.yaml` | ClusterIP Service → agent sync DNS |
| `admission/` | Optional Cosign admission webhook (see `admission/README.md`) |

Agent sync DNS:

```text
http://neuromesh-zt-policy-engine.neuromesh-system.svc.cluster.local:8080
```

## MANDATORY install order

Do **not** reorder. Policy engine is fail-closed: missing Secrets → CrashLoopBackOff.

1. **Namespace** — created by `neuromesh-agent.yaml` (or `kubectl create namespace neuromesh-system` first if applying PE alone).
2. **Secrets** (all in `neuromesh-system`) — see commands below.
3. **Policy engine** — Deployment + Service.
4. **Wait Ready** — `kubectl -n neuromesh-system rollout status deploy/neuromesh-zt-policy-engine`.
5. **Agent RBAC** — correlator ClusterRole/Binding.
6. **Agent DaemonSet** — after PE is Ready preferred (first sync succeeds).

```bash
# After Secrets exist:
kubectl apply -f deploy/kubernetes/neuromesh-zt-policy-engine-deployment.yaml
kubectl apply -f deploy/kubernetes/neuromesh-zt-policy-engine-service.yaml
kubectl -n neuromesh-system rollout status deploy/neuromesh-zt-policy-engine --timeout=120s

kubectl apply -f deploy/kubernetes/neuromesh-agent-correlator-rbac.yaml
kubectl apply -f deploy/kubernetes/neuromesh-agent.yaml
```

### Exact Secret commands

Generate an Ed25519 policy-bundle signing keypair (Cosign-compatible wire; same as PE README):

```bash
mkdir -p /tmp/neuromesh-k8s-keys
openssl genpkey -algorithm Ed25519 \
  -out /tmp/neuromesh-k8s-keys/policy-bundle-signing.pem
openssl pkey -in /tmp/neuromesh-k8s-keys/policy-bundle-signing.pem \
  -pubout -out /tmp/neuromesh-k8s-keys/policy-bundle.pub
chmod 600 /tmp/neuromesh-k8s-keys/policy-bundle-signing.pem
```

1. **Shared bearer token** (PE + agent):

```bash
kubectl -n neuromesh-system create secret generic neuromesh-policy-bundle-token \
  --from-literal=token="$(openssl rand -hex 32)"
```

2. **PE signing private key** (PKCS#8 PEM):

```bash
kubectl -n neuromesh-system create secret generic neuromesh-policy-bundle-signing-key \
  --from-file=signing.pem=/tmp/neuromesh-k8s-keys/policy-bundle-signing.pem
```

3. **Agent verify public key** (matching `.pub` — Issue #108 dedicated key, **not** image Cosign):

```bash
kubectl -n neuromesh-system create secret generic neuromesh-policy-bundle-pubkey \
  --from-file=bundle.pub=/tmp/neuromesh-k8s-keys/policy-bundle.pub
```

4. **SPIFFE trust bundle** (required — PE uses `static_file` mode and **refuses to boot** without a readable PEM bundle; never enable `NEUROMESH_INSECURE_MOCK_IDENTITY` in cluster):

```bash
# Replace path with your SPIRE / SPIFFE trust-domain bundle PEM for neuromesh.security
kubectl -n neuromesh-system create secret generic neuromesh-spiffe-trust-bundle \
  --from-file=bundle.pem=/path/to/spiffe-trust-bundle.pem
```

5. **Cosign pubkey** (existing — agent bytecode / image attestation only):

```bash
kubectl -n neuromesh-system create secret generic neuromesh-cosign-pubkey \
  --from-file=cosign.pub=./cosign.pub
```

### Image tags

Manifests pin `:0.1.0` (same style as agent / admission). CI publishes
`ghcr.io/neuromesh-security/neuromesh-zt-policy-engine:ci` and `:<sha>`.
If `:0.1.0` is not on GHCR yet, retag a build that includes Issue **#108**
signing + T-PB-04 temporal (`schema_version` **3**) before live verify.

## Agent behavior (accurate)

| Condition | Behavior |
|-----------|----------|
| `NEUROMESH_ZT_POLICY_ENGINE_URL` **unset** | Policy sync **disabled**; bootstrap deny prefixes only (`/tmp/`, `/dev/shm/`, `/var/tmp/`). |
| URL **set**, PE not Ready / unreachable | Sync attempts **fail**; agent retains bootstrap / last-known-good deny maps (**fail-closed**). Agent does **not** crash solely because PE is down — LSM enforcement continues. |
| URL set, PE Ready, token + verify pubkey OK | Sync every **30s**; Cosign-compatible signature + schema **3** temporal checks before any map apply. |

Therefore: prefer PE **Ready** before rolling the agent so the first sync succeeds. Applying the agent first is **safe for deny enforcement**, but identity exceptions stay **Invalid** until a successful PE sync.

## Live k3s verification sequence (paste-back)

Run on the droplet (Linux / k3s). Live evidence is **not** produced from Windows.

```bash
# --- 0) Preflight ---
kubectl get ns neuromesh-system 2>/dev/null || kubectl create namespace neuromesh-system
cd /path/to/neuromesh

# --- 1) Keys + Secrets ---
mkdir -p /tmp/neuromesh-k8s-keys
openssl genpkey -algorithm Ed25519 \
  -out /tmp/neuromesh-k8s-keys/policy-bundle-signing.pem
openssl pkey -in /tmp/neuromesh-k8s-keys/policy-bundle-signing.pem \
  -pubout -out /tmp/neuromesh-k8s-keys/policy-bundle.pub
chmod 600 /tmp/neuromesh-k8s-keys/policy-bundle-signing.pem

# SPIFFE: use a real trust-domain PEM for neuromesh.security (lab may use a
# SPIRE-exported bundle). PE will not become Ready without this Secret.
test -s /path/to/spiffe-trust-bundle.pem

kubectl -n neuromesh-system create secret generic neuromesh-policy-bundle-token \
  --from-literal=token="$(openssl rand -hex 32)" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n neuromesh-system create secret generic neuromesh-policy-bundle-signing-key \
  --from-file=signing.pem=/tmp/neuromesh-k8s-keys/policy-bundle-signing.pem \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n neuromesh-system create secret generic neuromesh-policy-bundle-pubkey \
  --from-file=bundle.pub=/tmp/neuromesh-k8s-keys/policy-bundle.pub \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n neuromesh-system create secret generic neuromesh-spiffe-trust-bundle \
  --from-file=bundle.pem=/path/to/spiffe-trust-bundle.pem \
  --dry-run=client -o yaml | kubectl apply -f -
# Cosign pubkey still required for agent bytecode attestation:
kubectl -n neuromesh-system create secret generic neuromesh-cosign-pubkey \
  --from-file=cosign.pub=./cosign.pub \
  --dry-run=client -o yaml | kubectl apply -f -

# --- 2) Apply PE + wait Ready ---
kubectl apply -f deploy/kubernetes/neuromesh-zt-policy-engine-deployment.yaml
kubectl apply -f deploy/kubernetes/neuromesh-zt-policy-engine-service.yaml
kubectl -n neuromesh-system rollout status deploy/neuromesh-zt-policy-engine --timeout=120s

# --- 3) healthz + signed bundle ---
kubectl -n neuromesh-system port-forward svc/neuromesh-zt-policy-engine 18080:8080 &
PF_PID=$!
sleep 2
curl -sfS http://127.0.0.1:18080/healthz
TOKEN=$(kubectl -n neuromesh-system get secret neuromesh-policy-bundle-token \
  -o jsonpath='{.data.token}' | base64 -d)
curl -sS -D - -H "Authorization: Bearer ${TOKEN}" \
  http://127.0.0.1:18080/v1/policy-bundle | tee /tmp/pe-bundle.out
# Expect: HTTP 200, header X-Neuromesh-Policy-Bundle-Signature, JSON schema_version 3
# with not_before / not_after
kill $PF_PID 2>/dev/null || true

# --- 4) Agent ---
kubectl apply -f deploy/kubernetes/neuromesh-agent-correlator-rbac.yaml
kubectl apply -f deploy/kubernetes/neuromesh-agent.yaml
kubectl -n neuromesh-system rollout status ds/neuromesh-agent --timeout=180s

# --- 5) Agent logs: applied path-prefix + schema 3 / temporal ---
kubectl -n neuromesh-system logs -l app.kubernetes.io/name=neuromesh-agent --tail=200 \
  | grep -E 'applied path-prefix|schema_version|policy-bundle|zt-policy-engine|bundle_'
```

### Host-agent alternative

If the DaemonSet image lacks latest PE signing / temporal features, run the
host binary with the same env and mount paths (simulate Secret mounts):

```bash
export NEUROMESH_ZT_POLICY_ENGINE_URL=http://neuromesh-zt-policy-engine.neuromesh-system.svc.cluster.local:8080
# Or NodePort / port-forward to PE if host DNS cannot resolve ClusterIP.
export NEUROMESH_POLICY_BUNDLE_TOKEN_FILE=/etc/neuromesh/policy-bundle/token
export NEUROMESH_POLICY_BUNDLE_PUBLIC_KEY_PATH=/etc/neuromesh/policy-bundle-pubkey/bundle.pub
export NEUROMESH_COSIGN_PUBLIC_KEY_PATH=/etc/neuromesh/cosign/cosign.pub
# Bind-mount or copy Secret files to those paths, then:
sudo -E ./target/release/agent-ebpf-sensor
```

See also `scripts/manual_verify_k8s_policy_engine.sh` for a non-destructive
checklist of the same sequence.

## Slice 2b-i notes

- `NEUROMESH_IDENTITY_CORRELATOR=1` and `NEUROMESH_CGROUP_ROOT=/host/sys/fs/cgroup` are set on the DaemonSet.
- **Never** set `NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS` here (lab/manual seed only).
- Auto-correlation/insert is **2b-ii** — not shipped in these manifests.
- RBAC cannot scope pods to “this node only”; `spec.nodeName` fieldSelector is data-plane filtering. See `docs/threat-model.md` residual risks.
