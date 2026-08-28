# Neuromesh — Kubernetes deploy

## Manifests

| File | Purpose |
|------|---------|
| `neuromesh-agent.yaml` | Namespace, DaemonSet, ServiceAccount |
| `neuromesh-agent-correlator-rbac.yaml` | Slice **2b-i** ClusterRole/Binding: pods `get/list/watch` only |
| `neuromesh-zt-policy-engine-deployment.yaml` | zt-policy-engine Deployment + ServiceAccount (port 8080) |
| `neuromesh-zt-policy-engine-service.yaml` | ClusterIP Service → agent sync DNS |
| `neuromesh-zt-policy-engine-networkpolicy.yaml` | Ingress NetworkPolicy (TCP/8080 from agent pods only) |
| `neuromesh-desired-policy.yaml` | Issue **#137 PR-1**: example DesiredPolicy ConfigMap + PE **get/watch-only** Role (OFF until Rego PR-2) |
| `admission/` | Optional Cosign admission webhook (see `admission/README.md`; Phase B part 2 TLS rotation Issue #168) |

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
kubectl apply -f deploy/kubernetes/neuromesh-zt-policy-engine-networkpolicy.yaml
kubectl -n neuromesh-system rollout status deploy/neuromesh-zt-policy-engine --timeout=120s

kubectl apply -f deploy/kubernetes/neuromesh-agent-correlator-rbac.yaml
kubectl apply -f deploy/kubernetes/neuromesh-agent.yaml
```

NetworkPolicy live gate (after PE + agent are Ready):

```bash
sudo -E bash scripts/manual_verify_network_policies.sh
# Optional: APPLY=1 to apply the in-repo NetworkPolicy YAMLs first
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

5. **Cosign pubkey** (agent bytecode + GHCR image attestation):

Use **`deploy/kubernetes/ci-cosign.pub`** — the CI static key (`secrets.COSIGN_PUBLIC_KEY`)
that signed the GHCR agent bytecode manifest. **Not** `~/neuromesh-attest-lab/cosign/cosign.pub`
(that key is for locally-built binaries only; the agent correctly fail-closes on a mismatch).

```bash
kubectl -n neuromesh-system create secret generic neuromesh-cosign-pubkey \
  --from-file=cosign.pub=deploy/kubernetes/ci-cosign.pub
```

### Image tags (confirmed fresh for live verify)

CI on `main` publishes **`:ci` / `:<fullsha>`** (and Cosign digests) — **not** `:0.1.0`.

| Component | Confirmed-fresh reference (post-#109 signing + #111 temporal, SHA `62062bbd…`) |
|-----------|--------------------------------------------------------------------------------|
| PE | `ghcr.io/neuromesh-security/neuromesh-zt-policy-engine@sha256:eceb694cc12409a935ca3d83a9ac856b0f3e4461131c63b193142aa828572255` |
| Agent | `ghcr.io/neuromesh-security/neuromesh-agent-ebpf-sensor@sha256:413424ce5ec990e97b58014daa05ae8addab27de5afcac74904eb28fdcd5de2d` |
| Admission webhook | `ghcr.io/neuromesh-security/neuromesh-k8s-admission-webhook@sha256:e3997b4c42763c2a2b488b3b0246e8bddaa071ba5d1328d6abd5ea118370e273` |

Manifests on this branch pin those digests. Do **not** live-test with a stale `:0.1.0` pin for the webhook (that tag is never published by CI).

## Agent behavior (accurate)

| Condition | Behavior |
|-----------|----------|
| `NEUROMESH_ZT_POLICY_ENGINE_URL` **unset** | Policy sync **disabled**; bootstrap deny prefixes only (`/tmp/`, `/dev/shm/`, `/var/tmp/`). |
| URL **set**, PE not Ready / unreachable | Sync attempts **fail**; agent retains bootstrap / last-known-good deny maps (**fail-closed**). Agent does **not** crash solely because PE is down — LSM enforcement continues. |
| URL set, PE Ready, token + verify pubkey OK | Sync every **30s**; Cosign-compatible signature + schema **3** temporal checks before any map apply. |

Therefore: prefer PE **Ready** before rolling the agent so the first sync succeeds. Applying the agent first is **safe for deny enforcement**, but identity exceptions stay **Invalid** until a successful PE sync.

## Live k3s verification (MANDATORY script)

**Do not improvise.** The full Secrets → PE → curl → agent path is:

[`scripts/manual_verify_k8s_policy_engine.sh`](../../scripts/manual_verify_k8s_policy_engine.sh)

```bash
cd /path/to/neuromesh
git checkout feat/k8s-zt-policy-engine-productize   # or pull PR #113
# Cosign defaults to deploy/kubernetes/ci-cosign.pub (CI key for GHCR images).
# Do NOT point NEUROMESH_COSIGN_PUB_FILE at the lab attest-lab key.
# optional: export NEUROMESH_SPIFFE_BUNDLE_PEM=/path/to/real-spire-bundle.pem
sudo -E bash scripts/manual_verify_k8s_policy_engine.sh
```

Paste the **full** script output to PR #113. The script pins the confirmed-fresh
PE/agent digests above, creates all Secrets, applies manifests, curls `/healthz`
and signed `/v1/policy-bundle`, then checks agent env + sync logs.

## Slice 2b-i notes

- `NEUROMESH_IDENTITY_CORRELATOR=1` and `NEUROMESH_CGROUP_ROOT=/host/sys/fs/cgroup` are set on the DaemonSet.
- **Never** set `NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS` here (lab/manual seed only).
- Auto-correlation/insert is **2b-ii** — not shipped in these manifests.
- RBAC cannot scope pods to “this node only”; `spec.nodeName` fieldSelector is data-plane filtering. See `docs/threat-model.md` residual risks.
