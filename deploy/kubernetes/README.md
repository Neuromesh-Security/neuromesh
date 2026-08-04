# Neuromesh agent — Kubernetes deploy

## Manifests

| File | Purpose |
|------|---------|
| `neuromesh-agent.yaml` | Namespace, DaemonSet, ServiceAccount |
| `neuromesh-agent-correlator-rbac.yaml` | Slice **2b-i** ClusterRole/Binding: pods `get/list/watch` only |

Apply both:

```bash
kubectl apply -f deploy/kubernetes/neuromesh-agent-correlator-rbac.yaml
kubectl apply -f deploy/kubernetes/neuromesh-agent.yaml
```

## Slice 2b-i notes

- `NEUROMESH_IDENTITY_CORRELATOR=1` and `NEUROMESH_CGROUP_ROOT=/host/sys/fs/cgroup` are set on the DaemonSet.
- **Never** set `NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS` here (lab/manual seed only).
- Auto-correlation/insert is **2b-ii** — not shipped in these manifests.
- RBAC cannot scope pods to “this node only”; `spec.nodeName` fieldSelector is data-plane filtering. See `docs/threat-model.md` residual risks.
