# Runbook: agent pinned BPF map ABI / CrashLoop recovery

**Audience:** on-call / lab operators  
**Related:** Issue #208, ADR-002, `apps/agent-ebpf-sensor/src/pin_abi.rs`

## Symptoms

- DaemonSet `neuromesh-agent` CrashLoop / `0/1 Error` after image upgrade.
- `kubectl logs --previous` ends with verifier output resembling:

```text
invalid access to map value, value_size=20 off=20 size=1
R4 min value is outside of the allowed memory range
Caused by:
    Permission denied (os error 13)
```

- Agent started fine on this node with a **pre-#134** image (16-byte deny key).
- Old LSM program may still be attached via the link pin — deny still works for
  whatever prefixes were last loaded, but the **new** agent cannot start or sync.

## Diagnostic checks (read-only first)

```bash
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
PIN=/sys/fs/bpf/neuromesh

sudo ls -la "$PIN"
sudo bpftool map show pinned "$PIN/PATH_DENY_LIST"
sudo bpftool map show pinned "$PIN/PATH_DENY_COUNT"
sudo bpftool map show pinned "$PIN/PROCESS_EVENTS" 2>/dev/null || true
sudo bpftool map show pinned "$PIN/RLIMIT_BUCKET" 2>/dev/null || true
sudo bpftool link show
sudo bpftool prog show name nm_lsm_bprm
```

**H1 (ABI drift):** `PATH_DENY_LIST` reports `value 20B` (legacy) while the
running/new image expects **36B**. Optional: start a scratch agent:

```bash
sudo mkdir -p /sys/fs/bpf/neuromesh-scratch
NEUROMESH_BPF_PIN_ROOT=/sys/fs/bpf/neuromesh-scratch \
  /path/to/new-agent-bin &
# expect clean load; then:
sudo rm -rf /sys/fs/bpf/neuromesh-scratch
```

## What automatic migration does (post-fix)

On agent start, before `EbpfLoader::load`:

1. Compare each pinned map to `PINNED_MAP_ABI` (`neuromesh-common`).
2. If `PATH_DENY_LIST` is the known legacy layout (value 20B): read entries,
   `rename` map pins into `legacy_abi_<n>/` (**LSM link pin stays** — no
   enforcement gap), load fresh maps, seed widened prefixes, attach new LSM,
   then delete `legacy_abi_<n>`.
3. Unknown layouts → **refuse start** with an actionable error (never coerce).
4. Process maps (`PROCESS_EVENTS`, `RLIMIT_BUCKET`) may be recreated on mismatch
   (non-enforcement state only).

Live proof script: `scripts/manual_verify_pin_abi_migration.sh`.

## Manual recovery (production caution)

> **WARNING:** Manually removing pins opens an **enforcement gap** until a new
> LSM program attaches. Prefer the automatic migration in a fixed agent image.
> Use the wipe path only on **lab** nodes, or when the layout is unknown and
> migration cannot run.

1. Capture evidence (`bpftool map show` → `~/pins-before.txt`).
2. Prefer deploying a build that includes Issue #208 migration and restarting
   the DaemonSet — **do not** wipe pins first.
3. If migration refuses an unknown layout: escalate; do not invent map sizes.

## Lab-only emergency unblock

Print-and-confirm with the maintainer before running. Between `rm` and the new
LSM attach the node has **no** `bprm_check_security` deny.

```bash
kubectl -n neuromesh-system delete ds neuromesh-agent
# old LSM program stays attached via link pin until pins are removed

sudo bpftool map show pinned /sys/fs/bpf/neuromesh/PATH_DENY_LIST > ~/pins-before.txt
sudo bpftool map show pinned /sys/fs/bpf/neuromesh/PATH_DENY_COUNT >> ~/pins-before.txt

sudo rm -rf /sys/fs/bpf/neuromesh/*   # ENFORCEMENT GAP STARTS (lab only)

kubectl apply -f deploy/kubernetes/neuromesh-agent.yaml
# gap ends when the new LSM attaches and pins
```

## Rollback

- **Code rollback:** revert the PR that introduced migration; redeploy prior
  agent digest. Legacy pins (36B) will then be **incompatible** with a pre-#134
  binary — do not roll agent ABI backwards without wiping pins in lab.
- **Policy rollback:** PE sync still owns deny prefixes after a successful start;
  STALE `pinned-resume` clears on the next successful bundle fetch.
