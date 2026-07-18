# BTF test fixtures

`vmlinux-5.15.167.4-microsoft-standard-wsl2.btf` is the **raw, unmodified**
`BTF_KIND_*` metadata blob copied byte-for-byte from `/sys/kernel/btf/vmlinux`
on a running Linux `5.15.167.4-microsoft-standard-WSL2` kernel (extracted via
`docker run --privileged -v /sys/kernel/btf:/btf:ro alpine cp /btf/vmlinux ...`
on 2026-07-17). It is real kernel-emitted debug metadata, not synthetic data,
and is used by `src/btf_offsets.rs`'s unit tests as ground truth for the
minimal BTF parser used to resolve `task_struct`/`linux_binprm` field offsets
at agent startup.

Ground truth for the three fields the parser resolves was obtained
independently with `bpftool btf dump file <this file> -j`, filtered with `jq`
for the `task_struct` and `linux_binprm` structs — **not** by running this
project's own parser — so the unit test that compares against these values is
a genuine cross-check against a separate, industry-standard BTF reader, not a
tautology:

| Struct          | Member        | bpftool `bits_offset` | Byte offset |
|------------------|---------------|-----------------------:|-------------:|
| `task_struct`    | `tgid`        | 11488                   | 1436         |
| `task_struct`    | `real_parent` | 11584                   | 1448         |
| `linux_binprm`   | `filename`    | 768                     | 96           |

Notably, none of these match the previous hardcoded offset constants that
lived in `ebpf/src/main.rs` (`BPRM_FILENAME_OFFSET = 72`,
`TASK_REAL_PARENT_OFFSET = 1216`, `TASK_TGID_OFFSET = 104`) — on this real,
currently-supported kernel, every one of the three hardcoded constants was
already wrong. That mismatch is exactly the class of hazard the dynamic
BTF-based resolver in `src/btf_offsets.rs` exists to eliminate.

## Known limitation: single real kernel fixture

Only one real kernel's BTF blob is checked in here. Additional LTS / HWE
blobs (e.g. real 6.1, or non-Azure 6.8) were not obtainable as checked-in
fixtures in the environment this file was produced in:

- The build/test sandbox's only running kernel is the Docker Desktop WSL2
  backend's `5.15.167.4-microsoft-standard-WSL2` — there is no way to boot an
  alternate real kernel to read its live `/sys/kernel/btf/vmlinux` from this
  environment.
- [`aquasecurity/btfhub-archive`](https://github.com/aquasecurity/btfhub-archive)
  (checked directly against its GitHub API), the standard public archive of
  historical kernel BTF blobs, only covers Ubuntu 16.04/18.04/20.04-era
  kernels — i.e. kernels old enough to predate `CONFIG_DEBUG_INFO_BTF` being
  built into the kernel image by default. Modern 6.x kernels ship BTF
  built-in and are consequently not archived there.

### What CI actually adds (and what it does not)

`ebpf-verifier-check` in `.github/workflows/ci.yml` runs the production
BTF resolver against each matrix runner's *live* `/sys/kernel/btf/vmlinux`
(via `verify-ebpf` → `Btf::from_sys_fs()` → `resolve_offsets` →
`EbpfLoader::override_global` → verifier load). That is a real, fail-closed
gate on the highest-trust path.

Matrix labels are honest about runner + approximate booted kernel
(Issue [#52](https://github.com/Neuromesh-Security/neuromesh/issues/52)):

| Matrix label                    | `runs-on`      | Actual booted kernel (approx.) |
|---------------------------------|----------------|--------------------------------|
| `ubuntu-22.04 / ~6.8-azure`     | `ubuntu-22.04` | `6.8.0-*-azure`                |
| `ubuntu-24.04 / ~6.17-azure`    | `ubuntu-24.04` | `6.17.0-*-azure`               |

So CI exercises **two** distinct live Azure HWE kernels (≈6.8 and ≈6.17),
not real 5.15 / 6.1 LTS. Closing that residual gap still requires a scoped
manual pre-release check on real target hardware (same disclosure pattern as
`execve_stress_test`), not hosted-runner matrix labels.

The negative-path tests in `src/btf_offsets.rs` (malformed/truncated BTF,
missing struct, missing member, unexpected bitfield encoding, misaligned
offset, out-of-range offset) do not depend on kernel version and give
independent coverage of the parser's fail-closed behavior regardless of this
gap. If a 6.1 or 6.8 real BTF blob becomes available later (e.g. by extracting
`.BTF` from a `linux-image-*-dbgsym` package's ELF `vmlinux`), it should be
added here and cross-checked with `bpftool` the same way.
