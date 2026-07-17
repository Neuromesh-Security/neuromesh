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

Only one real kernel's BTF blob is checked in here. Kernels 6.1 and 6.8+ (the
other two targets in this project's stated CI kernel matrix) were not
obtainable as real BTF blobs in the environment this fixture was produced in:

- The build/test sandbox's only running kernel is the Docker Desktop WSL2
  backend's `5.15.167.4-microsoft-standard-WSL2` — there is no way to boot an
  alternate real kernel to read its live `/sys/kernel/btf/vmlinux` from this
  environment.
- [`aquasecurity/btfhub-archive`](https://github.com/aquasecurity/btfhub-archive)
  (checked directly against its GitHub API), the standard public archive of
  historical kernel BTF blobs, only covers Ubuntu 16.04/18.04/20.04-era
  kernels — i.e. kernels old enough to predate `CONFIG_DEBUG_INFO_BTF` being
  built into the kernel image by default. Kernels 6.1 and 6.8 ship BTF
  built-in and are consequently not archived there.

The negative-path tests in `src/btf_offsets.rs` (malformed/truncated BTF,
missing struct, missing member, unexpected bitfield encoding, misaligned
offset, out-of-range offset) do not depend on kernel version and give
independent coverage of the parser's fail-closed behavior regardless of this
gap. If a 6.1 or 6.8 real BTF blob becomes available later (e.g. by extracting
`.BTF` from a `linux-image-*-dbgsym` package's ELF `vmlinux`), it should be
added here and cross-checked with `bpftool` the same way.
