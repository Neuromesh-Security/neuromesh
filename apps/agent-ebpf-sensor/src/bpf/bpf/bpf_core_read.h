/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Minimal CO-RE read helper — vendored so the build has no libbpf-dev
 * dependency, consistent with the rest of src/bpf/.
 *
 * `__builtin_preserve_access_index` tells clang to emit a BTF CO-RE field
 * relocation for the wrapped access chain instead of a compile-time-fixed
 * offset. Aya resolves the relocation against the target kernel's BTF
 * (/sys/kernel/btf/vmlinux) when the program is loaded, so the exact byte
 * layout of the local struct stand-ins in vmlinux.h does not need to match
 * the real kernel — only the accessed field names do.
 */
#pragma once

#ifndef __BPF_CORE_READ_H__
#define __BPF_CORE_READ_H__

#define bpf_core_read(dst, sz, src) \
	bpf_probe_read_kernel((dst), (sz), (const void *)__builtin_preserve_access_index(src))

#endif /* __BPF_CORE_READ_H__ */
