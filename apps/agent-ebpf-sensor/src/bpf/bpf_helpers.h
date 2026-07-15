/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#pragma once

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef int __s32;
typedef long long __s64;

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

#define __always_inline inline __attribute__((__always_inline__))

/* Kernel `linux/compiler_types.h` sparse annotation — no-op outside sparse. */
#define __user

enum bpf_map_type {
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_RINGBUF = 27,
};

enum {
	BPF_ANY = 0,
};

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value,
				   __u64 flags) = (void *)2;

static void *(*bpf_ringbuf_reserve)(void *ringmap, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *ringbuf_record, __u64 flags) = (void *)132;
static void (*bpf_ringbuf_discard)(void *ringbuf_record, __u64 flags) = (void *)133;

static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)15;
static long (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)16;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
/* Helper ids below cross-checked against the kernel's `enum bpf_func_id`
 * (include/uapi/linux/bpf.h); current __BPF_FUNC_MAX_ID is 212, so any id
 * >= 212 is guaranteed to be rejected by every kernel with
 * "invalid func unknown#<id>". */
static void *(*bpf_get_current_task)(void) = (void *)35;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)80;
/* NOTE: there is no `bpf_get_current_euid_egid` helper in the kernel — no
 * such BPF_FUNC has ever existed. Effective uid/gid must be read from
 * `task_struct->cred->euid` via CO-RE (see capture_credentials() in
 * sys_exec.bpf.c), not through a helper call. */

static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) =
	(void *)112;
static long (*bpf_probe_read_user_str)(void *dst, __u32 size, const void *unsafe_ptr) =
	(void *)114;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *src) = (void *)113;
static long (*bpf_probe_read_kernel_str)(void *dst, __u32 size, const void *src) = (void *)115;

#define SEC(NAME) __attribute__((section(NAME), used))
