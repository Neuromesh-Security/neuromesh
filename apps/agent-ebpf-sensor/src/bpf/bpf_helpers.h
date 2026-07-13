/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#pragma once

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef long long __s64;

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

enum bpf_map_type {
	BPF_MAP_TYPE_RINGBUF = 27,
};

enum {
	BPF_ANY = 0,
};

static void *(*bpf_ringbuf_reserve)(void *ringmap, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *ringbuf_record, __u64 flags) = (void *)132;
static void (*bpf_ringbuf_discard)(void *ringbuf_record, __u64 flags) = (void *)133;

static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)15;
static int (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)16;
static __u64 (*bpf_get_current_task)(void) = (void *)167;

static long (*bpf_probe_read_user_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)147;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *src) = (void *)113;

#define SEC(NAME) __attribute__((section(NAME), used))
