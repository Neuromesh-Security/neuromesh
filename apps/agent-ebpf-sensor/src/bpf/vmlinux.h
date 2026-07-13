/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Minimal vmlinux subset for CO-RE-style offsetof on tcp_connect kprobe. */
#pragma once

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __addrpair;

struct sock_common {
	union {
		__addrpair skc_addrpair;
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	union {
		__u32 skc_hash;
		__be16 skc_u16zeros[2];
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
};

struct sock {
	struct sock_common __sk_common;
};

struct pt_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long bp;
	unsigned long bx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long ax;
	unsigned long cx;
	unsigned long dx;
	unsigned long si;
	unsigned long di;
	unsigned long orig_ax;
	unsigned long ip;
	unsigned long cs;
	unsigned long flags;
	unsigned long sp;
	unsigned long ss;
};

#endif /* __VMLINUX_H__ */
