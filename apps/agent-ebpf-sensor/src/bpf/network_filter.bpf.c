// SPDX-License-Identifier: GPL-2.0
// Neuromesh L4 network visibility — kprobe/tcp_connect.
//
// CO-RE / BTF maps (SEC ".maps"). Socket destination fields are read into a
// kernel stack snapshot via bpf_probe_read_kernel, then copied into ringbuf.

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include "bpf_helpers.h"

char LICENSE[] SEC("license") = "GPL";

#define DROPPED_KEY 0

struct network_event_t {
	__u32 pid;
	__u32 uid;
	__u32 dest_ip;
	__u16 dest_port;
} __attribute__((packed));

struct sock_dest_stack_t {
	__be32 daddr;
	__be16 dport;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} NETWORK_EVENTS SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} DROPPED_EVENTS SEC(".maps");

static __always_inline void record_drop(void)
{
	__u32 key = DROPPED_KEY;
	__u64 *counter = bpf_map_lookup_elem(&DROPPED_EVENTS, &key);
	__u64 next;

	if (!counter)
		return;

	next = *counter + 1;
	bpf_map_update_elem(&DROPPED_EVENTS, &key, &next, BPF_ANY);
}

static __always_inline void read_sock_dest(struct sock *sk,
					   struct sock_dest_stack_t *out)
{
	__u32 daddr_off;
	__u32 dport_off;

	if (!sk || !out)
		return;

	__builtin_memset(out, 0, sizeof(*out));

	daddr_off = __builtin_offsetof(struct sock, __sk_common) +
		    __builtin_offsetof(struct sock_common, skc_daddr);
	dport_off = __builtin_offsetof(struct sock, __sk_common) +
		    __builtin_offsetof(struct sock_common, skc_dport);

	bpf_probe_read_kernel(&out->daddr, sizeof(out->daddr),
			      (const char *)sk + daddr_off);
	bpf_probe_read_kernel(&out->dport, sizeof(out->dport),
			      (const char *)sk + dport_off);
}

SEC("kprobe/tcp_connect")
int neuromesh_tcp_connect(struct pt_regs *ctx)
{
	struct sock_dest_stack_t stack_sock;
	struct network_event_t stack_event;
	struct network_event_t *event;
	__u64 pid_tgid;
	__u64 uid_gid;
	struct sock *sk;

	sk = (struct sock *)PT_REGS_PARM1(ctx);
	if (!sk)
		return 0;

	read_sock_dest(sk, &stack_sock);
	if (!stack_sock.daddr)
		return 0;

	__builtin_memset(&stack_event, 0, sizeof(stack_event));
	stack_event.dest_ip = (__u32)stack_sock.daddr;
	stack_event.dest_port = (__u16)stack_sock.dport;

	event = bpf_ringbuf_reserve(&NETWORK_EVENTS, sizeof(*event), 0);
	if (!event) {
		record_drop();
		return 0;
	}

	pid_tgid = bpf_get_current_pid_tgid();
	stack_event.pid = (__u32)(pid_tgid >> 32);
	uid_gid = bpf_get_current_uid_gid();
	stack_event.uid = (__u32)uid_gid;

	__builtin_memcpy(event, &stack_event, sizeof(stack_event));
	bpf_ringbuf_submit(event, 0);
	return 0;
}
