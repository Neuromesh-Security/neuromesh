// SPDX-License-Identifier: GPL-2.0
// Neuromesh process visibility — tracepoint syscalls/sys_enter_execve.
//
// CO-RE / BTF maps (SEC ".maps"). User strings are read into a stack buffer via
// bounded bpf_probe_read_user, then copied into the ringbuf record.

#include "bpf_helpers.h"

char LICENSE[] SEC("license") = "GPL";

#define ARGV0_LEN 128
#define CWD_LEN 256
#define DROPPED_KEY 0

struct process_event_t {
	__u32 pid;
	__u32 uid;
	char argv0[ARGV0_LEN];
	char cwd[CWD_LEN];
};

struct trace_event_raw_sys_enter {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	__s64 id;
	unsigned long args[6];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} PROCESS_EVENTS SEC(".maps");

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

static __always_inline void read_user_cstr(char *dst, __u32 dst_len, unsigned long addr)
{
	if (!dst || dst_len < 2 || !addr) {
		if (dst && dst_len)
			dst[0] = '\0';
		return;
	}

	__builtin_memset(dst, 0, dst_len);
	bpf_probe_read_user(dst, dst_len - 1, (const void *)addr);
	dst[dst_len - 1] = '\0';
}

SEC("tracepoint/syscalls/sys_enter_execve")
int neuromesh_process_events(struct trace_event_raw_sys_enter *ctx)
{
	char stack_buf[ARGV0_LEN];
	struct process_event_t *event;
	__u64 pid_tgid;
	__u64 uid_gid;

	if (!ctx || !ctx->args[0])
		return 0;

	read_user_cstr(stack_buf, sizeof(stack_buf), ctx->args[0]);

	event = bpf_ringbuf_reserve(&PROCESS_EVENTS, sizeof(*event), 0);
	if (!event) {
		record_drop();
		return 0;
	}

	pid_tgid = bpf_get_current_pid_tgid();
	event->pid = (__u32)(pid_tgid >> 32);
	uid_gid = bpf_get_current_uid_gid();
	event->uid = (__u32)uid_gid;

	__builtin_memcpy(event->argv0, stack_buf, sizeof(event->argv0));
	__builtin_memset(event->cwd, 0, sizeof(event->cwd));

	bpf_ringbuf_submit(event, 0);
	return 0;
}
