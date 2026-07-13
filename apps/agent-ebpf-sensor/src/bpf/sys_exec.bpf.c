// SPDX-License-Identifier: GPL-2.0
// Neuromesh process visibility — tracepoint syscalls/sys_enter_execve.
//
// Ringbuf records are fully zeroed before population. Filename is read via
// bounded bpf_probe_read_user_str from tracepoint args[0] (no BTF helpers).

#include "bpf_helpers.h"

char __license[] SEC("license") = "GPL";

#define COMM_LEN 16
#define FILENAME_LEN 128
#define DROPPED_KEY 0

struct process_event_t {
	__u32 pid;
	__u32 uid;
	__u32 ppid;
	char comm[COMM_LEN];
	char filename[FILENAME_LEN];
	__u64 ts;
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

SEC("tracepoint/syscalls/sys_enter_execve")
int neuromesh_process_events(struct trace_event_raw_sys_enter *ctx)
{
	struct process_event_t *event;
	__u64 pid_tgid;
	__u64 uid_gid;

	if (!ctx || !ctx->args[0])
		return 0;

	event = bpf_ringbuf_reserve(&PROCESS_EVENTS, sizeof(*event), 0);
	if (!event) {
		record_drop();
		return 0;
	}

	__builtin_memset(event, 0, sizeof(*event));

	pid_tgid = bpf_get_current_pid_tgid();
	event->pid = (__u32)(pid_tgid >> 32);
	uid_gid = bpf_get_current_uid_gid();
	event->uid = (__u32)uid_gid;
	event->ppid = 0;

	bpf_get_current_comm(event->comm, sizeof(event->comm));
	bpf_probe_read_user_str(event->filename, sizeof(event->filename),
				(const void *)ctx->args[0]);
	event->ts = bpf_ktime_get_ns();

	bpf_ringbuf_submit(event, 0);
	return 0;
}
