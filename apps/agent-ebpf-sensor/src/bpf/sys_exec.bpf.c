// SPDX-License-Identifier: GPL-2.0
// Neuromesh process visibility — tracepoint syscalls/sys_enter_execve.
//
// CO-RE / BTF maps (SEC ".maps"). User filename is read into a stack buffer via
// bpf_probe_read_user_str, then copied into the ringbuf record.

#include "bpf_helpers.h"

char __license[] SEC("license") = "GPL";

#define COMM_LEN 16
#define FILENAME_LEN 128
#define DROPPED_KEY 0

/* task_struct offsets (x86_64, kernel 6.x — best-effort, matches Rust eBPF hook). */
#define TASK_REAL_PARENT_OFFSET 1216
#define TASK_TGID_OFFSET 104

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

static __always_inline __u32 read_ppid_best_effort(void)
{
	void *task = (void *)bpf_get_current_task();
	void *parent = NULL;
	__u32 ppid = 0;

	if (!task)
		return 0;

	if (bpf_probe_read_kernel(&parent, sizeof(parent),
				  (const void *)task + TASK_REAL_PARENT_OFFSET))
		return 0;
	if (!parent)
		return 0;
	if (bpf_probe_read_kernel(&ppid, sizeof(ppid),
				  (const void *)parent + TASK_TGID_OFFSET))
		return 0;
	return ppid;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int neuromesh_process_events(struct trace_event_raw_sys_enter *ctx)
{
	char filename_buf[FILENAME_LEN];
	struct process_event_t *event;
	__u64 pid_tgid;
	__u64 uid_gid;

	if (!ctx || !ctx->args[0])
		return 0;

	__builtin_memset(filename_buf, 0, sizeof(filename_buf));
	bpf_probe_read_user_str(filename_buf, sizeof(filename_buf),
				(const void *)ctx->args[0]);

	event = bpf_ringbuf_reserve(&PROCESS_EVENTS, sizeof(*event), 0);
	if (!event) {
		record_drop();
		return 0;
	}

	pid_tgid = bpf_get_current_pid_tgid();
	event->pid = (__u32)(pid_tgid >> 32);
	uid_gid = bpf_get_current_uid_gid();
	event->uid = (__u32)uid_gid;
	event->ppid = read_ppid_best_effort();

	__builtin_memset(event->comm, 0, sizeof(event->comm));
	bpf_get_current_comm(event->comm, sizeof(event->comm));

	__builtin_memcpy(event->filename, filename_buf, sizeof(event->filename));
	event->ts = bpf_ktime_get_ns();

	bpf_ringbuf_submit(event, 0);
	return 0;
}
