// SPDX-License-Identifier: GPL-2.0
// Neuromesh process visibility — sys_enter_execve tracepoint (Ring 0).

#include "bpf_helpers.h"

/* GPL license required for GPL-only tracepoint helpers on modern kernels. */
char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 128

/* x86_64 kernel 6.x best-effort offsets (matches Rust ebpf lineage reader). */
#define TASK_REAL_PARENT_OFFSET 1216
#define TASK_TGID_OFFSET 104

struct process_event_t {
	__u32 pid;
	__u32 uid;
	__u32 ppid;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
};

struct trace_event_raw_sys_enter {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s64 common_pid;
	__s64 id;
	unsigned long args[6];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} PROCESS_EVENTS SEC(".maps");

static __always_inline __u32 read_ppid_best_effort(void)
{
	void *task = (void *)(long)bpf_get_current_task();
	void *parent = 0;
	__u32 tgid = 0;

	if (!task)
		return 0;

	if (bpf_probe_read_kernel(&parent, sizeof(parent),
				  (const void *)((const char *)task + TASK_REAL_PARENT_OFFSET)))
		return 0;
	if (!parent)
		return 0;

	if (bpf_probe_read_kernel(&tgid, sizeof(tgid),
				  (const void *)((const char *)parent + TASK_TGID_OFFSET)))
		return 0;

	return tgid;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int neuromesh_sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
	struct process_event_t *event;
	const char *filename_ptr = (const char *)ctx->args[0];
	__u64 pid_tgid;
	__u64 uid_gid;

	event = bpf_ringbuf_reserve(&PROCESS_EVENTS, sizeof(*event), 0);
	if (!event)
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	event->pid = (__u32)(pid_tgid >> 32);
	event->ppid = read_ppid_best_effort();

	uid_gid = bpf_get_current_uid_gid();
	event->uid = (__u32)uid_gid;

	__builtin_memset(event->comm, 0, sizeof(event->comm));
	__builtin_memset(event->filename, 0, sizeof(event->filename));

	bpf_get_current_comm(event->comm, sizeof(event->comm));
	bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename_ptr);

	bpf_ringbuf_submit(event, 0);
	return 0;
}
