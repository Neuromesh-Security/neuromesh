// SPDX-License-Identifier: GPL-2.0
// Neuromesh process visibility — sys_enter_execve tracepoint (Ring 0).
//
// CO-RE / BTF maps (SEC ".maps"), bounded user probes, drop-on-full ringbuf.
// No envp extraction — keeps stack under the 512-byte BPF limit.

#include "bpf_helpers.h"

char LICENSE[] SEC("license") = "GPL";

#define ARGV0_LEN 128
#define CWD_LEN 256
#define DROPPED_KEY 0

/* x86_64 kernel 6.x best-effort: task_struct->fs->pwd.path.dentry */
#define TASK_FS_OFFSET 1760
#define FS_PWD_DENTRY_OFFSET 16
#define DENTRY_D_INAME_OFFSET 52

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

static __always_inline void read_cwd_best_effort(char *cwd, __u32 cwd_len)
{
	void *task;
	void *fs;
	void *dentry;

	if (!cwd || cwd_len < 2)
		return;

	task = (void *)(long)bpf_get_current_task();
	if (!task)
		return;

	if (bpf_probe_read_kernel(&fs, sizeof(fs),
				  (const void *)((const char *)task + TASK_FS_OFFSET)))
		return;
	if (!fs)
		return;

	if (bpf_probe_read_kernel(&dentry, sizeof(dentry),
				  (const void *)((const char *)fs + FS_PWD_DENTRY_OFFSET)))
		return;
	if (!dentry)
		return;

	bpf_probe_read_kernel_str(cwd, cwd_len,
				  (const void *)((const char *)dentry + DENTRY_D_INAME_OFFSET));
}

SEC("tracepoint/syscalls/sys_enter_execve")
int neuromesh_sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
	struct process_event_t *event;
	const char *filename_ptr;
	char argv0_tmp[ARGV0_LEN];
	char cwd_tmp[CWD_LEN];
	__u64 pid_tgid;
	__u64 uid_gid;

	event = bpf_ringbuf_reserve(&PROCESS_EVENTS, sizeof(*event), 0);
	if (!event) {
		record_drop();
		return 0;
	}

	pid_tgid = bpf_get_current_pid_tgid();
	event->pid = (__u32)(pid_tgid >> 32);

	uid_gid = bpf_get_current_uid_gid();
	event->uid = (__u32)uid_gid;

	__builtin_memset(event->argv0, 0, sizeof(event->argv0));
	__builtin_memset(event->cwd, 0, sizeof(event->cwd));

	filename_ptr = (const char *)ctx->args[0];
	__builtin_memset(argv0_tmp, 0, sizeof(argv0_tmp));
	if (filename_ptr)
		bpf_probe_read_user_str(argv0_tmp, sizeof(argv0_tmp), filename_ptr);
	__builtin_memcpy(event->argv0, argv0_tmp, sizeof(event->argv0));

	__builtin_memset(cwd_tmp, 0, sizeof(cwd_tmp));
	read_cwd_best_effort(cwd_tmp, sizeof(cwd_tmp));
	__builtin_memcpy(event->cwd, cwd_tmp, sizeof(event->cwd));

	bpf_ringbuf_submit(event, 0);
	return 0;
}
