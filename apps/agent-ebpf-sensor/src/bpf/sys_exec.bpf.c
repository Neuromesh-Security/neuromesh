// SPDX-License-Identifier: GPL-2.0
// Neuromesh process visibility — kprobe/sys_execve (stable across 6.x kernels).
//
// CO-RE / BTF maps (SEC ".maps"). User memory is probed into stack buffers,
// then copied into ringbuf records (never probe directly into ringbuf memory).

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

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

static __always_inline int kprobe_sys_execve_handler(const char *filename)
{
	char stack_buf[ARGV0_LEN];
	struct process_event_t *event;
	long err;
	__u64 pid_tgid;
	__u64 uid_gid;

	__builtin_memset(stack_buf, 0, sizeof(stack_buf));
	if (!filename)
		return 0;

	err = bpf_probe_read_user_str(stack_buf, sizeof(stack_buf), filename);
	if (err <= 0)
		return 0;

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

SEC("kprobe/sys_execve")
int kprobe_sys_execve(struct pt_regs *ctx)
{
	return kprobe_sys_execve_handler((const char *)PT_REGS_PARM1(ctx));
}
