// SPDX-License-Identifier: GPL-2.0
// Neuromesh process visibility — tracepoint syscalls/sys_enter_execve.
//
// DEBUG SKELETON: verifier-safe minimum — scalar pid only, no ctx->args reads.

#include "bpf_helpers.h"

char __license[] SEC("license") = "GPL";

#define COMM_LEN 16
#define FILENAME_LEN 128

struct process_event_t {
	__u32 pid;
	__u32 uid;
	__u32 ppid;
	char comm[COMM_LEN];
	char filename[FILENAME_LEN];
	__u64 ts;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} PROCESS_EVENTS SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int neuromesh_process_events(void *ctx)
{
	struct process_event_t *event;
	__u64 pid_tgid;

	(void)ctx;

	event = bpf_ringbuf_reserve(&PROCESS_EVENTS, sizeof(*event), 0);
	if (!event)
		return 0;

	__builtin_memset(event, 0, sizeof(*event));

	pid_tgid = bpf_get_current_pid_tgid();
	event->pid = (__u32)(pid_tgid >> 32);

	bpf_ringbuf_submit(event, 0);
	return 0;
}
