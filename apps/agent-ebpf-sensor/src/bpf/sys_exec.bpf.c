// SPDX-License-Identifier: GPL-2.0
// Neuromesh process visibility — tracepoint syscalls/sys_enter_execve.
//
// Enterprise ExecEvent v1 capture with CO-RE lineage, bounded argv probing,
// per-CPU token-bucket rate limiting (~500k events/sec), and fail-closed
// filename capture (discard + CAPTURE_FAILURES on probe fault).

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "bpf_helpers.h"
#include "exec_event.h"

char __license[] SEC("license") = "GPL";

#define RATE_LIMIT_KEY 0
#define CAPTURE_FAIL_KEY 0

/* 500k events/sec → one token every 2000 ns; burst matches one second at peak rate. */
#define NS_PER_TOKEN 2000ULL
#define MAX_TOKENS 500000ULL

struct rate_limit_state {
	__u64 last_ns;
	__u64 tokens;
};

struct trace_event_raw_sys_enter {
	struct trace_entry ent;
	long id;
	unsigned long args[6];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} PROCESS_EVENTS SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct rate_limit_state);
} RATE_LIMIT_BUCKET SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} RATE_LIMIT_DROPS SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} CAPTURE_FAILURES SEC(".maps");

static __always_inline void record_counter(void *map)
{
	__u32 key = 0;
	__u64 *counter = bpf_map_lookup_elem(map, &key);

	if (!counter)
		return;

	*counter = *counter + 1;
}

static __always_inline void record_rate_drop(void)
{
	record_counter(&RATE_LIMIT_DROPS);
}

static __always_inline void record_capture_failure(void)
{
	record_counter(&CAPTURE_FAILURES);
}

static __always_inline int rate_limit_allow(void)
{
	__u32 key = RATE_LIMIT_KEY;
	struct rate_limit_state *state;
	__u64 now;
	__u64 delta;
	__u64 refill;

	state = bpf_map_lookup_elem(&RATE_LIMIT_BUCKET, &key);
	if (!state)
		return 1;

	now = bpf_ktime_get_ns();
	if (!state->last_ns) {
		state->last_ns = now;
		state->tokens = MAX_TOKENS;
	}

	delta = now - state->last_ns;
	if (delta >= NS_PER_TOKEN) {
		refill = delta / NS_PER_TOKEN;
		state->tokens += refill;
		if (state->tokens > MAX_TOKENS)
			state->tokens = MAX_TOKENS;
		state->last_ns = now;
	}

	if (!state->tokens) {
		record_rate_drop();
		return 0;
	}

	state->tokens -= 1;
	return 1;
}

static __always_inline void init_exec_event(struct exec_event_t *event)
{
	__builtin_memset(event, 0, sizeof(*event));
	event->event_type = EXEC_EVENT_TYPE_EXECVE;
	event->struct_size = EXEC_EVENT_STRUCT_SIZE;
	event->enforcement_action = ENFORCEMENT_ALLOWED;
}

static __always_inline void capture_pid_tgid(struct exec_event_t *event)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	event->pid = (__u32)(pid_tgid >> 32);
	event->tgid = (__u32)pid_tgid;
}

static __always_inline void capture_credentials(struct exec_event_t *event)
{
	__u64 uid_gid = bpf_get_current_uid_gid();
	__u64 euid_egid = bpf_get_current_euid_egid();

	event->uid = (__u32)uid_gid;
	event->gid = (__u32)(uid_gid >> 32);
	event->euid = (__u32)euid_egid;
}

static __always_inline void capture_comm(struct exec_event_t *event)
{
	long ret;

	ret = bpf_get_current_comm(event->comm, sizeof(event->comm));
	if (ret < 0)
		exec_mark_unknown(event->comm, sizeof(event->comm),
				  &event->capture_status, CAPTURE_COMM);
}

static __always_inline void capture_ppid(struct exec_event_t *event)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent;
	__u32 ppid = 0;

	if (!task) {
		event->capture_status |= CAPTURE_PPID;
		return;
	}

	if (bpf_core_read(&parent, sizeof(parent), &task->real_parent) < 0) {
		event->capture_status |= CAPTURE_PPID;
		return;
	}

	if (!parent) {
		event->capture_status |= CAPTURE_PPID;
		return;
	}

	if (bpf_core_read(&ppid, sizeof(ppid), &parent->tgid) < 0) {
		event->capture_status |= CAPTURE_PPID;
		return;
	}

	event->ppid = ppid;
}

static __always_inline void capture_namespace_id(struct exec_event_t *event)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct nsproxy *nsproxy;
	struct pid_namespace *pid_ns;
	unsigned int inum = 0;

	if (!task) {
		event->capture_status |= CAPTURE_NAMESPACE_ID;
		return;
	}

	if (bpf_core_read(&nsproxy, sizeof(nsproxy), &task->nsproxy) < 0 || !nsproxy) {
		event->capture_status |= CAPTURE_NAMESPACE_ID;
		return;
	}

	if (bpf_core_read(&pid_ns, sizeof(pid_ns), &nsproxy->pid_ns_for_children) < 0 ||
	    !pid_ns) {
		event->capture_status |= CAPTURE_NAMESPACE_ID;
		return;
	}

	if (bpf_core_read(&inum, sizeof(inum), &pid_ns->ns.inum) < 0) {
		event->capture_status |= CAPTURE_NAMESPACE_ID;
		return;
	}

	event->namespace_id = (__u64)inum;
}

static __always_inline void capture_container_id(struct exec_event_t *event)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct css_set *cgroups;
	struct cgroup_subsys_state *dfl_css;
	struct cgroup *cgrp;
	struct kernfs_node *kn;
	long ret;

	if (!task) {
		exec_mark_unknown(event->container_id, sizeof(event->container_id),
				  &event->capture_status, CAPTURE_CONTAINER_ID);
		return;
	}

	if (bpf_core_read(&cgroups, sizeof(cgroups), &task->cgroups) < 0 || !cgroups) {
		exec_mark_unknown(event->container_id, sizeof(event->container_id),
				  &event->capture_status, CAPTURE_CONTAINER_ID);
		return;
	}

	if (bpf_core_read(&dfl_css, sizeof(dfl_css), &cgroups->dfl) < 0 || !dfl_css) {
		exec_mark_unknown(event->container_id, sizeof(event->container_id),
				  &event->capture_status, CAPTURE_CONTAINER_ID);
		return;
	}

	if (bpf_core_read(&cgrp, sizeof(cgrp), &dfl_css->cgroup) < 0 || !cgrp) {
		exec_mark_unknown(event->container_id, sizeof(event->container_id),
				  &event->capture_status, CAPTURE_CONTAINER_ID);
		return;
	}

	if (bpf_core_read(&kn, sizeof(kn), &cgrp->kn) < 0 || !kn) {
		exec_mark_unknown(event->container_id, sizeof(event->container_id),
				  &event->capture_status, CAPTURE_CONTAINER_ID);
		return;
	}

	ret = bpf_probe_read_kernel_str(event->container_id,
					sizeof(event->container_id), kn->name);
	if (ret < 0)
		exec_mark_unknown(event->container_id, sizeof(event->container_id),
				  &event->capture_status, CAPTURE_CONTAINER_ID);
}

static __always_inline int capture_filename(struct exec_event_t *event,
					    const char __user *filename_ptr)
{
	long ret;

	if (!filename_ptr)
		return -1;

	__builtin_memset(event->filename, 0, sizeof(event->filename));
	ret = bpf_probe_read_user_str(event->filename, sizeof(event->filename),
				      filename_ptr);
	if (ret <= 0)
		return -1;

	return 0;
}

static __always_inline void capture_args_count(struct exec_event_t *event,
					       const char __user *const __user *argv)
{
	__u32 count = 0;
	const char __user *arg_ptr = 0;
	__u32 i;

	if (!argv) {
		event->capture_status |= CAPTURE_ARGS_COUNT;
		return;
	}

	for (i = 0; i < MAX_ARGS_PROBE; i++) {
		if (bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &argv[i]) < 0) {
			event->capture_status |= CAPTURE_ARGS_COUNT;
			break;
		}
		if (!arg_ptr)
			break;
		count++;
	}

	event->args_count = count;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int neuromesh_process_events(void *ctx)
{
	struct trace_event_raw_sys_enter *trace = ctx;
	struct exec_event_t *event;
	const char __user *filename_ptr;
	const char __user *const __user *argv_ptr;

	if (!rate_limit_allow())
		return 0;

	event = bpf_ringbuf_reserve(&PROCESS_EVENTS, sizeof(*event), 0);
	if (!event)
		return 0;

	init_exec_event(event);
	capture_pid_tgid(event);
	capture_credentials(event);
	capture_comm(event);
	capture_ppid(event);
	capture_namespace_id(event);
	capture_container_id(event);

	event->timestamp_ns = bpf_ktime_get_ns();
	if (!event->timestamp_ns)
		event->capture_status |= CAPTURE_TIMESTAMP;

	filename_ptr = (const char __user *)trace->args[0];
	argv_ptr = (const char __user *const __user *)trace->args[1];

	if (capture_filename(event, filename_ptr) < 0) {
		record_capture_failure();
		bpf_ringbuf_discard(event, 0);
		return 0;
	}

	capture_args_count(event, argv_ptr);

	/* Atomic schema publish — written last so userspace rejects torn records. */
	event->schema_version = EXEC_EVENT_SCHEMA_VERSION;
	bpf_ringbuf_submit(event, 0);
	return 0;
}
