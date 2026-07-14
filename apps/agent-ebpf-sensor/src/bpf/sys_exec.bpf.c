// SPDX-License-Identifier: GPL-2.0
// Neuromesh process visibility — tracepoint syscalls/sys_enter_execve.
//
// Verifier-safe skeleton with per-CPU token-bucket rate limiting (~500k events/sec).

#include "bpf_helpers.h"

char __license[] SEC("license") = "GPL";

#define COMM_LEN 16
#define FILENAME_LEN 128
#define RATE_LIMIT_KEY 0

/* 500k events/sec → one token every 2000 ns; burst matches one second at peak rate. */
#define NS_PER_TOKEN 2000ULL
#define MAX_TOKENS 500000ULL

struct process_event_t {
	__u32 pid;
	__u32 uid;
	__u32 ppid;
	char comm[COMM_LEN];
	char filename[FILENAME_LEN];
	__u64 ts;
};

struct rate_limit_state {
	__u64 last_ns;
	__u64 tokens;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
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

static __always_inline void record_rate_drop(void)
{
	__u32 key = RATE_LIMIT_KEY;
	__u64 *counter = bpf_map_lookup_elem(&RATE_LIMIT_DROPS, &key);

	if (!counter)
		return;

	*counter = *counter + 1;
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

SEC("tracepoint/syscalls/sys_enter_execve")
int neuromesh_process_events(void *ctx)
{
	struct process_event_t *event;
	__u64 pid_tgid;

	(void)ctx;

	if (!rate_limit_allow())
		return 0;

	event = bpf_ringbuf_reserve(&PROCESS_EVENTS, sizeof(*event), 0);
	if (!event)
		return 0;

	__builtin_memset(event, 0, sizeof(*event));

	pid_tgid = bpf_get_current_pid_tgid();
	event->pid = (__u32)(pid_tgid >> 32);

	bpf_ringbuf_submit(event, 0);
	return 0;
}
