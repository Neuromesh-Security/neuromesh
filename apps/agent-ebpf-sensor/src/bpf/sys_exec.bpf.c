// SPDX-License-Identifier: GPL-2.0
// Neuromesh process visibility — tracepoints syscalls/sys_enter_execve and
// syscalls/sys_enter_execveat.
//
// Enterprise ExecEvent v1 capture with CO-RE lineage, bounded argv probing,
// per-CPU token-bucket rate limiting (~500k events/sec), and fail-closed
// filename capture (discard + CAPTURE_FAILS on probe fault).
//
// Both tracepoints share emit_exec_event() so capture semantics cannot drift,
// and they share RLIMIT_BUCKET, so the aggregate admitted rate stays at the
// single ~500k/sec ceiling the PROCESS_EVENTS RingBuf was sized against
// (Issue #126). This file is telemetry only — enforcement lives exclusively in
// the Rust LSM program on bprm_check_security and is not touched here.

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
} RLIMIT_BUCKET SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} RLIMIT_DROPS SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} CAPTURE_FAILS SEC(".maps");

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
	record_counter(&RLIMIT_DROPS);
}

static __always_inline void record_capture_failure(void)
{
	record_counter(&CAPTURE_FAILS);
}

static __always_inline int rate_limit_allow(void)
{
	__u32 key = RATE_LIMIT_KEY;
	struct rate_limit_state *state;
	__u64 now;
	__u64 delta;
	__u64 refill;

	state = bpf_map_lookup_elem(&RLIMIT_BUCKET, &key);
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
	struct task_struct *task;
	struct cred *cred;
	kuid_t euid = {};
	__u64 uid_gid = bpf_get_current_uid_gid();

	event->uid = (__u32)uid_gid;
	event->gid = (__u32)(uid_gid >> 32);

	/* The kernel has no dedicated "get effective uid/gid" helper (checked
	 * against enum bpf_func_id, max id 211 — see bpf_helpers.h). Effective
	 * uid is read directly from task_struct->cred->euid via CO-RE, the
	 * same pattern used for ppid/namespace_id/container_id below. */
	task = (struct task_struct *)bpf_get_current_task();
	if (!task) {
		event->capture_status |= CAPTURE_EUID;
		return;
	}

	if (bpf_core_read(&cred, sizeof(cred), &task->cred) < 0 || !cred) {
		event->capture_status |= CAPTURE_EUID;
		return;
	}

	if (bpf_core_read(&euid, sizeof(euid), &cred->euid) < 0) {
		event->capture_status |= CAPTURE_EUID;
		return;
	}

	event->euid = euid.val;
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
	struct cgroup *cgrp;
	struct kernfs_node *kn;
	const char *name_ptr = (const char *)0;
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

	/* css_set->dfl_cgrp is the default-hierarchy cgroup directly — no
	 * cgroup_subsys_state indirection (see kernel/cgroup/cgroup.c). */
	if (bpf_core_read(&cgrp, sizeof(cgrp), &cgroups->dfl_cgrp) < 0 || !cgrp) {
		exec_mark_unknown(event->container_id, sizeof(event->container_id),
				  &event->capture_status, CAPTURE_CONTAINER_ID);
		return;
	}

	if (bpf_core_read(&kn, sizeof(kn), &cgrp->kn) < 0 || !kn) {
		exec_mark_unknown(event->container_id, sizeof(event->container_id),
				  &event->capture_status, CAPTURE_CONTAINER_ID);
		return;
	}

	/* `kn->name` must be fetched into a local variable via bpf_core_read
	 * first — `kn` is an untrusted/probed pointer (not a verifier-tracked
	 * PTR_TO_BTF_ID), so dereferencing `kn->name` directly (a plain load)
	 * is rejected by the verifier as an invalid memory access on an `inv`
	 * (scalar) register. Only the *address* `&kn->name` may be taken
	 * directly; the pointer *value* stored there must come back through a
	 * probe-read, exactly like every other field access in this chain. */
	if (bpf_core_read(&name_ptr, sizeof(name_ptr), &kn->name) < 0 || !name_ptr) {
		exec_mark_unknown(event->container_id, sizeof(event->container_id),
				  &event->capture_status, CAPTURE_CONTAINER_ID);
		return;
	}

	ret = bpf_probe_read_kernel_str(event->container_id,
					sizeof(event->container_id), name_ptr);
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

static __always_inline void capture_argv(struct exec_event_t *event,
					 const char __user *const __user *argv)
{
	/*
	 * Telemetry-only argv capture at sys_enter_execve (Issue #46).
	 *
	 * Source: syscall argv pointer (trace->args[1]) — NOT linux_binprm
	 * (this is the C sys_enter_execve path, not LSM).
	 *
	 * Pattern: bpf_probe_read_user for argv[i], then bpf_probe_read_user_str
	 * into a fixed slot event->argv[i][MAX_ARG_STR_LEN]. Variable offsets
	 * into a flat buffer are rejected by the verifier on the CI matrix
	 * (~5.15 WSL repro + ~6.8/~6.17-azure).
	 *
	 * Caps: MAX_ARGS_CAPTURE (8) × MAX_ARG_STR_LEN (32) = 256 bytes.
	 */
	__u32 count = 0;
	__u32 i;
	const char __user *arg_ptr = 0;
	long ret;

	__builtin_memset(event->argv, 0, sizeof(event->argv));
	event->argv_len = 0;
	event->argv_trunc_mask = 0;
	event->argv_flags = 0;
	event->args_count = 0;

	if (!argv) {
		event->capture_status |= CAPTURE_ARGS_COUNT | CAPTURE_ARGV;
		event->argv_flags |= ARGV_FLAG_PROBE_FAULT;
		return;
	}

#pragma clang loop unroll(full)
	for (i = 0; i < MAX_ARGS_CAPTURE; i++) {
		if (bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &argv[i]) < 0) {
			event->capture_status |= CAPTURE_ARGS_COUNT | CAPTURE_ARGV;
			event->argv_flags |= ARGV_FLAG_PROBE_FAULT;
			break;
		}
		if (!arg_ptr)
			break;

		ret = bpf_probe_read_user_str(event->argv[i], sizeof(event->argv[i]),
					      arg_ptr);
		if (ret <= 0) {
			event->capture_status |= CAPTURE_ARGV;
			event->argv_flags |= ARGV_FLAG_PROBE_FAULT;
			break;
		}
		/*
		 * bpf_probe_read_user_str returns `size` when the destination is
		 * filled (exact fit of size-1 chars + NUL, OR longer string
		 * truncated). Either way the analyst must not treat the slot as
		 * a proven complete argument — flag per-slot + event.
		 */
		if (ret >= (long)sizeof(event->argv[i])) {
			event->argv_trunc_mask |= (__u8)(1U << i);
			event->capture_status |= CAPTURE_ARGV;
		}
		count++;
	}

	event->args_count = count;
	event->argv_len = (__u16)count;

	/* More argv pointers remain beyond the slot cap → argc truncated. */
	if (count == MAX_ARGS_CAPTURE && argv) {
		const char __user *extra = 0;

		if (bpf_probe_read_user(&extra, sizeof(extra), &argv[MAX_ARGS_CAPTURE]) ==
			    0 &&
		    extra) {
			event->capture_status |= CAPTURE_ARGV;
			event->argv_flags |= ARGV_FLAG_ARGC_TRUNCATED;
		}
	}
}

/* Inlined byte-compare — `__builtin_memcmp` becomes an extern `memcmp` once
 * capture_envp is a bounded loop (not fully unrolled), which BPF cannot resolve. */
static __always_inline int nm_prefix_eq(const char *s, const char *p, const int n)
{
	int i;

#pragma clang loop unroll(full)
	for (i = 0; i < n; i++) {
		if (s[i] != p[i])
			return 0;
	}
	return 1;
}

static __always_inline void nm_copy32(char *dst, const char *src)
{
	int i;

#pragma clang loop unroll(full)
	for (i = 0; i < (int)MAX_ENV_STR_LEN; i++)
		dst[i] = src[i];
}

static __always_inline __u16 env_allowlist_bit(const char *s)
{
	if (nm_prefix_eq(s, "LD_PRELOAD=", 11))
		return 1U << 0;
	if (nm_prefix_eq(s, "LD_AUDIT=", 9))
		return 1U << 1;
	if (nm_prefix_eq(s, "LD_LIBRARY_PATH=", 16))
		return 1U << 2;
	if (nm_prefix_eq(s, "PATH=", 5))
		return 1U << 3;
	if (nm_prefix_eq(s, "NODE_OPTIONS=", 13))
		return 1U << 4;
	if (nm_prefix_eq(s, "PYTHONPATH=", 11))
		return 1U << 5;
	if (nm_prefix_eq(s, "BASH_ENV=", 9))
		return 1U << 6;
	if (nm_prefix_eq(s, "PROMPT_COMMAND=", 15))
		return 1U << 7;
	if (nm_prefix_eq(s, "SSLKEYLOGFILE=", 14))
		return 1U << 8;
	return 0;
}

static __always_inline void capture_envp(struct exec_event_t *event,
					 const char __user *const __user *envp)
{
	/*
	 * Telemetry-only env capture at sys_enter_execve / execveat (Issue #140).
	 *
	 * Same mechanism as capture_argv: syscall envp pointer
	 * (execve args[2] / execveat args[3]) — NOT mm_struct / BTF.
	 * Only compile-time allowlisted NAME=VALUE strings are copied into
	 * fixed 8×32 slots. All other names are omitted (not name-redacted).
	 *
	 * Verifier: argv can `#pragma unroll(full)` because dest is argv[i]
	 * with i folded to a constant. Envp cannot — it scans MAX_ENV_SCAN (32)
	 * pointers and packs hits into 8 slots, so a full unroll duplicates
	 * the 8-way store + 9 memcmps 32 times and blows the complexity budget.
	 * Keep the scan as a bounded loop (PATH_DENY-style); copy the already-
	 * probed 32 B stack buffer into a constant slot (no second user walk).
	 */
	__u32 i;
	__u32 hits = 0;
	__u16 seen = 0;
	__u32 scanned = 0;
	const char __user *env_ptr = 0;
	char probe[MAX_ENV_STR_LEN];
	long ret;

	__builtin_memset(event->env, 0, sizeof(event->env));
	event->env_len = 0;
	event->env_trunc_mask = 0;
	event->env_flags = 0;
	event->env_ptr_count = 0;
	event->env_header_pad = 0;

	if (!envp) {
		event->capture_status |= CAPTURE_ENV;
		event->env_flags |= ENV_FLAG_PROBE_FAULT;
		return;
	}

#pragma clang loop unroll(disable)
	for (i = 0; i < MAX_ENV_SCAN; i++) {
		if (bpf_probe_read_user(&env_ptr, sizeof(env_ptr), &envp[i]) < 0) {
			event->capture_status |= CAPTURE_ENV;
			event->env_flags |= ENV_FLAG_PROBE_FAULT;
			break;
		}
		if (!env_ptr)
			break;

		scanned++;
		ret = bpf_probe_read_user_str(probe, sizeof(probe), env_ptr);
		if (ret <= 0) {
			event->capture_status |= CAPTURE_ENV;
			event->env_flags |= ENV_FLAG_PROBE_FAULT;
			continue;
		}

		{
			__u16 bit = env_allowlist_bit(probe);

			if (!bit)
				continue;
			if (seen & bit)
				continue;
			if (hits >= MAX_ENV_CAPTURE) {
				event->env_flags |= ENV_FLAG_SLOTS_FULL;
				event->capture_status |= CAPTURE_ENV;
				continue;
			}

			/*
			 * Packed dest must be a literal index in each arm
			 * (argv pattern). Do not memcpy(event->env[hits]) —
			 * variable offset is rejected.
			 */
#define NM_PACK_ENV_SLOT(n)                                                        \
	if (hits == (n)) {                                                         \
		nm_copy32(event->env[(n)], probe);                                 \
		if (ret >= (long)sizeof(event->env[(n)])) {                        \
			event->env_trunc_mask |= (__u8)(1U << (n));                \
			event->capture_status |= CAPTURE_ENV;                      \
		}                                                                  \
	} else
			NM_PACK_ENV_SLOT(0)
			NM_PACK_ENV_SLOT(1)
			NM_PACK_ENV_SLOT(2)
			NM_PACK_ENV_SLOT(3)
			NM_PACK_ENV_SLOT(4)
			NM_PACK_ENV_SLOT(5)
			NM_PACK_ENV_SLOT(6)
			{
				nm_copy32(event->env[7], probe);
				if (ret >= (long)sizeof(event->env[7])) {
					event->env_trunc_mask |= (__u8)(1U << 7);
					event->capture_status |= CAPTURE_ENV;
				}
			}
#undef NM_PACK_ENV_SLOT
			seen |= bit;
			hits++;
		}
	}

	event->env_ptr_count = (__u16)scanned;
	event->env_len = (__u16)hits;

	if (scanned == MAX_ENV_SCAN && envp) {
		const char __user *extra = 0;

		if (bpf_probe_read_user(&extra, sizeof(extra), &envp[MAX_ENV_SCAN]) == 0 &&
		    extra) {
			event->env_flags |= ENV_FLAG_COUNT_TRUNCATED;
			event->capture_status |= CAPTURE_ENV;
		}
	}
}

/*
 * Shared emit path for every traced exec syscall variant.
 *
 * `syscall_flags` carries EXEC_FLAG_* for the calling tracepoint so the two
 * attaches cannot drift in capture behaviour: only the tracepoint argument
 * offsets differ between execve and execveat, never the captured fields.
 */
static __always_inline int emit_exec_event(const char __user *filename_ptr,
					   const char __user *const __user *argv_ptr,
					   const char __user *const __user *envp_ptr,
					   __u8 syscall_flags)
{
	struct exec_event_t *event;

	if (!rate_limit_allow())
		return 0;

	event = bpf_ringbuf_reserve(&PROCESS_EVENTS, sizeof(*event), 0);
	if (!event)
		return 0;

	init_exec_event(event);
	event->flags = syscall_flags;
	capture_pid_tgid(event);
	capture_credentials(event);
	capture_comm(event);
	capture_ppid(event);
	capture_namespace_id(event);
	capture_container_id(event);

	event->timestamp_ns = bpf_ktime_get_ns();
	if (!event->timestamp_ns)
		event->capture_status |= CAPTURE_TIMESTAMP;

	if (capture_filename(event, filename_ptr) < 0) {
		record_capture_failure();
		bpf_ringbuf_discard(event, 0);
		return 0;
	}

	/*
	 * AT_EMPTY_PATH (the fexecve(3) shape) passes an empty path string: the
	 * copy succeeds and yields "". Emit the UNKNOWN sentinel rather than a
	 * blank path so downstream rules never match on "". Scoped to execveat
	 * so the execve path stays byte-for-byte identical to before Issue #126.
	 */
	if ((syscall_flags & EXEC_FLAG_SYSCALL_EXECVEAT) && !event->filename[0]) {
		exec_mark_unknown(event->filename, sizeof(event->filename),
				  &event->capture_status, CAPTURE_FILENAME);
		event->flags |= EXEC_FLAG_PATH_FROM_FD;
	}

	capture_argv(event, argv_ptr);
	capture_envp(event, envp_ptr);

	/* Atomic schema publish — written last so userspace rejects torn records. */
	event->schema_version = EXEC_EVENT_SCHEMA_VERSION;
	bpf_ringbuf_submit(event, 0);
	return 0;
}

/* execve(const char *pathname, char *const argv[], char *const envp[]) */
SEC("tracepoint/syscalls/sys_enter_execve")
int nm_proc_events(void *ctx)
{
	struct trace_event_raw_sys_enter *trace = ctx;

	return emit_exec_event((const char __user *)trace->args[0],
			       (const char __user *const __user *)trace->args[1],
			       (const char __user *const __user *)trace->args[2], 0);
}

/*
 * execveat(int dfd, const char *pathname, char *const argv[],
 *          char *const envp[], int flags)
 *
 * Note the argument shift versus execve: dfd occupies args[0], so pathname is
 * args[1], argv is args[2], envp is args[3]. Also covers fexecve(3), which
 * glibc implements as execveat(fd, "", argv, envp, AT_EMPTY_PATH) — there is
 * no separate fexecve syscall to attach.
 */
SEC("tracepoint/syscalls/sys_enter_execveat")
int nm_execveat(void *ctx)
{
	struct trace_event_raw_sys_enter *trace = ctx;

	return emit_exec_event((const char __user *)trace->args[1],
			       (const char __user *const __user *)trace->args[2],
			       (const char __user *const __user *)trace->args[3],
			       EXEC_FLAG_SYSCALL_EXECVEAT);
}
