/* SPDX-License-Identifier: GPL-2.0 */
/* Shared ExecEvent v3 layout — must match neuromesh_common::ExecEvent byte-for-byte. */

#pragma once

#include "bpf_helpers.h"

#define EXEC_EVENT_SCHEMA_VERSION 3U
#define EXEC_EVENT_TYPE_EXECVE    1U
#define EXEC_EVENT_STRUCT_SIZE    932U

/*
 * Header `flags` bits — syscall-variant discriminator (Issue #126).
 *
 * `event_type` stays EXEC_EVENT_TYPE_EXECVE for every exec record: userspace
 * validation (`neuromesh_common::ExecEvent::is_valid`) hard-requires that value,
 * so introducing a second event_type would make execveat records fail decode and
 * be dropped silently. The variant is therefore a flag.
 */
#define EXEC_FLAG_SYSCALL_EXECVEAT (1U << 0)
/*
 * fexecve(3) is not a syscall: glibc implements it as
 * execveat(fd, "", argv, envp, AT_EMPTY_PATH). The syscall carries no path
 * string, so the filename copy succeeds but yields "". This bit marks that the
 * target was named by a file descriptor and the path is genuinely unresolvable
 * here, distinguishing it from a probe fault.
 */
#define EXEC_FLAG_PATH_FROM_FD     (1U << 1)

#define EXEC_COMM_LEN         16
#define EXEC_FILENAME_LEN     256
#define EXEC_CONTAINER_ID_LEN 64

#define ENFORCEMENT_ALLOWED 0U
#define ENFORCEMENT_BLOCKED 1U
#define ENFORCEMENT_UNKNOWN 2U

#define CAPTURE_PID          (1U << 0)
#define CAPTURE_PPID         (1U << 1)
#define CAPTURE_TGID         (1U << 2)
#define CAPTURE_UID          (1U << 3)
#define CAPTURE_EUID         (1U << 4)
#define CAPTURE_GID          (1U << 5)
#define CAPTURE_COMM         (1U << 6)
#define CAPTURE_FILENAME     (1U << 7)
#define CAPTURE_ARGS_COUNT   (1U << 8)
#define CAPTURE_CONTAINER_ID (1U << 9)
#define CAPTURE_NAMESPACE_ID (1U << 10)
#define CAPTURE_TIMESTAMP    (1U << 11)
#define CAPTURE_ARGV         (1U << 12)
#define CAPTURE_ENV          (1U << 13)

/*
 * Issue #46: verifier-safe argv capture at sys_enter_execve.
 * Fixed 8×32 slots (256 bytes total) — variable destination offsets into a
 * flat buffer fail the verifier (`R1 max value outside allowed memory range`).
 * Per-slot `bpf_probe_read_user_str` with a constant size is the standard
 * Tracee / Falco / aya-cookbook pattern.
 */
#define MAX_ARGS_CAPTURE  8U
#define MAX_ARG_STR_LEN   32U
#define MAX_ARGS_PROBE    MAX_ARGS_CAPTURE

/* argv_flags bits (Issue #46 truncation / fault signaling). */
#define ARGV_FLAG_ARGC_TRUNCATED (1U << 0)
#define ARGV_FLAG_PROBE_FAULT    (1U << 1)

/*
 * Issue #140: allowlisted env capture — same 8×32 slots as argv.
 * ENV_ALLOWLIST names (compile-time, must match neuromesh_common::ENV_VALUE_ALLOWLIST):
 * LD_PRELOAD LD_AUDIT LD_LIBRARY_PATH PATH NODE_OPTIONS PYTHONPATH BASH_ENV PROMPT_COMMAND SSLKEYLOGFILE
 */
#define MAX_ENV_CAPTURE  8U
#define MAX_ENV_STR_LEN  32U
#define MAX_ENV_SCAN     32U

#define ENV_FLAG_COUNT_TRUNCATED (1U << 0)
#define ENV_FLAG_PROBE_FAULT     (1U << 1)
#define ENV_FLAG_SLOTS_FULL      (1U << 2)

#define UNKNOWN_LITERAL "UNKNOWN"

struct exec_event_t {
	__u16 schema_version;
	__u8 event_type;
	__u8 flags;
	__u16 struct_size;
	__u16 header_reserved;
	__u8 header_pad[8];

	__u32 pid;
	__u32 ppid;
	__u32 tgid;
	__u32 uid;
	__u32 euid;
	__u32 gid;

	char comm[EXEC_COMM_LEN];
	char filename[EXEC_FILENAME_LEN];
	__u32 args_count;
	__u16 argv_len;
	/* Bit i set when slot i filled the 32-byte buffer (string may be truncated). */
	__u8 argv_trunc_mask;
	/* ARGV_FLAG_* — argc overflow / probe fault beyond per-slot mask. */
	__u8 argv_flags;
	char argv[MAX_ARGS_CAPTURE][MAX_ARG_STR_LEN];

	__u16 env_len;
	__u8 env_trunc_mask;
	__u8 env_flags;
	__u16 env_ptr_count;
	__u16 env_header_pad;
	char env[MAX_ENV_CAPTURE][MAX_ENV_STR_LEN];

	char container_id[EXEC_CONTAINER_ID_LEN];
	__u8 align_pad[4];
	__u64 namespace_id;
	__u64 timestamp_ns;

	__u8 enforcement_action;
	__u16 capture_status;
	__u8 status_reserved[5];
} __attribute__((packed));

_Static_assert(sizeof(struct exec_event_t) == EXEC_EVENT_STRUCT_SIZE,
	       "exec_event_t size drift — sync with neuromesh-common::ExecEvent");

static __always_inline void exec_mark_unknown(char *buf, __u32 size, __u16 *status,
					      __u16 bit)
{
	const char unknown[] = UNKNOWN_LITERAL;

	__builtin_memset(buf, 0, size);
	__builtin_memcpy(buf, unknown, sizeof(unknown) - 1);
	*status |= bit;
}
