/* SPDX-License-Identifier: GPL-2.0 */
/* Shared ExecEvent v1 layout — must match neuromesh_common::ExecEvent byte-for-byte. */

#pragma once

#include "bpf_helpers.h"

#define EXEC_EVENT_SCHEMA_VERSION 1U
#define EXEC_EVENT_TYPE_EXECVE    1U
#define EXEC_EVENT_STRUCT_SIZE    408U

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

#define MAX_ARGS_PROBE 16U

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
