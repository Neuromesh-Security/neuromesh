/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#pragma once

#ifndef __BPF_TRACING_H__
#define __BPF_TRACING_H__

struct pt_regs;

#if defined(__x86_64__) && !defined(__TARGET_ARCH_x86_64)
#define __TARGET_ARCH_x86_64 1
#endif

#if defined(__TARGET_ARCH_x86_64)
#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_PARM6(x) ((x)->r9)
#endif

#if defined(__TARGET_ARCH_x86)
#define PT_REGS_PARM1(x) ((x)->ax)
#define PT_REGS_PARM2(x) ((x)->dx)
#define PT_REGS_PARM3(x) ((x)->cx)
#endif

#endif /* __BPF_TRACING_H__ */
