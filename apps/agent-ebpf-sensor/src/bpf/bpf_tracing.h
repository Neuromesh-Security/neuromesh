/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#pragma once

#include "vmlinux.h"

#define PT_REGS_PARM1(x) ((void *)((x)->di))
#define PT_REGS_PARM2(x) ((void *)((x)->si))
#define PT_REGS_PARM3(x) ((void *)((x)->dx))
#define PT_REGS_PARM4(x) ((void *)((x)->cx))
#define PT_REGS_PARM5(x) ((void *)((x)->r8))
