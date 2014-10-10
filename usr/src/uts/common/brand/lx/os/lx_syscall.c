/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/thread.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/proc.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/model.h>
#include <sys/brand.h>
#include <sys/machbrand.h>
#include <sys/lx_syscalls.h>
#include <sys/lx_brand.h>
#include <sys/lx_impl.h>

/*
 * Some system calls return either a 32-bit or a 64-bit value, depending
 * on the datamodel.
 */
#ifdef	_LP64
#define	V_RVAL	SE_64RVAL
#else
#define	V_RVAL	SE_32RVAL1
#endif

/*
 * Define system calls that return a native 'long' quantity i.e. a 32-bit
 * or 64-bit integer - depending on how the kernel is itself compiled
 * e.g. read(2) returns 'ssize_t' in the kernel and in userland.
 */
#define	LX_CL(name, call, narg)      \
	{ V_RVAL, (name), (llfcn_t)(call), (narg) }

/*
 * Returns a 32 bit quantity regardless of datamodel
 */
#define	LX_CI(name, call, narg)      \
	{ SE_32RVAL1, (name), (llfcn_t)(call), (narg) }

extern longlong_t lx_nosys(void);
#define	LX_NOSYS(name)			\
	{SE_64RVAL, (name), (llfcn_t)lx_nosys, 0}

typedef int64_t (*llfcn_t)();

/*
 * In-Kernel Emulation table
 * The entries in this table are NOT indexed by either of the Linux syscall
 * numbers (32-bit or 64-bit). Instead, the entries are laid out linearly
 * with the LX_EMUL_* defines uses to lookup the correct entry.
 */
typedef struct lx_ike {
	int	sy_flags;
	char	*sy_name;
	llfcn_t	sy_callc;
	char	sy_narg;
} lx_ike_t;

static lx_ike_t lx_ike_ent[] =
{
	LX_NOSYS("lx_nosys"),					/* 0 */
	LX_CL("getpid",			lx_getpid,		0), /* 1 */
	LX_CL("kill",			lx_kill,		2),
	LX_CL("pipe",			lx_pipe,		1),
	LX_CL("brk",			lx_brk,			1),
	LX_CL("getppid",		lx_getppid,		0),
	LX_CL("sysinfo",		lx_sysinfo,		1),
	LX_CL("clone",			lx_clone,		5),
	LX_CL("modify_ldt",		lx_modify_ldt,		3),
	LX_CL("sched_setparam",		lx_sched_setparam,	2),
	LX_CL("sched_getparam",		lx_sched_getparam,	2), /* 10 */
	LX_CL("sched_rr_get_interval",	lx_sched_rr_get_interval, 2),
	LX_CL("setresuid16",		lx_setresuid16,		3),
	LX_CL("setresgid16",		lx_setresgid16,		3),
	LX_CL("rt_sigqueueinfo",	lx_rt_sigqueueinfo,	3),
	LX_CL("setgroups",		lx_setgroups,		2),
	LX_CL("setresuid",		lx_setresuid,		3),
	LX_CL("setresgid",		lx_setresgid,		3),
	LX_CL("gettid",			lx_gettid,		0),
	LX_CL("tkill",			lx_tkill,		2),
	LX_CL("futex",			lx_futex,		6), /* 20 */
	LX_CL("set_thread_area",	lx_set_thread_area,	1),
	LX_CL("get_thread_area",	lx_get_thread_area,	1),
	LX_CL("set_tid_address",	lx_set_tid_address,	1),
	LX_CL("pipe2",			lx_pipe2,		2),
	LX_CL("rt_tgsigqueueinfo",	lx_rt_tgsigqueueinfo,	4),
	LX_CL("arch_prctl",		lx_arch_prctl,		2),
	LX_CL("tgkill",			lx_tgkill,		3),
};

int64_t
lx_emulate_syscall(int num, uintptr_t arg1, uintptr_t arg2,
    uintptr_t arg3, uintptr_t arg4, uintptr_t arg5, uintptr_t arg6)
{
	lx_ike_t *jsp;
	int64_t rval;

	rval = (int64_t)0;

	jsp = &(lx_ike_ent[num]);

	switch (jsp->sy_narg) {
	case 0: {
		lx_print("--> %s()\n", jsp->sy_name);
		rval = (int64_t)jsp->sy_callc();
		break;
	}
	case 1: {
		lx_print("--> %s(0x%lx)\n", jsp->sy_name, arg1);
		rval = (int64_t)jsp->sy_callc(arg1);
		break;
	}
	case 2: {
		lx_print("--> %s(0x%lx, 0x%lx)\n", jsp->sy_name, arg1, arg2);
		rval = (int64_t)jsp->sy_callc(arg1, arg2);
		break;
	}
	case 3: {
		lx_print("--> %s(0x%lx, 0x%lx, 0x%lx)\n",
		    jsp->sy_name, arg1, arg2, arg3);
		rval = (int64_t)jsp->sy_callc(arg1, arg2, arg3);
		break;
	}
	case 4: {
		lx_print("--> %s(0x%lx, 0x%lx, 0x%lx, 0x%lx)\n",
		    jsp->sy_name, arg1, arg2, arg3, arg4);
		rval = (int64_t)jsp->sy_callc(arg1, arg2, arg3, arg4);
		break;
	}
	case 5: {
		lx_print("--> %s(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)\n",
		    jsp->sy_name, arg1, arg2, arg3, arg4, arg5);
		rval = (int64_t)jsp->sy_callc(arg1, arg2, arg3, arg4, arg5);
		break;
	}
	case 6: {
		lx_print("--> %s(0x%lx, 0x%lx, 0x%lx, 0x%lx,"
		    " 0x%lx, 0x%lx)\n",
		    jsp->sy_name, arg1, arg2, arg3, arg4, arg5, arg6);
		rval = (int64_t)jsp->sy_callc(arg1, arg2, arg3, arg4, arg5,
		    arg6);
		break;
	}
	default:
		panic("Invalid IKE entry: #%d at 0x%p\n", num, (void *)jsp);
	}
	lx_print("----------> return  (0x%llx)\n", (long long)rval);
	return (rval);
}
