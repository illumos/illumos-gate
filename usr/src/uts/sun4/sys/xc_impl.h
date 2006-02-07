/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_XC_IMPL_H
#define	_SYS_XC_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _ASM

#include <sys/note.h>
#include <sys/cpu_module.h>
#include <sys/panic.h>		/* for panic_quiesce */

extern cpuset_t cpu_ready_set;	/* cpus ready for x-call */
extern void send_self_xcall(struct cpu *, uint64_t, uint64_t, xcfunc_t *);
extern uint_t xc_loop(void);
extern uint_t xc_serv(void);
extern void xc_stop(struct regs *);
#ifdef TRAPTRACE
extern void xc_trace(uint_t, cpuset_t *, xcfunc_t *, uint64_t, uint64_t);
#endif /* TRAPTRACE */
extern uint64_t xc_func_time_limit;

extern uint_t sendmondo_in_recover;

/*
 * Lightweight XTrap Sync
 */
#ifdef sun4v
#define	XT_SYNC_ONE(cpuid)				\
{							\
	cpuset_t set;					\
	CPUSET_ONLY(set, cpuid);			\
	xt_sync(set);					\
}

#define	XT_SYNC_SOME(cpuset)				\
{							\
	xt_sync(cpuset);				\
}

#else /* sun4v */

#define	XT_SYNC_ONE(cpuid)				\
{							\
	init_mondo((xcfunc_t *)xt_sync_tl1, 0, 0);	\
	send_one_mondo(cpuid);				\
}

#define	XT_SYNC_SOME(cpuset)				\
{							\
	init_mondo((xcfunc_t *)xt_sync_tl1, 0, 0);	\
	send_mondo_set(cpuset);				\
}

#endif /* sun4v */

/*
 * Protect the dispatching of the mondo vector
 */

#define	XC_SPL_ENTER(cpuid, opl)					\
{									\
	opl = splr(XCALL_PIL);						\
	cpuid = CPU->cpu_id;						\
	if (xc_spl_enter[cpuid] && !panic_quiesce)			\
		cmn_err(CE_PANIC, "XC SPL ENTER already entered (0x%x)",\
		cpuid);							\
	xc_spl_enter[cpuid] = 1;					\
}

#define	XC_SPL_EXIT(cpuid, opl)				\
{							\
	ASSERT(xc_spl_enter[cpuid] != 0);		\
	xc_spl_enter[cpuid] = 0;			\
	splx(opl);					\
}

/*
 * set up a x-call request
 */
#define	XC_SETUP(cpuid, func, arg1, arg2)		\
{							\
	xc_mbox[cpuid].xc_func = func;			\
	xc_mbox[cpuid].xc_arg1 = arg1;			\
	xc_mbox[cpuid].xc_arg2 = arg2;			\
	xc_mbox[cpuid].xc_state = XC_DOIT;		\
}

/*
 * set up x-call requests to the cpuset
 */
#define	SEND_MBOX_ONLY(xc_cpuset, func, arg1, arg2, lcx, state)		\
{									\
	int pix;							\
	cpuset_t  tmpset = xc_cpuset;					\
	for (pix = 0; pix < NCPU; pix++) {				\
		if (CPU_IN_SET(tmpset, pix)) {				\
			ASSERT(MUTEX_HELD(&xc_sys_mutex));		\
			ASSERT(CPU_IN_SET(xc_mbox[lcx].xc_cpuset, pix));\
			ASSERT(xc_mbox[pix].xc_state == state);		\
			XC_SETUP(pix, func, arg1, arg2);		\
			membar_stld();					\
			CPUSET_DEL(tmpset, pix);			\
			CPU_STATS_ADDQ(CPU, sys, xcalls, 1);		\
			if (CPUSET_ISNULL(tmpset))			\
				break;					\
		}							\
	}								\
}

/*
 * set up and notify a x-call request to the cpuset
 */
#define	SEND_MBOX_MONDO(xc_cpuset, func, arg1, arg2, state)	\
{								\
	int pix;						\
	cpuset_t  tmpset = xc_cpuset;				\
	for (pix = 0; pix < NCPU; pix++) {			\
		if (CPU_IN_SET(tmpset, pix)) {			\
			ASSERT(xc_mbox[pix].xc_state == state);	\
			XC_SETUP(pix, func, arg1, arg2);	\
			CPUSET_DEL(tmpset, pix);		\
			if (CPUSET_ISNULL(tmpset))		\
				break;				\
		}						\
	}							\
	membar_stld();						\
	send_mondo_set(xc_cpuset);				\
}

/*
 * set up and notify a x-call request, signalling xc_cpuset
 * cpus to enter xc_loop()
 */
#define	SEND_MBOX_MONDO_XC_ENTER(xc_cpuset)			\
{								\
	int pix;						\
	cpuset_t  tmpset = xc_cpuset;				\
	for (pix = 0; pix < NCPU; pix++) {			\
		if (CPU_IN_SET(tmpset, pix)) {			\
			ASSERT(xc_mbox[pix].xc_state ==		\
			    XC_IDLE);				\
			xc_mbox[pix].xc_state = XC_ENTER;	\
			CPUSET_DEL(tmpset, pix);		\
			if (CPUSET_ISNULL(tmpset)) {		\
				break;				\
			}					\
		}						\
	}							\
	send_mondo_set(xc_cpuset);				\
}

/*
 * wait x-call requests to be completed
 */
#define	WAIT_MBOX_DONE(xc_cpuset, lcx, state, sync)			\
{									\
	int pix;							\
	uint64_t loop_cnt = 0;						\
	cpuset_t tmpset;						\
	cpuset_t  recv_cpuset;						\
	int first_time = 1;						\
	CPUSET_ZERO(recv_cpuset);					\
	while (!CPUSET_ISEQUAL(recv_cpuset, xc_cpuset)) {		\
		tmpset = xc_cpuset;					\
		for (pix = 0; pix < NCPU; pix++) {			\
			if (CPU_IN_SET(tmpset, pix)) {			\
				if (xc_mbox[pix].xc_state == state) {	\
					CPUSET_ADD(recv_cpuset, pix);	\
				}					\
			}						\
			CPUSET_DEL(tmpset, pix);			\
			if (CPUSET_ISNULL(tmpset))			\
				break;					\
		}							\
		if (loop_cnt++ > xc_func_time_limit) {			\
			if (sendmondo_in_recover) {			\
				drv_usecwait(1);			\
				loop_cnt = 0;				\
				continue;				\
			}						\
			_NOTE(CONSTANTCONDITION)			\
			if (sync && first_time) {			\
				XT_SYNC_SOME(xc_cpuset);		\
				first_time = 0;				\
				loop_cnt = 0;				\
				continue;				\
			}						\
			panic("WAIT_MBOX_DONE() timeout, "		\
				"recv_cpuset 0x%lx, xc cpuset 0x%lx ",	\
				*(ulong_t *)&recv_cpuset,		\
				*(ulong_t *)&xc_cpuset);		\
		}							\
	}								\
}

/*
 * xc_state flags
 */
enum xc_states {
	XC_IDLE = 0,	/* not in the xc_loop(); set by xc_loop */
	XC_ENTER,	/* entering xc_loop(); set by xc_attention */
	XC_WAIT,	/* entered xc_loop(); set by xc_loop */
	XC_DOIT,	/* xcall request; set by xc_one, xc_some, or xc_all */
	XC_EXIT		/* exiting xc_loop(); set by xc_dismissed */
};

/*
 * user provided handlers must be pc aligned
 */
#define	PC_ALIGN 4

#ifdef TRAPTRACE
#define	XC_TRACE(type, cpus, func, arg1, arg2) \
		xc_trace((type), (cpus), (func), (arg1), (arg2))
#else /* !TRAPTRACE */
#define	XC_TRACE(type, cpus, func, arg1, arg2)
#endif /* TRAPTRACE */

#if defined(DEBUG) || defined(TRAPTRACE)
/*
 * get some statistics when xc/xt routines are called
 */

#define	XC_STAT_INC(a)	(a)++;
#define	XC_CPUID	0

#define	XT_ONE_SELF	1
#define	XT_ONE_OTHER	2
#define	XT_SOME_SELF	3
#define	XT_SOME_OTHER	4
#define	XT_ALL_SELF	5
#define	XT_ALL_OTHER	6
#define	XC_ONE_SELF	7
#define	XC_ONE_OTHER	8
#define	XC_ONE_OTHER_H	9
#define	XC_SOME_SELF	10
#define	XC_SOME_OTHER	11
#define	XC_SOME_OTHER_H	12
#define	XC_ALL_SELF	13
#define	XC_ALL_OTHER	14
#define	XC_ALL_OTHER_H	15
#define	XC_ATTENTION	16
#define	XC_DISMISSED	17
#define	XC_LOOP_ENTER	18
#define	XC_LOOP_DOIT	19
#define	XC_LOOP_EXIT	20

extern	uint_t x_dstat[NCPU][XC_LOOP_EXIT+1];
extern	uint_t x_rstat[NCPU][4];
#define	XC_LOOP		1
#define	XC_SERV		2

#define	XC_STAT_INIT(cpuid) 				\
{							\
	x_dstat[cpuid][XC_CPUID] = 0xffffff00 | cpuid;	\
	x_rstat[cpuid][XC_CPUID] = 0xffffff00 | cpuid;	\
}

#else /* DEBUG || TRAPTRACE */

#define	XC_STAT_INIT(cpuid)
#define	XC_STAT_INC(a)
#define	XC_ATTENTION_CPUSET(x)
#define	XC_DISMISSED_CPUSET(x)

#endif /* DEBUG || TRAPTRACE */

#endif	/* !_ASM */

/*
 * Maximum delay in milliseconds to wait for send_mondo to complete
 */
#define	XC_SEND_MONDO_MSEC	1000

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_XC_IMPL_H */
