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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FTRACE_H
#define	_SYS_FTRACE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Constants used by both asm and non-asm code.
 */

/*
 * Flags determining the state of tracing -
 *   both for the "ftrace_state" variable, and for the per-CPU variable
 *   "cpu[N]->cpu_ftrace_state".
 */
#define	FTRACE_READY	0x00000001
#define	FTRACE_ENABLED	0x00000002

#if !defined(_ASM)

#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <sys/types.h>

/*
 * The record of a single event.
 *
 * Should fit nicely into a standard cache line.
 * Here, the 32-bit version is 32 bytes, and the 64-bit version is 64 bytes.
 */
typedef struct ftrace_record {
	char		*ftr_event;
	kthread_t	*ftr_thread;
	uint64_t	ftr_tick;
	caddr_t		ftr_caller;
	ulong_t		ftr_data1;
	ulong_t		ftr_data2;
	ulong_t		ftr_data3;
#ifdef	_LP64
	ulong_t		__pad;
#endif
} ftrace_record_t;

/*
 * Default per-CPU event ring buffer size.
 */
#define	FTRACE_NENT 1024

#ifdef _KERNEL

/*
 * Tunable parameters in /etc/system.
 */
extern int ftrace_atboot;	/* Whether to start fast tracing on boot. */
extern int ftrace_nent;		/* Size of the per-CPU event ring buffer. */

extern int		ftrace_cpu_setup(cpu_setup_t, int, void *);
extern void		ftrace_init(void);
extern int		ftrace_start(void);
extern int		ftrace_stop(void);
extern void		ftrace_0(char *, caddr_t);
extern void		ftrace_1(char *, ulong_t, caddr_t);
extern void		ftrace_2(char *, ulong_t, ulong_t, caddr_t);
extern void		ftrace_3(char *, ulong_t, ulong_t, ulong_t, caddr_t);
extern void		ftrace_3_notick(char *, ulong_t, ulong_t, ulong_t,
    caddr_t);

typedef	uintptr_t	ftrace_icookie_t;
extern ftrace_icookie_t ftrace_interrupt_disable(void);
extern void ftrace_interrupt_enable(ftrace_icookie_t);
extern caddr_t caller(void);

#define	FTRACE_0(fmt)						\
	{							\
		if (CPU->cpu_ftrace.ftd_state & FTRACE_ENABLED)	\
			ftrace_0(fmt, caller());		\
	}
#define	FTRACE_1(fmt, d1) 					\
	{							\
		if (CPU->cpu_ftrace.ftd_state & FTRACE_ENABLED)	\
			ftrace_1(fmt, d1, caller());		\
	}
#define	FTRACE_2(fmt, d1, d2) 					\
	{							\
		if (CPU->cpu_ftrace.ftd_state & FTRACE_ENABLED)	\
			ftrace_2(fmt, d1, d2, caller());	\
	}
#define	FTRACE_3(fmt, d1, d2, d3) 				\
	{							\
		if (CPU->cpu_ftrace.ftd_state & FTRACE_ENABLED)	\
			ftrace_3(fmt, d1, d2, d3, caller());	\
	}
#define	FTRACE_START()	ftrace_start()
#define	FTRACE_STOP()	ftrace_stop()

#endif	/* _KERNEL */

#endif	/* !defined(_ASM) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FTRACE_H */
