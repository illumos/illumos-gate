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
 */

#ifndef	_SYS_CLOCK_TICK_H
#define	_SYS_CLOCK_TICK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/mutex.h>
#include <sys/cpuvar.h>
#include <sys/systm.h>
#include <sys/cyclic.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	CLOCK_TICK_NCPUS	32

/*
 * Per-CPU structure to facilitate multi-threaded tick accounting.
 *
 * ct_lock
 *	Mutex for the structure. Used to lock the structure to pass
 *	arguments to the tick processing softint handler.
 * ct_intr
 *	Tick processing softint handle. For parallelism, each CPU
 *	needs to have its own softint handle.
 * ct_lbolt
 *	Copy of the lbolt at the time of tick scheduling.
 * ct_pending
 *	Number of ticks to be processed by one invocation of the tick
 *	processing softint.
 * ct_start
 *	First CPU to do tick processing for.
 * ct_end
 *	Last CPU to do tick processing for.
 * ct_scan
 *	CPU to start the tick processing from. Rotated every tick.
 */
typedef struct clock_tick_cpu {
	kmutex_t		ct_lock;
	ulong_t			ct_intr;
	clock_t			ct_lbolt;
	int			ct_pending;
	int			ct_start;
	int			ct_end;
	int			ct_scan;
} clock_tick_cpu_t;

/*
 * Per-set structure to facilitate multi-threaded tick accounting.
 * clock_tick_lock protects this.
 *
 * ct_start
 *	First CPU to do tick processing for.
 * ct_end
 *	Last CPU to do tick processing for.
 * ct_scan
 *	CPU to start the tick processing from. Rotated every tick.
 */
typedef struct clock_tick_set {
	int			ct_start;
	int			ct_end;
	int			ct_scan;
} clock_tick_set_t;

#define	CLOCK_TICK_CPU_OFFLINE(cp)	\
	(((cp) != cpu_active) && ((cp)->cpu_next_onln == (cp)))

#define	CLOCK_TICK_XCALL_SAFE(cp)	\
		CPU_IN_SET(clock_tick_online_cpuset, cp->cpu_id)

#define	CLOCK_TICK_PROC_MAX		10

#ifdef	_KERNEL
#pragma weak		create_softint
extern ulong_t		create_softint(uint_t, uint_t (*)(caddr_t, caddr_t),
				caddr_t);
#pragma weak		invoke_softint
extern void		invoke_softint(processorid_t, ulong_t);
#pragma weak		sync_softint
extern void		sync_softint(cpuset_t);
extern void		clock_tick(kthread_t *, int);
extern void		membar_sync(void);

extern int		hires_tick;
#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_CLOCK_TICK_H */
