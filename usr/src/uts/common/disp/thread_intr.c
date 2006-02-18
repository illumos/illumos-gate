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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * FILE NOTICE BEGIN
 *
 * This file should not be modified.  If you wish to modify it or have it
 * modified, please contact Sun Microsystems at <LFI149367@-sun-.-com->
 * (without anti-spam dashes)
 *
 * FILE NOTICE END
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/cpuvar.h>
#include <sys/stack.h>
#include <vm/seg_kp.h>
#include <sys/proc.h>
#include <sys/pset.h>
#include <sys/sysmacros.h>

/*
 * Create and initialize an interrupt thread.
 */
static void
thread_create_intr(cpu_t *cp)
{
	kthread_t *tp;

	tp = thread_create(NULL, 0,
	    (void (*)())thread_create_intr, NULL, 0, &p0, TS_ONPROC, 0);

	/*
	 * Set the thread in the TS_FREE state.  The state will change
	 * to TS_ONPROC only while the interrupt is active.  Think of these
	 * as being on a private free list for the CPU.  Being TS_FREE keeps
	 * inactive interrupt threads out of debugger thread lists.
	 *
	 * We cannot call thread_create with TS_FREE because of the current
	 * checks there for ONPROC.  Fix this when thread_create takes flags.
	 */
	THREAD_FREEINTR(tp, cp);

	/*
	 * Nobody should ever reference the credentials of an interrupt
	 * thread so make it NULL to catch any such references.
	 */
	tp->t_cred = NULL;
	tp->t_flag |= T_INTR_THREAD;
	tp->t_cpu = cp;
	tp->t_bound_cpu = cp;
	tp->t_disp_queue = cp->cpu_disp;
	tp->t_affinitycnt = 1;
	tp->t_preempt = 1;

	/*
	 * Don't make a user-requested binding on this thread so that
	 * the processor can be offlined.
	 */
	tp->t_bind_cpu = PBIND_NONE;	/* no USER-requested binding */
	tp->t_bind_pset = PS_NONE;

#if defined(__i386) || defined(__amd64)
	tp->t_stk -= STACK_ALIGN;
	*(tp->t_stk) = 0;		/* terminate intr thread stack */
#endif

	/*
	 * Link onto CPU's interrupt pool.
	 */
	tp->t_link = cp->cpu_intr_thread;
	cp->cpu_intr_thread = tp;
}

/*
 * Allocate a given number of interrupt threads for a given CPU.
 * These threads will get freed by cpu_destroy_bound_threads()
 * when CPU gets unconfigured.
 */
void
cpu_intr_alloc(cpu_t *cp, int n)
{
	int i;

	for (i = 0; i < n; i++)
		thread_create_intr(cp);

	cp->cpu_intr_stack = (caddr_t)segkp_get(segkp, INTR_STACK_SIZE,
		KPD_HASREDZONE | KPD_NO_ANON | KPD_LOCKED) +
		INTR_STACK_SIZE - SA(MINFRAME);
}
