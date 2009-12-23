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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <sys/machsystm.h>
#include <sys/systm.h>
#include <sys/promif.h>
#include <sys/xc_levels.h>
#include <sys/spl.h>
#include <sys/bitmap.h>

/*
 * Interrupt another CPU.
 * 	This is useful to make the other CPU go through a trap so that
 *	it recognizes an address space trap (AST) for preempting a thread.
 *
 *	It is possible to be preempted here and be resumed on the CPU
 *	being poked, so it isn't an error to poke the current CPU.
 *	We could check this and still get preempted after the check, so
 *	we don't bother.
 */
void
poke_cpu(int cpun)
{
	if (panicstr)
		return;
	/*
	 * We don't need to receive an ACK from the CPU being poked,
	 * so just send out a directed interrupt.
	 */
	send_dirint(cpun, XC_CPUPOKE_PIL);
}

/*
 * Call a function on a target CPU
 */
void
cpu_call(cpu_t *cp, cpu_call_func_t func, uintptr_t arg1, uintptr_t arg2)
{
	cpuset_t set;

	if (panicstr)
		return;

	/*
	 * Prevent CPU from going off-line
	 */
	kpreempt_disable();

	/*
	 * If we are on the target CPU, call the function directly, but raise
	 * the PIL to XC_PIL.
	 * This guarantees that functions called via cpu_call() can not ever
	 * interrupt each other.
	 */
	if (CPU == cp) {
		int save_spl = splr(ipltospl(XC_HI_PIL));

		(*func)(arg1, arg2);
		splx(save_spl);
	} else {
		CPUSET_ONLY(set, cp->cpu_id);
		xc_call((xc_arg_t)arg1, (xc_arg_t)arg2, 0, CPUSET2BV(set),
		    (xc_func_t)func);
	}
	kpreempt_enable();
}
