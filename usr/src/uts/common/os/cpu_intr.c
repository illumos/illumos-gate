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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/var.h>
#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <sys/kstat.h>
#include <sys/uadmin.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/procset.h>
#include <sys/processor.h>
#include <sys/debug.h>
#include <sys/cyclic.h>
#include <sys/pool_pset.h>

/*
 * cpu_intr_on - determine whether the CPU is participating
 * in I/O interrupts.
 */
int
cpu_intr_on(cpu_t *cp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	return ((cp->cpu_flags & CPU_ENABLE) != 0);
}

/*
 * Return the next on-line CPU handling interrupts.
 */
cpu_t *
cpu_intr_next(cpu_t *cp)
{
	cpu_t	*c;

	ASSERT(MUTEX_HELD(&cpu_lock));

	c = cp->cpu_next_onln;
	while (c != cp) {
		if (cpu_intr_on(c)) {
			return (c);
		}
		c = c->cpu_next_onln;
	}
	return (NULL);
}

/*
 * cpu_intr_count - count how many CPUs are handling I/O interrupts.
 */
int
cpu_intr_count(cpu_t *cp)
{
	cpu_t	*c;
	int	count = 0;

	ASSERT(MUTEX_HELD(&cpu_lock));
	c = cp;
	do {
		if (cpu_intr_on(c)) {
			++count;
		}
	} while ((c = c->cpu_next) != cp);
	return (count);
}

/*
 * Enable I/O interrupts on this CPU, if they are disabled.
 */
void
cpu_intr_enable(cpu_t *cp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	if (!cpu_intr_on(cp)) {
		cpu_enable_intr(cp);
		cpu_set_state(cp);
	}
}

/*
 * cpu_intr_disable - redirect I/O interrupts targetted at this CPU.
 *
 * semantics: We check the count of CPUs that are accepting
 * interrupts, because it's stupid to take the last CPU out
 * of I/O interrupt participation. This also permits the
 * p_online syscall to fail gracefully in uniprocessor configurations
 * without having to perform any special platform-specific operations.
 */
int
cpu_intr_disable(cpu_t *cp)
{
	int	e = EBUSY;

	ASSERT(MUTEX_HELD(&cpu_lock));
	if ((cpu_intr_count(cp) > 1) && (cpu_intr_next(cp) != NULL)) {
		if (cpu_intr_on(cp)) {
			/*
			 * Juggle away cyclics, but don't fail if we don't
			 * manage to juggle all of them away; we want to allow
			 * CPU-bound cyclics to continue to fire on the
			 * sheltered CPU.
			 */
			(void) cyclic_juggle(cp);
			e = cpu_disable_intr(cp);
		}
	}
	if (e == 0)
		cpu_set_state(cp);
	return (e);
}
