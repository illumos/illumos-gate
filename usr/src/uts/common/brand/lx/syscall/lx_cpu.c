/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <sys/cmn_err.h>
#include <sys/lx_impl.h>

/*
 * We support neither the second argument (NUMA node), nor the third (obsolete
 * pre-2.6.24 caching functionality which was ultimately broken).
 */
/* ARGSUSED1 */
long
lx_getcpu(unsigned int *cpu, uintptr_t p2, uintptr_t p3)
{
	unsigned int curcpu = curthread->t_cpu->cpu_id;

	if (copyout(&curcpu, cpu, sizeof (curcpu)) != 0)
		return (set_errno(EFAULT));

	return (0);
}
