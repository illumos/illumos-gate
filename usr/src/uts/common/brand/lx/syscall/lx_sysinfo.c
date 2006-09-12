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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <vm/anon.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/zone.h>
#include <sys/time.h>

struct lx_sysinfo {
	int32_t si_uptime;	/* Seconds since boot */
	uint32_t si_loads[3];	/* 1, 5, and 15 minute avg runq length */
	uint32_t si_totalram;	/* Total memory size */
	uint32_t si_freeram;	/* Available memory */
	uint32_t si_sharedram;	/* Shared memory */
	uint32_t si_bufferram;	/* Buffer memory */
	uint32_t si_totalswap;	/* Total swap space */
	uint32_t si_freeswap;	/* Avail swap space */
	uint16_t si_procs;	/* Process count */
	uint32_t si_totalhigh;	/* High memory size */
	uint32_t si_freehigh;	/* Avail high memory */
	uint32_t si_mem_unit;	/* Unit size of memory fields */
};

long
lx_sysinfo(struct lx_sysinfo *sip)
{
	struct lx_sysinfo si;
	hrtime_t birthtime;
	zone_t *zone = curthread->t_procp->p_zone;
	proc_t *init_proc;

	/*
	 * We don't record the time a zone was booted, so we use the
	 * birthtime of that zone's init process instead.
	 */
	mutex_enter(&pidlock);
	init_proc = prfind(zone->zone_proc_initpid);
	if (init_proc != NULL)
		birthtime = init_proc->p_mstart;
	else
		birthtime = p0.p_mstart;
	mutex_exit(&pidlock);
	si.si_uptime = (gethrtime() - birthtime) / NANOSEC;

	/*
	 * We scale down the load in avenrun to allow larger load averages
	 * to fit in 32 bits.  Linux doesn't, so we remove the scaling
	 * here.
	 */
	si.si_loads[0] = avenrun[0] << FSHIFT;
	si.si_loads[1] = avenrun[1] << FSHIFT;
	si.si_loads[2] = avenrun[2] << FSHIFT;

	/*
	 * In linux each thread looks like a process, so we conflate the
	 * two in this stat as well.
	 */
	si.si_procs = (int32_t)zone->zone_nlwps;

	/*
	 * If the maximum memory stat is less than 1^20 pages (i.e. 4GB),
	 * then we report the result in bytes.  Otherwise we use pages.
	 * Once we start supporting >1TB x86 systems, we'll need a third
	 * option.
	 */
	if (MAX(physmem, k_anoninfo.ani_max) < 1024 * 1024) {
		si.si_totalram = physmem * PAGESIZE;
		si.si_freeram = freemem * PAGESIZE;
		si.si_totalswap = k_anoninfo.ani_max * PAGESIZE;
		si.si_freeswap = k_anoninfo.ani_free * PAGESIZE;
		si.si_mem_unit = 1;
	} else {
		si.si_totalram = physmem;
		si.si_freeram = freemem;
		si.si_totalswap = k_anoninfo.ani_max;
		si.si_freeswap = k_anoninfo.ani_free;
		si.si_mem_unit = PAGESIZE;
	}
	si.si_bufferram = 0;
	si.si_sharedram = 0;

	/*
	 * These two stats refer to high physical memory.  If an
	 * application running in a Linux zone cares about this, then
	 * either it or we are broken.
	 */
	si.si_totalhigh = 0;
	si.si_freehigh = 0;

	if (copyout(&si, sip, sizeof (si)) != 0)
		return (set_errno(EFAULT));
	return (0);
}
