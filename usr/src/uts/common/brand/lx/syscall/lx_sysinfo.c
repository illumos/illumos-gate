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
 * Copyright 2016 Joyent, Inc.
 */

#include <vm/anon.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/zone.h>
#include <sys/time.h>

typedef struct lx_sysinfo {
	int64_t si_uptime;	/* Seconds since boot */
	uint64_t si_loads[3];	/* 1, 5, and 15 minute avg runq length */
	uint64_t si_totalram;	/* Total memory size */
	uint64_t si_freeram;	/* Available memory */
	uint64_t si_sharedram;	/* Shared memory */
	uint64_t si_bufferram;	/* Buffer memory */
	uint64_t si_totalswap;	/* Total swap space */
	uint64_t si_freeswap;	/* Avail swap space */
	uint16_t si_procs;	/* Process count */
	uint16_t si_pad;	/* Padding */
	uint64_t si_totalhigh;	/* High memory size */
	uint64_t si_freehigh;	/* Avail high memory */
	uint32_t si_mem_unit;	/* Unit size of memory fields */
} lx_sysinfo_t;

#if defined(_SYSCALL32_IMPL)
/*
 * 64-bit kernel view of the 32-bit usermode struct.
 */
#pragma pack(4)
typedef struct lx_sysinfo32 {
	int32_t si_uptime;	/* Seconds since boot */
	uint32_t si_loads[3];	/* 1, 5, and 15 minute avg runq length */
	uint32_t si_totalram;	/* Total memory size */
	uint32_t si_freeram;	/* Available memory */
	uint32_t si_sharedram;	/* Shared memory */
	uint32_t si_bufferram;	/* Buffer memory */
	uint32_t si_totalswap;	/* Total swap space */
	uint32_t si_freeswap;	/* Avail swap space */
	uint16_t si_procs;	/* Process count */
	uint16_t si_pad;	/* Padding */
	uint32_t si_totalhigh;	/* High memory size */
	uint32_t si_freehigh;	/* Avail high memory */
	uint32_t si_mem_unit;	/* Unit size of memory fields */
	char __si_pad[8];
} lx_sysinfo32_t;
#pragma pack()
#endif

extern pgcnt_t swapfs_minfree;

static void
lx_sysinfo_common(lx_sysinfo_t *si)
{
	zone_t *zone = curthread->t_procp->p_zone;
	uint64_t zphysmem, zfreemem, ztotswap, zfreeswap;

	si->si_uptime = gethrestime_sec() - zone->zone_boot_time;

	si->si_loads[0] = zone->zone_hp_avenrun[0];
	si->si_loads[1] = zone->zone_hp_avenrun[1];
	si->si_loads[2] = zone->zone_hp_avenrun[2];

	/*
	 * In linux each thread looks like a process, so we conflate the
	 * two in this stat as well.
	 */
	si->si_procs = (int32_t)zone->zone_nlwps;

	/*
	 * If memory or swap limits are set on the zone, use those, otherwise
	 * use the system values. physmem and freemem are in pages, but the
	 * zone values are in bytes. Likewise, ani_max and ani_free are in
	 * pages.
	 */
	if (zone->zone_phys_mem_ctl == UINT64_MAX) {
		zphysmem = physmem;
		zfreemem = freemem;
	} else {
		int64_t freemem;

		zphysmem = btop(zone->zone_phys_mem_ctl);
		freemem = zone->zone_phys_mem_ctl - zone->zone_phys_mem;
		if (freemem > 0) {
			zfreemem = btop(freemem);
		} else {
			zfreemem = 0;
		}
	}

	if (zone->zone_max_swap_ctl == UINT64_MAX) {
		ztotswap = k_anoninfo.ani_max;
		zfreeswap = k_anoninfo.ani_free;
	} else {
		/*
		 * See the comment in swapctl for a description of how free is
		 * calculated within a zone.
		 */
		rctl_qty_t used;
		spgcnt_t avail;
		uint64_t max;

		avail = MAX((spgcnt_t)(availrmem - swapfs_minfree), 0);
		max = k_anoninfo.ani_max + k_anoninfo.ani_mem_resv + avail;

		mutex_enter(&zone->zone_mem_lock);
		ztotswap = btop(zone->zone_max_swap_ctl);
		used = btop(zone->zone_max_swap);
		mutex_exit(&zone->zone_mem_lock);

		zfreeswap = MIN(ztotswap, max) - used;
	}

	/*
	 * If the maximum memory stat is less than 1^20 pages (i.e. 4GB),
	 * then we report the result in bytes.  Otherwise we use pages.
	 * Once we start supporting >1TB systems/zones, we'll need a third
	 * option.
	 */
	if (MAX(zphysmem, ztotswap) < 1024 * 1024) {
		si->si_totalram = ptob(zphysmem);
		si->si_freeram = ptob(zfreemem);
		si->si_totalswap = ptob(ztotswap);
		si->si_freeswap = ptob(zfreeswap);
		si->si_mem_unit = 1;
	} else {
		si->si_totalram = zphysmem;
		si->si_freeram = zfreemem;
		si->si_totalswap = ztotswap;
		si->si_freeswap = zfreeswap;
		si->si_mem_unit = PAGESIZE;
	}
	si->si_bufferram = 0;
	si->si_sharedram = 0;

	/*
	 * These two stats refer to high physical memory.  If an
	 * application running in a Linux zone cares about this, then
	 * either it or we are broken.
	 */
	si->si_totalhigh = 0;
	si->si_freehigh = 0;
}

long
lx_sysinfo64(caddr_t sip)
{
	lx_sysinfo_t si;

	bzero(&si, sizeof (si));
	lx_sysinfo_common(&si);

	if (copyout(&si, sip, sizeof (si)) != 0) {
		return (set_errno(EFAULT));
	}

	return (0);
}

#if defined(_SYSCALL32_IMPL)
long
lx_sysinfo32(caddr_t sip)
{
	lx_sysinfo_t si;
	lx_sysinfo32_t si32;
	int i;

	lx_sysinfo_common(&si);

	/*
	 * Convert the lx_sysinfo_t into the legacy 32-bit view:
	 */
	bzero(&si32, sizeof (si32));
	si32.si_uptime = si.si_uptime;

	for (i = 0; i < 3; i++) {
		if ((si.si_loads[i]) > 0x7fffffff)
			si32.si_loads[i] = 0x7fffffff;
		else
			si32.si_loads[i] = si.si_loads[i];
	}

	si32.si_procs = si.si_procs;
	si32.si_totalram = si.si_totalram;
	si32.si_freeram = si.si_freeram;
	si32.si_totalswap = si.si_totalswap;
	si32.si_freeswap = si.si_freeswap;
	si32.si_mem_unit = si.si_mem_unit;

	si32.si_bufferram = si.si_bufferram;
	si32.si_sharedram = si.si_sharedram;

	si32.si_totalhigh = si.si_totalhigh;
	si32.si_freehigh = si.si_freehigh;

	if (copyout(&si32, sip, sizeof (si32)) != 0) {
		return (set_errno(EFAULT));
	}

	return (0);
}
#endif
