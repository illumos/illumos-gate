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
#include <sys/iommutsb.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/bootconf.h>
#include <sys/mutex.h>
#include <sys/platform_module.h>
#include <sys/cmn_err.h>

/*
 * The interfaces provided by this file will eventually no longer
 * be required once a physically contiguous memory allocator
 * is available.
 */

/*
 *  The TSB size and consequently the DVMA range is appropriated proportional
 *  to the physical memory size.
 *
 *     phys_mem_size	   iommu TSB size	DVMA size
 *	    <= 32MB		 64KB		 64MB
 *	    <= 128MB		256KB		256MB
 *	    <= 512MB		512KB		512MB
 *	     > 512MB		  1MB		  1GB
 *
 *  NOTE: The original Solaris 8 FCS allocations must be used with
 *        32-bit kernels.
 *
 */
static uint_t
resolve_tsb_size(pgcnt_t phys_mem_size)
{
	if (phys_mem_size <= 0x1000)
		return (0x10000);
	else if (phys_mem_size <= 0x4000)
		return (0x40000);
	else if (phys_mem_size <= 0x10000)
		return (0x80000);
	else
		return (0x100000);
}

/* TSB size must be a power of 2 between the minimum and the maximum. */
#define	MIN_TSB_BYTES	0x2000
#define	MAX_TSB_BYTES	0x100000

/*
 * Use boot to allocate the physically contiguous memory needed for the
 * IOMMU's TSB arrays until there is an interface for dynamically
 * allocated, physically contiguous memory.
 * The number IOMMUs at boot, niommu_tsbs, is set as a side effect
 * of map_wellknown_devices(). The number of TSBs allocated is
 * at least niommu_tsbs. On platforms supporting Dynamic Reconfiguration
 * the platmod routine set_platform_tsb_spares() returns the
 * maximum total number of TSBs expected. The final number of TSBs
 * allocated is set in iommu_tsb_num.
 *
 * WARNING - since this routine uses boot to allocate memory, it MUST
 * be called before the kernel takes over memory allocation from boot.
 */
#define	MAX_IOMMU_PER_AGENT	2
#define	MAX_TSB_ALLOC		(MAX_UPA * MAX_IOMMU_PER_AGENT)

static kmutex_t iommu_tsb_avail_lock;
static uint16_t iommu_tsb_avail[MAX_TSB_ALLOC];
#define	IOMMU_TSB_INUSE		0x8000u
static uint_t iommu_tsb_num;
#ifdef DEBUG
static uint_t iommu_tsb_nfree;
#endif /* DEBUG */

static caddr_t iommu_tsb_base;
static uint_t iommu_tsb_size;

uint_t niommu_tsbs;

/*
 * The following variables can be patched to override the auto-selection
 * of dvma space based on the amount of installed physical memory.
 * Not settable via /etc/system as it is read after iommu_tsb_init()
 * is called.
 */
uint_t iommu_tsb_size_min = MIN_TSB_BYTES;
uint_t iommu_tsb_size_max = MAX_TSB_BYTES;

caddr_t
iommu_tsb_init(caddr_t alloc_base)
{
	size_t total_size;
	caddr_t base = (caddr_t)roundup((uintptr_t)alloc_base, MMU_PAGESIZE);
	uint_t tsb_min, tsb_max;
	uint_t tsb_size;
	uint_t ntsbs;

	/*
	 * determine the amount of physical memory required for the TSB arrays
	 *
	 * assumes niommu_tsbs has already been initialized, i.e.
	 * map_wellknown_devices()
	 *
	 * TSB space is allocated proportional to memory size (see
	 * resolve_tsb_size) but later constained by the limit obtained
	 * from get_dvma_property_limit in the nexus attach.
	 */
	tsb_size = resolve_tsb_size(physinstalled);

	tsb_min = MAX(iommu_tsb_size_min, MIN_TSB_BYTES);
	tsb_max = MIN(iommu_tsb_size_max, MAX_TSB_BYTES);

	if (tsb_min <= tsb_max) {
		uint_t sz;

		/* Ensure that min and max are powers of two. */
		/* guaranteed min and max are both between MIN/MAX_TSB_BYTES */
		for (sz = MAX_TSB_BYTES; !(sz & tsb_min); sz >>= 1)
			/* empty */;
		tsb_min = sz;
		for (sz = MAX_TSB_BYTES; !(sz & tsb_max); sz >>= 1)
			/* empty */;
		tsb_max = sz;

		/* guaranteed min still <= max */
		tsb_size = MIN(tsb_size, tsb_max);
		tsb_size = MAX(tsb_size, tsb_min);
	} else
		cmn_err(CE_WARN,
		    "iommutsb: bad iommu_tsb_size_min/max value pair");

	iommu_tsb_size = tsb_size;

	if (&set_platform_tsb_spares)
		ntsbs = set_platform_tsb_spares();
	else
		ntsbs = 0;
	ntsbs = MAX(ntsbs, niommu_tsbs);
	ntsbs = MIN(ntsbs, MAX_TSB_ALLOC);

	total_size = ntsbs * tsb_size;

	if (total_size == 0)
		return (alloc_base);

	/*
	 * allocate the physical memory for the TSB arrays
	 */
	if ((iommu_tsb_base = (caddr_t)BOP_ALLOC(bootops, base,
	    total_size, MMU_PAGESIZE)) == NULL)
		cmn_err(CE_PANIC, "Cannot allocate IOMMU TSB arrays");
	ASSERT(iommu_tsb_base == base);

	iommu_tsb_num = ntsbs;
#ifdef DEBUG
	iommu_tsb_nfree = iommu_tsb_num;
#endif /* DEBUG */

	return (base + total_size);
}

/*
 * External allocation interface to the nexus drivers (sbus, pci).
 * As an aid to debugging, the upaid or portid is recorded against
 * an allocation.
 */
uint16_t
iommu_tsb_alloc(uint16_t id)
{
	uint16_t tsbc;
	uint_t i;

	tsbc = IOMMU_TSB_COOKIE_NONE;
	mutex_enter(&iommu_tsb_avail_lock);
	for (i = 0; i < iommu_tsb_num; i++) {
		if (iommu_tsb_avail[i] == 0) {
			iommu_tsb_avail[i] = IOMMU_TSB_INUSE | id;
			tsbc = (uint16_t)i;
#ifdef DEBUG
			ASSERT(iommu_tsb_nfree != 0);
			iommu_tsb_nfree--;
#endif /* DEBUG */
			break;
		}
	}
	mutex_exit(&iommu_tsb_avail_lock);
	return (tsbc);
}

void
iommu_tsb_free(uint16_t tsbc)
{
	ASSERT(tsbc != IOMMU_TSB_COOKIE_NONE);
	ASSERT(tsbc < iommu_tsb_num);
	mutex_enter(&iommu_tsb_avail_lock);
	if (iommu_tsb_avail[tsbc] == 0) {
		cmn_err(CE_PANIC, "iommu_tsb_free(%d): tsb not in use", tsbc);
	}
	iommu_tsb_avail[tsbc] = 0;
#ifdef DEBUG
	ASSERT(iommu_tsb_nfree < iommu_tsb_num);
	iommu_tsb_nfree++;
#endif /* DEBUG */
	mutex_exit(&iommu_tsb_avail_lock);
}

/*ARGSUSED*/
uint_t
iommu_tsb_cookie_to_size(uint16_t tsbc)
{
	ASSERT(tsbc != IOMMU_TSB_COOKIE_NONE);
	ASSERT(tsbc < iommu_tsb_num);
	ASSERT(iommu_tsb_avail[tsbc] != 0);
	return (iommu_tsb_size);
}

uint64_t *
iommu_tsb_cookie_to_va(uint16_t tsbc)
{
	ASSERT(tsbc != IOMMU_TSB_COOKIE_NONE);
	ASSERT(tsbc < iommu_tsb_num);
	ASSERT(iommu_tsb_avail[tsbc] != 0);
	return ((uint64_t *)(iommu_tsb_base + (tsbc * iommu_tsb_size)));
}
