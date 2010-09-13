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

#include <sys/types.h>
#include <sys/machsystm.h>
#include <sys/machparam.h>
#include <sys/cmn_err.h>
#include <sys/cpuvar.h>
#include <sys/note.h>
#include <sys/hypervisor_api.h>
#include <sys/lpad.h>

typedef struct {
	uint64_t	inuse;
	uint64_t	buf[LPAD_SIZE / sizeof (uint64_t)];
} lpad_t;

/*
 * A global pool of landing pad memory. Currently, CPUs are only
 * brought into the system one at a time, so the pool is only a
 * single landing pad. In the future, it may be desirable to bring
 * CPUs into the systems in parallel. At that time, the size of
 * the pool can be increased by changing the pool size constant.
 */
#define	LPAD_POOL_SIZE	1

static lpad_t	lpad_pool[LPAD_POOL_SIZE];

#ifdef DEBUG
static int lpad_dbg = 0;

#define	LPAD_DBG		if (lpad_dbg) printf
#define	LPAD_DUMP_DATA		lpad_dump_data

static void lpad_dump_data(uint64_t *lpd_start, uint64_t *lpd_end);

#else /* DEBUG */

#define	LPAD_DBG		_NOTE(CONSTCOND) if (0) printf
#define	LPAD_DUMP_DATA
#endif /* DEBUG */

extern void mach_cpu_startup(uint64_t rabase, uint64_t memsize);
extern void mach_cpu_startup_end(void);
extern int promif_in_cif(void);

static lpad_t *lpad_alloc(void);

uint64_t *
lpad_setup(int cpuid, uint64_t pc, uint64_t arg)
{
	lpad_t		*lpp;
	uint64_t	textsz;
	uint64_t	datasz;
	lpad_data_t	*lpd;
	lpad_map_t	*lpm;

	/* external parameters */
	extern caddr_t	textva;
	extern caddr_t	datava;
	extern tte_t	ktext_tte;
	extern tte_t	kdata_tte;
	extern caddr_t	mmu_fault_status_area;

	LPAD_DBG("lpad_setup...\n");

	if ((cpuid < 0) || (cpuid > NCPU)) {
		cmn_err(CE_PANIC, "lpad_setup: invalid cpuid");
	}

	/* allocate our landing pad */
	if ((lpp = lpad_alloc()) == NULL) {
		cmn_err(CE_PANIC, "lpad_setup: unable to allocate lpad");
	}

	/* calculate the size of our text */
	textsz = (uint64_t)mach_cpu_startup_end - (uint64_t)mach_cpu_startup;

	LPAD_DBG("lpad textsz=%ld\n", textsz);

	ASSERT(textsz <= LPAD_TEXT_SIZE);

	/* copy over text section */
	bcopy((void *)mach_cpu_startup, lpp->buf, textsz);

	lpd = (lpad_data_t *)(((caddr_t)lpp->buf) + LPAD_TEXT_SIZE);
	lpm = (lpad_map_t *)lpd->map;

	ASSERT(mmu_fault_status_area);

	bzero(lpd, LPAD_TEXT_SIZE);
	lpd->magic = LPAD_MAGIC_VAL;
	lpd->inuse = &(lpp->inuse);
	lpd->mmfsa_ra = va_to_pa(mmu_fault_status_area) + (MMFSA_SIZE * cpuid);
	lpd->pc = pc;
	lpd->arg = arg;

	/*
	 * List of mappings:
	 *
	 *    - permanent inst/data mapping for kernel text
	 *    - permanent data mapping for kernel data
	 *    - non-permanent inst mapping for kernel data,
	 *	required for landing pad text
	 */
	lpd->nmap = 3;

	/* verify the lpad has enough room for the data */
	datasz = sizeof (lpad_data_t);
	datasz += (lpd->nmap - 1) * sizeof (lpad_map_t);

	ASSERT(datasz <= LPAD_DATA_SIZE);

	/*
	 * Kernel Text Mapping
	 */
	lpm->va = (uint64_t)textva;
	lpm->tte = ktext_tte;
	lpm->flag_mmuflags = (MAP_ITLB | MAP_DTLB);
	lpm->flag_perm = 1;
	lpm++;

	/*
	 * Kernel Data Mapping
	 */
	lpm->va = (uint64_t)datava;
	lpm->tte = kdata_tte;
	lpm->flag_mmuflags = MAP_DTLB;
	lpm->flag_perm = 1;
	lpm++;

	/*
	 * Landing Pad Text Mapping
	 *
	 * Because this mapping should not be permanent,
	 * the permanent mapping above cannot be used.
	 */
	lpm->va = (uint64_t)datava;
	lpm->tte = kdata_tte;
	lpm->flag_mmuflags = MAP_ITLB;
	lpm->flag_perm = 0;
	lpm++;

	ASSERT(((uint64_t)lpm - (uint64_t)lpd) == datasz);

	LPAD_DBG("copied %ld bytes of data into lpad\n", datasz);

	LPAD_DUMP_DATA((uint64_t *)lpd, (uint64_t *)lpm);

	return (lpp->buf);
}

static lpad_t *
lpad_alloc(void)
{
	int	idx;

	/*
	 * No locking is required for the global lpad pool since
	 * it should only be accessed while in the CIF which is
	 * single threaded. If this assumption changes, locking
	 * would be required.
	 */
	ASSERT(promif_in_cif());

	/*
	 * Wait until an lpad buffer becomes available.
	 */
	for (;;) {
		LPAD_DBG("checking lpad pool:\n");

		/* walk the lpad buffer array */
		for (idx = 0; idx < LPAD_POOL_SIZE; idx++) {

			LPAD_DBG("\tchecking lpad_pool[%d]\n", idx);

			if (lpad_pool[idx].inuse == 0) {
				LPAD_DBG("found empty lpad (%d)\n", idx);

				/* mark the buffer as busy */
				lpad_pool[idx].inuse = 1;

				return (&lpad_pool[idx]);
			}
		}
	}
}

#ifdef DEBUG
static void
lpad_dump_data(uint64_t *lpd_start, uint64_t *lpd_end)
{
	uint64_t	*lp;
	uint_t		offset = 0;

	if (lpad_dbg == 0)
		return;

	printf("lpad data:\n");

	for (lp = lpd_start; lp < lpd_end; lp++) {
		printf("\t0x%02x  0x%016lx\n", offset, *lp);
		offset += sizeof (uint64_t);
	}
}
#endif /* DEBUG */
