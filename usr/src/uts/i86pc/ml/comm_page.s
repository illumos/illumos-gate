
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

#include <sys/asm_linkage.h>
#include <sys/asm_misc.h>
#include <sys/param.h>
#include <sys/comm_page.h>
#include <sys/tsc.h>

#if defined(_GENCTF) || defined(__lint)

hrtime_t tsc_last;
hrtime_t tsc_resume_cap;
hrtime_t tsc_hrtime_base;
uint32_t tsc_max_delta;
volatile uint32_t hres_lock;
uint32_t tsc_type;
uint32_t nsec_scale;
int64_t hrestime_adj;
hrtime_t hres_last_tick;
uint32_t tsc_ncpu;
volatile timestruc_t hrestime;
hrtime_t tsc_sync_tick_delta[NCPU];

comm_page_t comm_page;

#else /* defined(_GENCTF) || defined(__lint) */

#include "assym.h"

/*
 * x86 Comm Page
 *
 * This is the definition for the comm page on x86.  The purpose of this struct
 * is to consolidate certain pieces of kernel state into one contiguous section
 * of memory in order for it to be exposed (read-only) to userspace.  The
 * struct contents are defined by hand so that member variables will maintain
 * their original symbols for use throughout the rest of the kernel.  This
 * layout must exactly match the C definition of comm_page_t.
 * See: "uts/i86pc/sys/comm_page.h"
 */

	.data
	DGDEF3(comm_page, COMM_PAGE_S_SIZE, 4096)
	DGDEF2(tsc_last, 8)
	.fill	1, 8, 0
	DGDEF2(tsc_hrtime_base, 8)
	.fill	1, 8, 0
	DGDEF2(tsc_resume_cap, 8)
	.fill	1, 8, 0
	DGDEF2(tsc_type, 4);
	.fill	1, 4, _CONST(TSC_RDTSC_CPUID)
	DGDEF2(tsc_max_delta, 4);
	.fill	1, 4, 0
	DGDEF2(hres_lock, 4);
	.fill	1, 4, 0
	DGDEF2(nsec_scale, 4);
	.fill	1, 4, 0
	DGDEF2(hrestime_adj, 8)
	.fill	1, 8, 0
	DGDEF2(hres_last_tick, 8)
	.fill	1, 8, 0
	DGDEF2(tsc_ncpu, 4)
	.fill	1, 4, 0
	/* _cp_pad */
	.fill	1, 4, 0
	DGDEF2(hrestime, _MUL(2, 8))
	.fill	2, 8, 0
	DGDEF2(tsc_sync_tick_delta, _MUL(NCPU, 8))
	.fill	_CONST(NCPU), 8, 0

	/* pad out the rest of the page from the struct end */
	.fill	_CONST(COMM_PAGE_SIZE - COMM_PAGE_S_SIZE), 1, 0

#endif /* defined(_GENCTF) || defined(__lint) */
