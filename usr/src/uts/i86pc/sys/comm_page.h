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

#ifndef _COMM_PAGE_H
#define	_COMM_PAGE_H

#ifndef _ASM
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#endif /* _ASM */

#ifdef __cplusplus
extern "C" {
#endif

#define	COMM_PAGE_SIZE	PAGESIZE

#ifndef _ASM

/*
 * x86 comm page
 *
 * This struct defines the data format for the "comm page": kernel data made
 * directly available to userspace for read-only operations.  This enables
 * facilities such as clock_gettime to operate entirely in userspace without
 * the need for a trap or fasttrap.
 *
 * A note about 32-bit/64-bit compatibility:
 * The current format of the comm page is designed to be consistent for both
 * 32-bit and 64-bit programs running in a 64-bit kernel.  On 32-bit kernels,
 * the comm page is not exposed to userspace due to the difference in
 * timespec_t sizing.
 *
 * This struct is instantiated "by hand" in assembly to preserve the global
 * symbols it contains.  That layout must be kept in sync with the structure
 * defined here.
 * See: "uts/i86pc/ml/comm_page.s"
 */
typedef struct comm_page_s {
	hrtime_t		cp_tsc_last;
	hrtime_t		cp_tsc_hrtime_base;
	hrtime_t		cp_tsc_resume_cap;
	uint32_t		cp_tsc_type;
	uint32_t		cp_tsc_max_delta;

	volatile uint32_t	cp_hres_lock;	/* must be 8-byte aligned */
	uint32_t		cp_nsec_scale;
	int64_t			cp_hrestime_adj;
	hrtime_t		cp_hres_last_tick;
	uint32_t		cp_tsc_ncpu;
	uint32_t		_cp_pad;
	volatile int64_t	cp_hrestime[2];
#if defined(_MACHDEP)
	hrtime_t		cp_tsc_sync_tick_delta[NCPU];
#else
	/* length resides in cp_ncpu */
	hrtime_t		cp_tsc_sync_tick_delta[];
#endif /* defined(_MACHDEP) */
} comm_page_t;

#if defined(_KERNEL)
extern comm_page_t comm_page;

#if defined(_MACHDEP)
extern hrtime_t tsc_last;
extern hrtime_t tsc_hrtime_base;
extern hrtime_t tsc_resume_cap;
extern uint32_t tsc_type;
extern uint32_t tsc_max_delta;
extern volatile uint32_t hres_lock;
extern uint32_t nsec_scale;
extern int64_t hrestime_adj;
extern hrtime_t hres_last_tick;
extern uint32_t tsc_ncpu;
extern volatile timestruc_t hrestime;
extern hrtime_t tsc_sync_tick_delta[NCPU];
#endif /* defined(_MACHDEP) */
#endif /* defined(_KERNEL) */

#endif  /* _ASM */

#ifdef __cplusplus
}
#endif

#endif /* _COMM_PAGE_H */
